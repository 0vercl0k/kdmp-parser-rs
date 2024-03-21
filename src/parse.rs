// Axel '0vercl0k' Souchet - February 25 2024
//! This has all the parsing logic for parsing kernel crash-dumps.
use std::cell::RefCell;
use std::cmp::min;
use std::fmt::Debug;
use std::fs::File;
use std::path::Path;
use std::{io, mem};

use crate::bits::Bits;
use crate::error::Result;
use crate::gxa::Gxa;
use crate::map::{MappedFileReader, Reader};
use crate::structs::{
    read_struct, BmpHeader64, Context, DumpType, ExceptionRecord64, FullRdmpHeader64, Header64,
    KernelRdmpHeader64, Page, PfnRange, PhysmemDesc, PhysmemMap, PhysmemRun,
    HEADER64_EXPECTED_SIGNATURE, HEADER64_EXPECTED_VALID_DUMP,
};
use crate::{Gpa, Gva, KdmpParserError, Pfn, Pxe};

fn gpa_from_bitmap(bitmap_idx: u64, bit_idx: usize) -> Option<Gpa> {
    let pfn = Pfn::new(
        bitmap_idx
            .checked_mul(8)?
            .checked_add(bit_idx.try_into().ok()?)?,
    );

    Some(pfn.gpa())
}

fn gpa_from_pfn_range(pfn_range: &PfnRange, page_idx: u64) -> Option<Gpa> {
    let offset = page_idx.checked_mul(Page::size())?;

    Some(Pfn::new(pfn_range.page_file_number).gpa_with_offset(offset))
}

/// A kernel dump parser that gives access to the physical memory space stored
/// in the dump. It also offers virtual to physical memory translation as well
/// as a virtual read facility.
pub struct KernelDumpParser<'reader> {
    /// Which type of dump is it?
    dump_type: DumpType,
    /// Context header.
    context: Box<Context>,
    /// The dump headers.
    headers: Box<Header64>,
    /// This maps a physical address to a file offset. Seeking there gives the
    /// page content.
    physmem: PhysmemMap,
    /// The [`Reader`] object that allows us to seek / read the dump file which
    /// could be memory mapped, read from a file, etc.
    reader: RefCell<Box<dyn Reader + 'reader>>,
}

impl<'reader> Debug for KernelDumpParser<'reader> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KernelDumpParser")
            .field("dump_type", &self.dump_type)
            .finish()
    }
}

impl<'reader> KernelDumpParser<'reader> {
    /// Create an instance from a file path. This memory maps the file and
    /// parses it.
    pub fn with_reader(mut reader: impl Reader + 'reader) -> Result<Self> {
        // Parse the dump header and check if things look right.
        let headers = Box::new(read_struct::<Header64>(&mut reader)?);
        if headers.signature != HEADER64_EXPECTED_SIGNATURE {
            return Err(KdmpParserError::InvalidSignature(headers.signature));
        }

        if headers.valid_dump != HEADER64_EXPECTED_VALID_DUMP {
            return Err(KdmpParserError::InvalidValidDump(headers.valid_dump));
        }

        // Grab the dump type and make sure it is one we support.
        let dump_type = DumpType::try_from(headers.dump_type)?;

        // Let's figure out how to get physical memory out of this dump now.
        let physmem = Self::build_physmem(dump_type, &headers, &mut reader)?;

        // Read the context record.
        let context = Box::new(read_struct::<Context>(&mut io::Cursor::new(
            headers.context_record_buffer.as_slice(),
        ))?);

        let reader: RefCell<Box<dyn Reader>> = RefCell::new(Box::new(reader));

        Ok(Self {
            dump_type,
            context,
            headers,
            physmem,
            reader,
        })
    }

    pub fn new<P>(dump_path: &P) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        // We'll assume that if you are opening a dump file larger than 4gb, you don't
        // want it memory mapped.
        let size = dump_path.as_ref().metadata()?.len();
        const FOUR_GIGS: u64 = 1_024 * 1_024 * 1_024 * 4;

        match size {
            0..=FOUR_GIGS => {
                let mapped_file = MappedFileReader::new(dump_path.as_ref())?;

                Self::with_reader(mapped_file)
            }
            _ => {
                let file = File::open(dump_path)?;

                Self::with_reader(file)
            }
        }
    }

    pub fn physmem(&self) -> impl ExactSizeIterator<Item = (Gpa, u64)> + '_ {
        self.physmem.iter().map(|(&k, &v)| (k, v))
    }

    /// What kind of dump is it?
    pub fn dump_type(&self) -> DumpType {
        self.dump_type
    }

    /// Get the exception record.
    pub fn exception_record(&self) -> &ExceptionRecord64 {
        &self.headers.exception
    }

    /// Get the context record.
    pub fn context_record(&self) -> &Context {
        &self.context
    }

    /// Translate a [`Gpa`] into a file offset of where the content of the page
    /// resides in.
    fn phys_translate(&self, gpa: Gpa) -> Option<u64> {
        let offset = *self.physmem.get(&gpa.page_align())?;

        offset.checked_add(gpa.offset())
    }

    fn seek(&self, pos: io::SeekFrom) -> Result<u64> {
        Ok(self.reader.borrow_mut().seek(pos)?)
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        Ok(self.reader.borrow_mut().read(buf)?)
    }

    /// Read physical memory starting at `gpa` into a `buffer`.
    pub fn phys_read(&self, gpa: Gpa, buffer: &mut [u8]) -> Option<usize> {
        // Amount of bytes left to read.
        let mut amount_left = buffer.len();
        // Total amount of bytes that we have successfully read.
        let mut total_read = 0;
        // The current gpa we are reading from.
        let mut addr = gpa;
        // Let's try to read as much as the user wants.
        while amount_left > 0 {
            // Translate the gpa into a file offset..
            let phy_offset = self.phys_translate(addr)?;
            // ..and seek the reader there.
            self.seek(io::SeekFrom::Start(phy_offset)).ok()?;
            // We need to take care of reads that straddle different physical memory pages.
            // So let's figure out the maximum amount of bytes we can read off this page.
            // Either, we read it until its end, or we stop if the user wants us to read
            // less.
            let left_in_page = (Page::size() - gpa.offset()) as usize;
            let amount_wanted = min(amount_left, left_in_page);
            // Figure out where we should read into.
            let slice = &mut buffer[total_read..total_read + amount_wanted];
            // Read the physical memory!
            let amount_read = self.read(slice).ok()?;
            // Update the total amount of read bytes and how much work we have left.
            total_read += amount_read;
            amount_left -= amount_read;
            // If we couldn't read as much as we wanted, we're done.
            if amount_read != amount_wanted {
                return Some(total_read);
            }

            // We have more work to do, so let's move to the next page.
            addr = addr.next_aligned_page();
        }

        // Yay, we read as much bytes as the user wanted!
        Some(total_read)
    }

    /// Read an exact amount of physical memory starting at `gpa` into a
    /// `buffer`.
    pub fn phys_read_exact(&self, gpa: Gpa, buffer: &mut [u8]) -> Option<()> {
        // Read physical memory.
        let len = self.phys_read(gpa, buffer)?;

        // If we read as many bytes as we wanted, then it's a win..
        if len == buffer.len() {
            Some(())
        }
        // ..otherwise, we call it quits.
        else {
            None
        }
    }

    /// Read a `u64` in physical memory at `gpa`.
    pub fn phys_read8(&self, gpa: Gpa) -> Option<u64> {
        let mut buffer = [0; mem::size_of::<u64>()];
        self.phys_read_exact(gpa, &mut buffer)?;

        Some(u64::from_le_bytes(buffer))
    }

    /// Read virtual memory starting at `gva` into a `buffer`.
    pub fn virt_read(&self, gva: Gva, buffer: &mut [u8]) -> Option<usize> {
        // Amount of bytes left to read.
        let mut amount_left = buffer.len();
        // Total amount of bytes that we have successfully read.
        let mut total_read = 0;
        // The current gva we are reading from.
        let mut addr = gva;
        // Let's try to read as much as the user wants.
        while amount_left > 0 {
            // We need to take care of reads that straddle different virtual memory pages.
            // So let's figure out the maximum amount of bytes we can read off this page.
            // Either, we read it until its end, or we stop if the user wants us to read
            // less.
            let left_in_page = (Page::size() - addr.offset()) as usize;
            let amount_wanted = min(amount_left, left_in_page);
            // Figure out where we should read into.
            let slice = &mut buffer[total_read..total_read + amount_wanted];
            // Translate the gva into a gpa..
            let gpa = self.virt_translate(addr)?;
            // .. and read the physical memory!
            let amount_read = self.phys_read(gpa, slice)?;
            // Update the total amount of read bytes and how much work we have left.
            total_read += amount_read;
            amount_left -= amount_read;
            // If we couldn't read as much as we wanted, we're done.
            if amount_read != amount_wanted {
                return Some(total_read);
            }

            // We have more work to do, so let's move to the next page.
            addr = addr.next_aligned_page();
        }

        // Yay, we read as much bytes as the user wanted!
        Some(total_read)
    }

    /// Read virtual memory starting at `gva`
    pub fn virt_read_exact(&self, gva: Gva, buffer: &mut [u8]) -> Option<()> {
        // Read virtual memory.
        let len = self.virt_read(gva, buffer)?;

        // If we read as many bytes as we wanted, then it's a win..
        if len == buffer.len() {
            Some(())
        }
        // ..otherwise, we call it quits.
        else {
            None
        }
    }

    /// Translate a [`Gva`] into a [`Gpa`].
    pub fn virt_translate(&self, gva: Gva) -> Option<Gpa> {
        // Aligning in case PCID bits are set (bits 11:0)
        let pml4_base = Gpa::from(self.headers.directory_table_base).page_align();
        let pml4e_gpa = Gpa::new(pml4_base.u64() + (gva.pml4e_idx() * 8));
        let pml4e = Pxe::from(self.phys_read8(pml4e_gpa)?);
        if !pml4e.present() {
            return None;
        }

        let pdpt_base = pml4e.pfn.gpa();
        let pdpte_gpa = Gpa::new(pdpt_base.u64() + (gva.pdpe_idx() * 8));
        let pdpte = Pxe::from(self.phys_read8(pdpte_gpa)?);
        if !pdpte.present() {
            return None;
        }

        // huge pages:
        // 7 (PS) - Page size; must be 1 (otherwise, this entry references a page
        // directory; see Table 4-1
        let pd_base = pdpte.pfn.gpa();
        if pdpte.large_page() {
            return Some(Gpa::new(pd_base.u64() + (gva.u64() & 0x3fff_ffff)));
        }

        let pde_gpa = Gpa::new(pd_base.u64() + (gva.pde_idx() * 8));
        let pde = Pxe::from(self.phys_read8(pde_gpa)?);
        if !pde.present() {
            return None;
        }

        // large pages:
        // 7 (PS) - Page size; must be 1 (otherwise, this entry references a page
        // table; see Table 4-18
        let pt_base = pde.pfn.gpa();
        if pde.large_page() {
            return Some(Gpa::new(pt_base.u64() + (gva.u64() & 0x1f_ffff)));
        }

        let pte_gpa = Gpa::new(pt_base.u64() + (gva.pte_idx() * 8));
        let pte = Pxe::from(self.phys_read8(pte_gpa)?);
        if pte.large_page() {
            return None;
        }

        let page_base = pte.pfn.gpa();

        Some(Gpa::new(page_base.u64() + gva.offset()))
    }

    /// Build the physical memory map for a [`DumpType::Full`] dump.
    ///
    /// Here is how runs works. Every `runs` document a number of consecutive
    /// physical pages starting at a `PFN`. This means that you can have
    /// "holes" in the physical address space and you don't need to write any
    /// data for them. Here is a small example:
    ///   - Run[0]: BasePage = 1_337, PageCount = 2
    ///   - Run[1]: BasePage = 1_400, PageCount = 1
    ///
    /// In the above, there is a "hole" between the two runs. It has 2+1 memory
    /// pages at: Pfn(1_337+0), Pfn(1_337+1) and Pfn(1_400+0) (but nothing
    /// at Pfn(1_339)).
    ///
    /// In terms of the content of those physical memory pages, they are packed
    /// and stored one after another. If the first page of the first run is
    /// at file offset 0x2_000, then the first page of the second run is at
    /// file offset 0x2_000+(2*0x1_000).
    fn full_physmem(headers: &Header64, reader: &mut impl Reader) -> Result<PhysmemMap> {
        let mut page_offset = reader.stream_position()?;
        let mut run_cursor = io::Cursor::new(headers.physical_memory_block_buffer);
        let physmem_desc = read_struct::<PhysmemDesc>(&mut run_cursor)?;
        let mut physmem = PhysmemMap::new();

        for run_idx in 0..physmem_desc.number_of_runs {
            let run = read_struct::<PhysmemRun>(&mut run_cursor)?;
            for page_idx in 0..run.page_count {
                // Calculate the physical address.
                let phys_addr = run
                    .phys_addr(page_idx)
                    .ok_or_else(|| KdmpParserError::PhysAddrOverflow(run_idx, page_idx))?;

                // We now know where this page lives at, insert it into the physmem map.
                if physmem.insert(phys_addr, page_offset).is_some() {
                    return Err(KdmpParserError::DuplicateGpa(phys_addr));
                }

                // Move the page offset along.
                page_offset = page_offset
                    .checked_add(Page::size())
                    .ok_or_else(|| KdmpParserError::PageOffsetOverflow(run_idx, page_idx))?;
            }
        }

        Ok(physmem)
    }

    /// Build the physical memory map for a [`DumpType::Bmp`] dump.
    fn bmp_physmem(reader: &mut impl Reader) -> Result<PhysmemMap> {
        let bmp_header = read_struct::<BmpHeader64>(reader)?;
        if !bmp_header.looks_good() {
            return Err(KdmpParserError::InvalidData(
                "bmp header doesn't look right",
            ));
        }

        debug_assert_eq!(bmp_header.pages % 8, 0);
        let bitmap_size = bmp_header.pages / 8;
        let mut page_offset = bmp_header.first_page;
        let mut physmem = PhysmemMap::new();

        // Walk the bitmap byte per byte..
        for bitmap_idx in 0..bitmap_size {
            let mut byte = [0u8];
            reader.read_exact(&mut byte)?;
            let byte = byte[0];
            // ..and walk every bits.
            for bit_idx in 0..8 {
                // If it's not set, go to the next.
                if byte.bit(bit_idx) == 0 {
                    continue;
                }

                // Calculate where the page is.
                let pa = gpa_from_bitmap(bitmap_idx, bit_idx).ok_or_else(|| {
                    KdmpParserError::Overflow("overflow when computing pfn in bitmap")
                })?;

                debug_assert!(physmem.insert(pa, page_offset).is_none());
                page_offset = page_offset.checked_add(Page::size()).ok_or_else(|| {
                    KdmpParserError::BitmapPageOffsetOverflow(bitmap_idx, bit_idx)
                })?;
            }
        }

        Ok(physmem)
    }

    /// Build the physical memory map for [`DumpType::KernelMemory`] /
    /// [`DumpType::KernelAndUserMemory`] and [`DumpType::CompleteMemory`] dump.
    fn kernel_physmem(dump_type: DumpType, reader: &mut impl Reader) -> Result<PhysmemMap> {
        use DumpType as D;
        let mut page_count = 0u64;
        let (mut page_offset, metadata_size, total_number_of_pages) = match dump_type {
            D::KernelMemory | D::KernelAndUserMemory => {
                let kernel_hdr = read_struct::<KernelRdmpHeader64>(reader)?;
                if !kernel_hdr.hdr.looks_good() {
                    return Err(KdmpParserError::InvalidData(
                        "RdmpHeader64 doesn't look right",
                    ));
                }

                (
                    kernel_hdr.hdr.first_page_offset,
                    kernel_hdr.hdr.metadata_size,
                    0,
                )
            }
            D::CompleteMemory => {
                let full_hdr = read_struct::<FullRdmpHeader64>(reader)?;
                if !full_hdr.hdr.looks_good() {
                    return Err(KdmpParserError::InvalidData(
                        "FullRdmpHeader64 doesn't look right",
                    ));
                }

                (
                    full_hdr.hdr.first_page_offset,
                    full_hdr.hdr.metadata_size,
                    full_hdr.total_number_of_pages,
                )
            }
            _ => unreachable!(),
        };

        if page_offset == 0 || metadata_size == 0 {
            return Err(KdmpParserError::InvalidData(
                "no first page or metadata size",
            ));
        }

        let pfn_range_size = mem::size_of::<PfnRange>();
        if (metadata_size % pfn_range_size as u64) != 0 {
            return Err(KdmpParserError::InvalidData(
                "metadata size is not a multiple of 8",
            ));
        }

        let number_pfns = metadata_size / pfn_range_size as u64;
        let mut physmem = PhysmemMap::new();

        for _ in 0..number_pfns {
            if dump_type == D::CompleteMemory {
                // `CompleteMemoryDump` type seems to be bound by the `total_number_of_pages`
                // field, *not* by `metadata_size`.
                if page_count == total_number_of_pages {
                    break;
                }

                if page_count > total_number_of_pages {
                    return Err(KdmpParserError::InvalidData(
                        "page_count > total_number_of_pages",
                    ));
                }
            }

            let pfn_range = read_struct::<PfnRange>(reader)?;
            if pfn_range.page_file_number == 0 {
                break;
            }

            for page_idx in 0..pfn_range.number_of_pages {
                let gpa = gpa_from_pfn_range(&pfn_range, page_idx)
                    .ok_or_else(|| KdmpParserError::Overflow("overflow w/ pfn_range"))?;
                debug_assert!(physmem.insert(gpa, page_offset).is_none());
                page_offset = page_offset
                    .checked_add(Page::size())
                    .ok_or_else(|| KdmpParserError::Overflow("overflow w/ page_offset"))?;
            }

            page_count = page_count
                .checked_add(pfn_range.number_of_pages)
                .ok_or_else(|| KdmpParserError::Overflow("overflow w/ page_count"))?;
        }

        Ok(physmem)
    }

    fn build_physmem(
        dump_type: DumpType,
        headers: &Header64,
        reader: &mut impl Reader,
    ) -> Result<PhysmemMap> {
        use DumpType as D;
        match dump_type {
            D::Full => Self::full_physmem(headers, reader),
            D::Bmp => Self::bmp_physmem(reader),
            D::KernelMemory | D::KernelAndUserMemory | D::CompleteMemory => {
                Self::kernel_physmem(dump_type, reader)
            }
        }
    }
}
