// Axel '0vercl0k' Souchet - February 25 2024
//! This has all the parsing logic for parsing kernel crash-dumps.
use core::slice;
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::{self, Debug};
use std::fs::File;
use std::mem::MaybeUninit;
use std::ops::Range;
use std::path::Path;
use std::{io, mem};

use crate::bits::Bits;
use crate::error::{Error, Result};
use crate::gxa::{Gpa, Gva};
use crate::map::{MappedFileReader, Reader};
use crate::pxe::Pfn;
use crate::structs::{
    BmpHeader64, Context, DUMP_HEADER64_EXPECTED_SIGNATURE, DUMP_HEADER64_EXPECTED_VALID_DUMP,
    DumpType, ExceptionRecord64, FullRdmpHeader64, Header64, KdDebuggerData64, KernelRdmpHeader64,
    PageKind, PfnRange, PhysmemDesc, PhysmemMap, PhysmemRun, Pod,
};
use crate::virt;
use crate::virt_utils::{
    ModuleMap, try_extract_kernel_modules, try_extract_user_modules, try_find_prcb,
};

fn gpa_from_bitmap(bitmap_idx: u64, bit_idx: usize) -> Option<Gpa> {
    let pfn = Pfn::new(
        bitmap_idx
            .checked_mul(8)?
            .checked_add(bit_idx.try_into().ok()?)?,
    );

    Some(pfn.gpa())
}

fn gpa_from_pfn_range(pfn_range: &PfnRange, page_idx: u64) -> Option<Gpa> {
    let offset = page_idx.checked_mul(PageKind::Normal.size())?;

    Some(Pfn::new(pfn_range.page_file_number).gpa_with_offset(offset))
}

/// Read a `T` from the cursor.
fn read_struct<T: Pod>(reader: &mut impl Reader) -> Result<T> {
    let mut s: MaybeUninit<T> = MaybeUninit::uninit();
    let size_of_s = size_of_val(&s);
    let slice_over_s = unsafe { slice::from_raw_parts_mut(s.as_mut_ptr().cast::<u8>(), size_of_s) };
    reader.read_exact(slice_over_s)?;

    Ok(unsafe { s.assume_init() })
}

/// A kernel dump parser that gives access to the physical memory space stored
/// in the dump. It also offers virtual to physical memory translation as well
/// as a virtual read facility.
pub struct KernelDumpParser {
    /// Which type of dump is it?
    dump_type: DumpType,
    /// Context header.
    context: Box<Context>,
    /// The dump headers.
    headers: Box<Header64>,
    /// This maps a physical address to a file offset. Seeking there gives the
    /// page content.
    /// XXX: Is this pub(crate) fair?
    pub(crate) physmem: PhysmemMap,
    /// The [`Reader`] object that allows us to seek / read the dump file which
    /// could be memory mapped, read from a file, etc.
    reader: RefCell<Box<dyn Reader>>,
    /// The driver modules loaded when the crash-dump was taken. Extracted from
    /// the nt!PsLoadedModuleList.
    kernel_modules: ModuleMap,
    /// The user modules / DLLs loaded when the crash-dump was taken. Extract
    /// from the current PEB.Ldr.InLoadOrderModuleList.
    user_modules: ModuleMap,
}

impl Debug for KernelDumpParser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KernelDumpParser")
            .field("dump_type", &self.dump_type)
            .finish_non_exhaustive()
    }
}

impl KernelDumpParser {
    /// Create an instance from a [`Reader`] & parse the file.
    pub fn with_reader(mut reader: impl Reader + 'static) -> Result<Self> {
        // Parse the dump header and check if things look right.
        let headers = Box::new(read_struct::<Header64>(&mut reader)?);
        if headers.signature != DUMP_HEADER64_EXPECTED_SIGNATURE {
            return Err(Error::InvalidSignature(headers.signature));
        }

        if headers.valid_dump != DUMP_HEADER64_EXPECTED_VALID_DUMP {
            return Err(Error::InvalidValidDump(headers.valid_dump));
        }

        // Grab the dump type and make sure it is one we support.
        let dump_type = DumpType::try_from(headers.dump_type)?;

        // Let's figure out how to get physical memory out of this dump now.
        let physmem = Self::build_physmem(dump_type, &headers, &mut reader)?;

        // Read the context record.
        let context = Box::new(read_struct(&mut io::Cursor::new(
            headers.context_record_buffer.as_slice(),
        ))?);

        let reader: RefCell<Box<dyn Reader>> = RefCell::new(Box::new(reader));
        let mut parser = Self {
            dump_type,
            context,
            headers,
            physmem,
            reader,
            kernel_modules: HashMap::default(),
            user_modules: HashMap::default(),
        };

        // Extract the kernel modules if we can. If it fails because of a memory
        // translation error we'll keep going, otherwise we'll error out.
        if let Some(kernel_modules) = try_extract_kernel_modules(&parser)? {
            parser.kernel_modules.extend(kernel_modules);
        }

        // Now let's try to find out user-modules. For that we need the
        // `KDDEBUGGER_DATA_BLOCK` structure to know where a bunch of things are.
        // If we can't read the block, we'll have to stop the adventure here as we won't
        // be able to read the things we need to keep going.
        let virt_reader = virt::Reader::new(&parser);
        let Some(kd_debugger_data_block) = virt_reader
            .try_read_struct::<KdDebuggerData64>(parser.headers().kd_debugger_data_block.into())?
        else {
            return Ok(parser);
        };
        let kd_debugger_data_block = Box::new(kd_debugger_data_block);

        // We need to figure out which PRCB is the one that crashed.
        let Some(prcb_addr) = try_find_prcb(&parser, &kd_debugger_data_block)? else {
            return Ok(parser);
        };

        // Finally, we're ready to extract the user modules!
        let Some(user_modules) =
            try_extract_user_modules(&virt_reader, &kd_debugger_data_block, prcb_addr)?
        else {
            return Ok(parser);
        };

        parser.user_modules.extend(user_modules);

        Ok(parser)
    }

    /// Create an instance from a file path; depending on the file size, it'll
    /// either memory maps it or open it as a regular file.
    pub fn new(dump_path: impl AsRef<Path>) -> Result<Self> {
        const FOUR_GIGS: u64 = 1_024 * 1_024 * 1_024 * 4;
        // We'll assume that if you are opening a dump file larger than 4gb, you don't
        // want it memory mapped.
        let size = dump_path.as_ref().metadata()?.len();

        if let 0..=FOUR_GIGS = size {
            let mapped_file = MappedFileReader::new(dump_path.as_ref())?;

            Self::with_reader(mapped_file)
        } else {
            let file = File::open(dump_path)?;

            Self::with_reader(file)
        }
    }

    /// Physical memory map that maps page aligned [`Gpa`] to `offset` where the
    /// content of the page can be found. The offset is relevant with the
    /// associated `reader`.
    pub fn physmem(&self) -> impl ExactSizeIterator<Item = (Gpa, u64)> + '_ {
        self.physmem.iter().map(|(&k, &v)| (k, v))
    }

    /// Kernel modules loaded when the dump was taken.
    pub fn kernel_modules(&self) -> impl ExactSizeIterator<Item = (&Range<Gva>, &str)> + '_ {
        self.kernel_modules.iter().map(|(k, v)| (k, v.as_str()))
    }

    /// User modules loaded when the dump was taken.
    pub fn user_modules(&self) -> impl ExactSizeIterator<Item = (&Range<Gva>, &str)> + '_ {
        self.user_modules.iter().map(|(k, v)| (k, v.as_str()))
    }

    /// What kind of dump is it?
    pub fn dump_type(&self) -> DumpType {
        self.dump_type
    }

    /// Get the dump headers.
    pub fn headers(&self) -> &Header64 {
        &self.headers
    }

    /// Get the exception record.
    pub fn exception_record(&self) -> &ExceptionRecord64 {
        &self.headers.exception
    }

    /// Get the context record.
    pub fn context_record(&self) -> &Context {
        &self.context
    }

    /// Seek to `pos`.
    pub(crate) fn seek(&self, pos: io::SeekFrom) -> Result<u64> {
        Ok(self.reader.borrow_mut().seek(pos)?)
    }

    /// Read however many bytes in `buf` and returns the amount of bytes read.
    pub(crate) fn read_exact(&self, buf: &mut [u8]) -> Result<()> {
        Ok(self.reader.borrow_mut().read_exact(buf)?)
    }

    /// Build the physical memory map for a [`DumpType::Full`] dump.
    ///
    /// Here is how runs works. Every `runs` document a number of consecutive
    /// physical pages starting at a `PFN`. This means that you can have
    /// "holes" in the physical address space and you don't need to write any
    /// data for them. Here is a small example:
    ///   - `Run[0]`: `BasePage = 1_337`, `PageCount = 2`
    ///   - `Run[1]`: `BasePage = 1_400`, `PageCount = 1`
    ///
    /// In the above, there is a "hole" between the two runs. It has `2+1`
    /// memory pages at: `Pfn(1_337+0)`, `Pfn(1_337+1)` and `Pfn(1_400+0)`
    /// (but nothing at `Pfn(1_339)`).
    ///
    /// In terms of the content of those physical memory pages, they are packed
    /// and stored one after another. If the first page of the first run is
    /// at file offset `0x2_000`, then the first page of the second run is at
    /// file offset `0x2_000+(2*0x1_000)`.
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
                    .ok_or(Error::PhysAddrOverflow(run_idx, page_idx))?;

                // We now know where this page lives at, insert it into the physmem map.
                if physmem.insert(phys_addr, page_offset).is_some() {
                    return Err(Error::DuplicateGpa(phys_addr));
                }

                // Move the page offset along.
                page_offset = page_offset
                    .checked_add(PageKind::Normal.size())
                    .ok_or(Error::PageOffsetOverflow(run_idx, page_idx))?;
            }
        }

        Ok(physmem)
    }

    /// Build the physical memory map for a [`DumpType::Bmp`] dump.
    fn bmp_physmem(reader: &mut impl Reader) -> Result<PhysmemMap> {
        let bmp_header = read_struct::<BmpHeader64>(reader)?;
        if !bmp_header.looks_good() {
            return Err(Error::InvalidData("bmp header doesn't look right"));
        }

        let remaining_bits = bmp_header.pages % 8;
        let bitmap_size = bmp_header.pages.next_multiple_of(8) / 8;
        let mut page_offset = bmp_header.first_page;
        let mut physmem = PhysmemMap::new();

        // Walk the bitmap byte per byte..
        for bitmap_idx in 0..bitmap_size {
            let mut byte = [0u8];
            reader.read_exact(&mut byte)?;
            // ..if this is the last byte, and we have a few more bits to read..
            let last_byte = bitmap_idx == bitmap_size - 1;
            if last_byte && remaining_bits != 0 {
                // ..let's mask out the ones we don't care about.
                let mask = (1u8 << remaining_bits).wrapping_sub(1);
                byte[0] &= mask;
            }

            let byte = byte[0];
            // Walk every bits.
            for bit_idx in 0..8 {
                // If it's not set, go to the next.
                if byte.bit(bit_idx) == 0 {
                    continue;
                }

                // Calculate where the page is.
                let pa =
                    gpa_from_bitmap(bitmap_idx, bit_idx).ok_or(Error::Overflow("pfn in bitmap"))?;

                let insert = physmem.insert(pa, page_offset);
                debug_assert!(insert.is_none());
                page_offset = page_offset
                    .checked_add(PageKind::Normal.size())
                    .ok_or(Error::BitmapPageOffsetOverflow(bitmap_idx, bit_idx))?;
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
                    return Err(Error::InvalidData("RdmpHeader64 doesn't look right"));
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
                    return Err(Error::InvalidData("FullRdmpHeader64 doesn't look right"));
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
            return Err(Error::InvalidData("no first page or metadata size"));
        }

        let pfn_range_size = mem::size_of::<PfnRange>();
        if (metadata_size % pfn_range_size as u64) != 0 {
            return Err(Error::InvalidData("metadata size is not a multiple of 8"));
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
                    return Err(Error::InvalidData("page_count > total_number_of_pages"));
                }
            }

            let pfn_range = read_struct::<PfnRange>(reader)?;
            if pfn_range.page_file_number == 0 {
                break;
            }

            for page_idx in 0..pfn_range.number_of_pages {
                let gpa = gpa_from_pfn_range(&pfn_range, page_idx)
                    .ok_or(Error::Overflow("w/ pfn_range"))?;
                let insert = physmem.insert(gpa, page_offset);
                debug_assert!(insert.is_none());
                page_offset = page_offset
                    .checked_add(PageKind::Normal.size())
                    .ok_or(Error::Overflow("w/ page_offset"))?;
            }

            page_count = page_count
                .checked_add(pfn_range.number_of_pages)
                .ok_or(Error::Overflow("w/ page_count"))?;
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
            D::Bmp | D::LiveKernelMemory => Self::bmp_physmem(reader),
            D::KernelMemory | D::KernelAndUserMemory | D::CompleteMemory => {
                Self::kernel_physmem(dump_type, reader)
            }
        }
    }
}
