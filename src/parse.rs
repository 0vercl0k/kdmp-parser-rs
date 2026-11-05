// Axel '0vercl0k' Souchet - February 25 2024
//! This has all the parsing logic for parsing kernel crash-dumps.
use core::slice;
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::{self, Debug};
use std::fs::File;
use std::io::{Cursor, SeekFrom};
use std::mem::MaybeUninit;
use std::num::NonZeroU64;
use std::ops::Range;
use std::path::Path;

use crate::bits::Bits;
use crate::error::{Error, Result};
use crate::gxa::{Gpa, Gva};
use crate::map::{MappedFileReader, Reader};
use crate::physindex::{Builder, PhysIndex};
use crate::pxe::Pfn;
use crate::structs::{
    BmpHeader64, Context, DUMP_HEADER64_EXPECTED_SIGNATURE, DUMP_HEADER64_EXPECTED_VALID_DUMP,
    DumpType, ExceptionRecord64, FullRdmpHeader64, Header64, KdDebuggerData64, KernelRdmpHeader64,
    PageKind, PfnRange, PhysmemDesc, PhysmemRun, Pod,
};
use crate::virt;
use crate::virt_utils::{
    ModuleMap, try_extract_kernel_modules, try_extract_user_modules, try_find_prcb,
};

/// Calculate the pfn from a bitmap & bit index.
fn pfn_from_bitmap_idxs(bitmap_idx: u64, bit_idx: u64) -> Option<Pfn> {
    Some(Pfn::new(bitmap_idx.checked_mul(8)?.checked_add(bit_idx)?))
}

/// Total length of the reader, leaving its position unchanged.
fn reader_len(reader: &mut impl Reader) -> Result<u64> {
    let pos = reader.stream_position()?;
    let len = reader.seek(SeekFrom::End(0))?;
    reader.seek(SeekFrom::Start(pos))?;

    Ok(len)
}

/// Checks that `pages` pages stored from `file_offset` fit in a reader of
/// `len` bytes.
fn check_pages_fit(file_offset: u64, pages: NonZeroU64, reader_len: u64) -> bool {
    let Some(end) = pages
        .get()
        .checked_mul(PageKind::Normal.len())
        .and_then(|size| file_offset.checked_add(size))
    else {
        return false;
    };

    end <= reader_len
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
    /// Index the physical memory space.
    pub(crate) physidx: PhysIndex,
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
        let physidx = Self::build_phyidx(dump_type, &headers, &mut reader)?;

        // Read the context record.
        let context = Box::new(read_struct(&mut Cursor::new(
            headers.context_record_buffer.as_slice(),
        ))?);

        let reader: RefCell<Box<dyn Reader>> = RefCell::new(Box::new(reader));
        let mut parser = Self {
            dump_type,
            context,
            headers,
            physidx,
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
        // `KDDEBUGGER_DATA_BLOCK` structure to know where a bunch of things
        // are. If we can't read the block, we'll have to stop the
        // adventure here as we won't be able to read the things we need
        // to keep going.
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
        // We'll assume that if you are opening a dump file larger than 4gb, you
        // don't want it memory mapped.
        let size = dump_path.as_ref().metadata()?.len();

        if let 0..=FOUR_GIGS = size {
            let mapped_file = MappedFileReader::new(dump_path.as_ref())?;

            Self::with_reader(mapped_file)
        } else {
            let file = File::open(dump_path)?;

            Self::with_reader(file)
        }
    }

    /// Get a list of every GPAs available in this dump.
    pub fn gpas(&self) -> impl ExactSizeIterator<Item = Gpa> {
        // We don't surface the offset to the user because they can't really do
        // anything w/ it (cf gh issue #16).
        self.physidx.iter().map(|(gpa, _)| gpa)
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
    pub(crate) fn seek(&self, pos: SeekFrom) -> Result<u64> {
        Ok(self.reader.borrow_mut().seek(pos)?)
    }

    /// Read however many bytes in `buf` and returns the amount of bytes read.
    pub(crate) fn read_exact(&self, buf: &mut [u8]) -> Result<()> {
        Ok(self.reader.borrow_mut().read_exact(buf)?)
    }

    /// Build the physical memory index for a [`DumpType::Full`] dump.
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
    fn full_physindex(headers: &Header64, reader: &mut impl Reader) -> Result<PhysIndex> {
        let reader_len = reader_len(reader)?;
        let mut page_offset = reader.stream_position()?;
        let mut run_cursor = Cursor::new(headers.physical_memory_block_buffer);
        let physmem_desc = read_struct::<PhysmemDesc>(&mut run_cursor)?;

        let mut physidx = Builder::new();
        for _ in 0..physmem_desc.number_of_runs {
            let run = read_struct::<PhysmemRun>(&mut run_cursor)?;
            let Some(page_count) = NonZeroU64::new(run.page_count) else {
                return Err(Error::InvalidData("zero page_count"));
            };

            // Guard against `page_count` that would extend past the file.
            if !check_pages_fit(page_offset, page_count, reader_len) {
                return Err(Error::InvalidData("run doesn't fit"));
            }

            // Calculate the physical address of the first page..
            let phys_addr = run
                .first_page_phys_addr()
                .ok_or(Error::InvalidData("overflow w/ physmemrun first"))?;

            // ..and make sure the end of the run doesn't overflow either.
            run.last_page_phys_addr()
                .ok_or(Error::InvalidData("overflow w/ physmemrun last"))?;

            // This is looking sane so push the run into the index.
            physidx.push_run(phys_addr, page_count, page_offset);

            // Move the page offset along.
            page_offset += run
                .total_len()
                .ok_or(Error::InvalidData("overflow w/ page offset"))?;
        }

        physidx.finish()
    }

    /// Build the physical memory index for a [`DumpType::Bmp`] dump.
    ///
    /// The way this scheme works is that there's a bitmap that tells you if a
    /// PFN exists or not. There's also a `first_page` field that gives you the
    /// file offset to the content of the first PFN. From there each bit
    /// describes a PFN.
    ///
    /// Let's walk through an example to make the above crystal clear; consider
    /// the below header:
    ///   - Bmp header: pages: 137, first_page: 431
    ///
    /// From there, we can calculate the bitmap size in bytes; there's 1 page
    /// per bit, so the bitmap size is round_above(137 / 8) = 18 bytes. But
    /// notice that although the bitmap is 18 bytes long, not all bits off the
    /// last byte should be looked at: 136 / 8 = 17, so we basically need 1 bit
    /// off that last byte (137 % 8).
    ///
    /// And then it's just a matter of computing a pfn from a byte & a bit
    /// index: `((byte_idx * 8) + bit_idx)`. And for every bit, you can move
    /// the file offset by a page.
    ///
    /// If the bit is 0, the PFN isn't in the file. In that case you don't move
    /// the file offset (otherwise you'd have to embed a full page of 0's for
    /// every "holes").
    fn bmp_physindex(reader: &mut impl Reader) -> Result<PhysIndex> {
        let bmp_header = read_struct::<BmpHeader64>(reader)?;
        if !bmp_header.looks_good() {
            return Err(Error::InvalidData("bmp header doesn't look right"));
        }

        let Some(total_pages) = NonZeroU64::new(bmp_header.total_present_pages) else {
            return Err(Error::InvalidData("bmp has 0 total pages"));
        };

        let Some(pages) = NonZeroU64::new(bmp_header.pages) else {
            return Err(Error::InvalidData("bmp has 0 pages"));
        };

        // Make sure the bitmap doesn't extend past the dump file's end..
        let reader_len = reader_len(reader)?;
        let bitmap_size = pages.get().div_ceil(8);
        if reader
            .stream_position()?
            .checked_add(bitmap_size)
            .is_none_or(|end| end > reader_len)
        {
            return Err(Error::InvalidData(
                "bitmap extends past the end of the file",
            ));
        }

        // ..also check that the number of pages described fit in the file.
        let remaining_bits = pages.get() % 8;
        let mut page_offset = bmp_header.first_page;
        if !check_pages_fit(page_offset, total_pages, reader_len) {
            return Err(Error::InvalidData("bitmap doesn't fit"));
        }

        // Walk the bitmap byte per byte..
        let mut physidx = Builder::new();
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

            // Walk every bits.
            for bit_idx in 0u64..8 {
                // If it's not set, go to the next.
                if byte[0].bit(bit_idx.try_into().unwrap()) == 0 {
                    continue;
                }

                // Calculate the PFN..
                let pfn = pfn_from_bitmap_idxs(bitmap_idx, bit_idx)
                    .ok_or(Error::InvalidData("malformed bitmap"))?;

                // .. and feed it to the index.
                physidx.push(pfn.gpa(), page_offset);

                // Move the file offset along.
                page_offset = page_offset
                    .checked_add(PageKind::Normal.len())
                    .ok_or(Error::InvalidData("malformed bitmap"))?;
            }
        }

        physidx.finish()
    }

    /// Build the physical memory index for [`DumpType::KernelMemory`] /
    /// [`DumpType::KernelAndUserMemory`] and [`DumpType::CompleteMemory`] dump.
    fn kernel_physidx(dump_type: DumpType, reader: &mut impl Reader) -> Result<PhysIndex> {
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

        // `metadata_size` includes the [`PhysmemDesc`] already consumed
        // as part of reading [`KernelRdmpHeader64`] / [`FullRdmpHeader64`].
        // Only the bytes between the current position and the first
        // page contain [`PfnRange`]s.
        let pfn_ranges_len = page_offset
            .checked_sub(reader.stream_position()?)
            .ok_or(Error::InvalidData("first page precedes PFN range table"))?;
        let pfn_range_size = size_of::<PfnRange>() as u64;
        if !pfn_ranges_len.is_multiple_of(pfn_range_size) {
            return Err(Error::InvalidData(
                "PFN range table size is not a multiple of sizeof::<PfnRange>()",
            ));
        }

        let reader_len = reader_len(reader)?;
        if page_offset > reader_len {
            return Err(Error::InvalidData(
                "PFN range table extends past the end of the file",
            ));
        }

        let number_pfns = pfn_ranges_len / pfn_range_size;
        let mut physmem = Builder::new();

        for _ in 0..number_pfns {
            if dump_type == D::CompleteMemory {
                // `CompleteMemoryDump` type seems to be bound by the
                // `total_number_of_pages` field, *not* by `metadata_size`.
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

            let Some(number_of_pages) = NonZeroU64::new(pfn_range.number_of_pages) else {
                return Err(Error::InvalidData("zero number_of_pages"));
            };

            // Guard against `number_of_pages` that would extend past the file.
            if !check_pages_fit(page_offset, number_of_pages, reader_len) {
                return Err(Error::InvalidData("run doesn't fit"));
            }

            // Calculate the physical address of the first page..
            let phys_addr = pfn_range
                .first_page_phys_addr()
                .ok_or(Error::InvalidData("overflow w/ pfn range first"))?;

            // ..and make sure the end of the range doesn't overflow either.
            pfn_range
                .last_page_phys_addr()
                .ok_or(Error::InvalidData("overflow w/ pfn range last"))?;

            // This is looking sane so push the run into the index.
            physmem.push_run(phys_addr, number_of_pages, page_offset);

            // Move the page offset along.
            page_offset += pfn_range
                .total_len()
                .ok_or(Error::InvalidData("overflow w/ page offset"))?;

            page_count = page_count
                .checked_add(pfn_range.number_of_pages)
                .ok_or(Error::InvalidData("overflow w/ page_count"))?;
        }

        physmem.finish()
    }

    fn build_phyidx(
        dump_type: DumpType,
        headers: &Header64,
        reader: &mut impl Reader,
    ) -> Result<PhysIndex> {
        use DumpType as D;
        match dump_type {
            D::Full => Self::full_physindex(headers, reader),
            D::Bmp | D::LiveKernelMemory => Self::bmp_physindex(reader),
            D::KernelMemory | D::KernelAndUserMemory | D::CompleteMemory => {
                Self::kernel_physidx(dump_type, reader)
            }
        }
    }
}
