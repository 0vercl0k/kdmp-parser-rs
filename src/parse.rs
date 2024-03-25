// Axel '0vercl0k' Souchet - February 25 2024
//! This has all the parsing logic for parsing kernel crash-dumps.
use core::slice;
use std::cell::RefCell;
use std::cmp::min;
use std::collections::HashMap;
use std::fmt::Debug;
use std::fs::File;
use std::ops::Range;
use std::path::Path;
use std::{io, mem};

use crate::bits::Bits;
use crate::error::{PxeNotPresent, Result};
use crate::gxa::Gxa;
use crate::map::{MappedFileReader, Reader};
use crate::structs::{
    read_struct, BmpHeader64, Context, DumpHeader64, DumpType, ExceptionRecord64, FullRdmpHeader64,
    KdDebuggerData64, KernelRdmpHeader64, LdrDataTableEntry, ListEntry, Page, PfnRange,
    PhysmemDesc, PhysmemMap, PhysmemRun, UnicodeString, DUMP_HEADER64_EXPECTED_SIGNATURE,
    DUMP_HEADER64_EXPECTED_VALID_DUMP,
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

/// Translate a [`Gpa`] into a file offset of where the content of the page
/// resides in.
fn phys_translate(physmem: &PhysmemMap, gpa: Gpa) -> Result<u64> {
    let offset = *physmem
        .get(&gpa.page_align())
        .ok_or_else(|| KdmpParserError::PhysTranslate(gpa))?;

    offset
        .checked_add(gpa.offset())
        .ok_or_else(|| KdmpParserError::Overflow("w/ gpa offset"))
}

/// Read physical memory starting at `gpa` into a `buffer`.
fn phys_read(
    reader: &mut impl Reader,
    physmem: &PhysmemMap,
    gpa: Gpa,
    buffer: &mut [u8],
) -> Result<usize> {
    // Amount of bytes left to read.
    let mut amount_left = buffer.len();
    // Total amount of bytes that we have successfully read.
    let mut total_read = 0;
    // The current gpa we are reading from.
    let mut addr = gpa;
    // Let's try to read as much as the user wants.
    while amount_left > 0 {
        // Translate the gpa into a file offset..
        let phy_offset = phys_translate(physmem, addr)?;
        // ..and seek the reader there.
        reader.seek(io::SeekFrom::Start(phy_offset))?;
        // We need to take care of reads that straddle different physical memory pages.
        // So let's figure out the maximum amount of bytes we can read off this page.
        // Either, we read it until its end, or we stop if the user wants us to read
        // less.
        let left_in_page = (Page::size() - gpa.offset()) as usize;
        let amount_wanted = min(amount_left, left_in_page);
        // Figure out where we should read into.
        let slice = &mut buffer[total_read..total_read + amount_wanted];
        // Read the physical memory!
        let amount_read = reader.read(slice)?;
        // Update the total amount of read bytes and how much work we have left.
        total_read += amount_read;
        amount_left -= amount_read;
        // If we couldn't read as much as we wanted, we're done.
        if amount_read != amount_wanted {
            return Ok(total_read);
        }

        // We have more work to do, so let's move to the next page.
        addr = addr.next_aligned_page();
    }

    // Yay, we read as much bytes as the user wanted!
    Ok(total_read)
}

/// Read an exact amount of physical memory starting at `gpa` into a
/// `buffer`.
fn phys_read_exact(
    reader: &mut impl Reader,
    physmem: &PhysmemMap,
    gpa: Gpa,
    buffer: &mut [u8],
) -> Result<()> {
    // Read physical memory.
    let len = phys_read(reader, physmem, gpa, buffer)?;

    // If we read as many bytes as we wanted, then it's a win..
    if len == buffer.len() {
        Ok(())
    }
    // ..otherwise, we call it quits.
    else {
        Err(KdmpParserError::PartialPhysRead)
    }
}

fn phys_read8(reader: &mut impl Reader, physmem: &PhysmemMap, gpa: Gpa) -> Result<u64> {
    let mut buffer = [0; mem::size_of::<u64>()];
    phys_read_exact(reader, physmem, gpa, &mut buffer)?;

    Ok(u64::from_le_bytes(buffer))
}

/// Translate a [`Gva`] into a [`Gpa`].
fn virt_translate(
    reader: &mut impl Reader,
    physmem: &PhysmemMap,
    table_base: Gpa,
    gva: Gva,
) -> Result<Gpa> {
    // Aligning in case PCID bits are set (bits 11:0)
    let pml4_base = table_base.page_align();
    let pml4e_gpa = Gpa::new(pml4_base.u64() + (gva.pml4e_idx() * 8));
    let pml4e = Pxe::from(phys_read8(reader, physmem, pml4e_gpa)?);
    if !pml4e.present() {
        return Err(KdmpParserError::VirtTranslate(gva, PxeNotPresent::Pml4e));
    }

    let pdpt_base = pml4e.pfn.gpa();
    let pdpte_gpa = Gpa::new(pdpt_base.u64() + (gva.pdpe_idx() * 8));
    let pdpte = Pxe::from(phys_read8(reader, physmem, pdpte_gpa)?);
    if !pdpte.present() {
        return Err(KdmpParserError::VirtTranslate(gva, PxeNotPresent::Pdpte));
    }

    // huge pages:
    // 7 (PS) - Page size; must be 1 (otherwise, this entry references a page
    // directory; see Table 4-1
    let pd_base = pdpte.pfn.gpa();
    if pdpte.large_page() {
        return Ok(Gpa::new(pd_base.u64() + (gva.u64() & 0x3fff_ffff)));
    }

    let pde_gpa = Gpa::new(pd_base.u64() + (gva.pde_idx() * 8));
    let pde = Pxe::from(phys_read8(reader, physmem, pde_gpa)?);
    if !pde.present() {
        return Err(KdmpParserError::VirtTranslate(gva, PxeNotPresent::Pde));
    }

    // large pages:
    // 7 (PS) - Page size; must be 1 (otherwise, this entry references a page
    // table; see Table 4-18
    let pt_base = pde.pfn.gpa();
    if pde.large_page() {
        return Ok(Gpa::new(pt_base.u64() + (gva.u64() & 0x1f_ffff)));
    }

    let pte_gpa = Gpa::new(pt_base.u64() + (gva.pte_idx() * 8));
    let pte = Pxe::from(phys_read8(reader, physmem, pte_gpa)?);
    if !pte.present() {
        // We'll allow reading from a transition PTE, so return an error only if it's
        // not one, otherwise we'll carry on.
        if !pte.transition() {
            return Err(KdmpParserError::VirtTranslate(gva, PxeNotPresent::Pte));
        }
    }

    let page_base = pte.pfn.gpa();

    Ok(Gpa::new(page_base.u64() + gva.offset()))
}

/// Read virtual memory starting at `gva` into a `buffer`.
fn virt_read(
    reader: &mut impl Reader,
    physmem: &PhysmemMap,
    table_base: Gpa,
    gva: Gva,
    buffer: &mut [u8],
) -> Result<usize> {
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
        let gpa = virt_translate(reader, physmem, table_base, addr)?;
        // .. and read the physical memory!
        let amount_read = phys_read(reader, physmem, gpa, slice)?;
        // Update the total amount of read bytes and how much work we have left.
        total_read += amount_read;
        amount_left -= amount_read;
        // If we couldn't read as much as we wanted, we're done.
        if amount_read != amount_wanted {
            return Ok(total_read);
        }

        // We have more work to do, so let's move to the next page.
        addr = addr.next_aligned_page();
    }

    // Yay, we read as much bytes as the user wanted!
    Ok(total_read)
}

/// Read virtual memory starting at `gva`
fn virt_read_exact(
    reader: &mut impl Reader,
    physmem: &PhysmemMap,
    table_base: Gpa,
    gva: Gva,
    buffer: &mut [u8],
) -> Result<()> {
    // Read virtual memory.
    let len = virt_read(reader, physmem, table_base, gva, buffer)?;

    // If we read as many bytes as we wanted, then it's a win..
    if len == buffer.len() {
        Ok(())
    }
    // ..otherwise, we call it quits.
    else {
        Err(KdmpParserError::PartialVirtRead)
    }
}

/// Read a `T` from virtual memory.
fn virt_read_struct<T>(
    reader: &mut impl Reader,
    physmem: &PhysmemMap,
    table_base: Gpa,
    gva: Gva,
) -> Result<T> {
    let mut t = mem::MaybeUninit::uninit();
    let size_of_t = mem::size_of_val(&t);
    let slice_over_t = unsafe { slice::from_raw_parts_mut(t.as_mut_ptr() as *mut u8, size_of_t) };

    virt_read_exact(reader, physmem, table_base, gva, slice_over_t)?;

    Ok(unsafe { t.assume_init() })
}

fn virt_read_unicode_string(
    reader: &mut impl Reader,
    physmem: &PhysmemMap,
    table_base: Gpa,
    unicode_str: &UnicodeString,
) -> Result<String> {
    if (unicode_str.length % 2) != 0 {
        return Err(KdmpParserError::InvalidUnicodeString);
    }

    let mut buffer = vec![0; unicode_str.length.into()];
    virt_read_exact(
        reader,
        physmem,
        table_base,
        unicode_str.buffer.into(),
        &mut buffer,
    )?;

    let n = unicode_str.length / 2;

    Ok(String::from_utf16(unsafe {
        slice::from_raw_parts(buffer.as_ptr().cast(), n.into())
    })?)
}

fn read_module_map(
    reader: &mut impl Reader,
    physmem: &PhysmemMap,
    table_base: Gpa,
    head_addr: Gva,
) -> Result<ModuleMap> {
    let mut modules = ModuleMap::new();
    let entry = virt_read_struct::<ListEntry>(reader, physmem, table_base, head_addr)?;
    let mut entry_addr = entry.flink.into();
    // We'll walk it until we hit the starting point (it is circular).
    while entry_addr != head_addr {
        // Read the table entry..
        let data = virt_read_struct::<LdrDataTableEntry>(reader, physmem, table_base, entry_addr)?;

        // ..and read it. I've seen dumps where the `full_dll_name` UNICODE_STRING have
        // a `buffer` member that points to an invalid virtual address. In
        // that case, we'll attempt to read the `base_dll_name` as a
        // recovery mechanism. If this one fails as well, well we got
        // nothing left.
        let dll_name =
            match virt_read_unicode_string(reader, physmem, table_base, &data.full_dll_name) {
                Ok(o) => Ok(o),
                e @ Err(KdmpParserError::VirtTranslate(..)) => e,
                Err(e) => return Err(e),
            }
            .or_else(|_| {
                virt_read_unicode_string(reader, physmem, table_base, &data.base_dll_name)
            })?;

        // Turn it into a string and shove it into the hash map.
        let dll_end_addr = data
            .dll_base
            .checked_add(data.size_of_image.into())
            .ok_or_else(|| KdmpParserError::Overflow("module address"))?;
        let at = data.dll_base.into()..dll_end_addr.into();
        let inserted = modules.insert(at, dll_name);
        debug_assert!(inserted.is_none());

        // Go to the next entry.
        entry_addr = data.in_load_order_links.flink.into();
    }

    Ok(modules)
}

fn extract_kernel_modules(
    reader: &mut impl Reader,
    physmem: &PhysmemMap,
    headers: &DumpHeader64,
) -> Result<ModuleMap> {
    let table_base = Gpa::from(headers.directory_table_base);
    // Read the first LIST_ENTRY - it is a dummy node, so grab the next address off
    // of it.
    let head_addr = Gva::from(headers.ps_loaded_module_list);
    // Walk the `PsLoadedModuleList` to extract the kernel modules.
    read_module_map(reader, physmem, table_base, head_addr)
}

// Let's try to find which nt!_KPRCB matches the CONTEXT that we have in the
// dump. This is the heuristic we use to figure out which processor was
// executing when the crash-dump was taken.
fn find_prcb(
    reader: &mut impl Reader,
    physmem: &PhysmemMap,
    headers: &DumpHeader64,
    kd_debugger_data_block: &KdDebuggerData64,
    context: &Context,
) -> Result<Option<u64>> {
    let table_base = Gpa::from(headers.directory_table_base);
    let mut kprcb_ptr_addr = kd_debugger_data_block.ki_processor_block;
    for _ in 0..headers.number_processors {
        let kprcb_ptr =
            virt_read_struct::<u64>(reader, physmem, table_base, kprcb_ptr_addr.into())?;

        let kprcb_context_ptr_addr = kprcb_ptr
            .checked_add(kd_debugger_data_block.offset_prcb_context.into())
            .ok_or(KdmpParserError::Overflow("offset_prcb"))?;

        let kprcb_context_ptr =
            virt_read_struct::<u64>(reader, physmem, table_base, kprcb_context_ptr_addr.into())?;

        let kprcb_context = Box::new(virt_read_struct::<Context>(
            reader,
            physmem,
            table_base,
            kprcb_context_ptr.into(),
        )?);

        if kprcb_context.rsp == context.rsp {
            return Ok(Some(kprcb_ptr));
        }

        kprcb_ptr_addr = kprcb_ptr_addr
            .checked_add(8)
            .ok_or(KdmpParserError::Overflow("kprcb ptr"))?;
    }

    Ok(None)
}

fn extract_user_modules(
    reader: &mut impl Reader,
    physmem: &PhysmemMap,
    headers: &DumpHeader64,
    kd_debugger_data_block: &KdDebuggerData64,
    prcb_addr: u64,
) -> Result<Option<ModuleMap>> {
    let table_base = Gpa::from(headers.directory_table_base);

    // Get the current _KTHREAD.
    let kthread_addr = prcb_addr
        .checked_add(kd_debugger_data_block.offset_prcb_current_thread.into())
        .ok_or(KdmpParserError::Overflow("offset prcb current thread"))?;
    let kthread_addr = virt_read_struct::<u64>(reader, physmem, table_base, kthread_addr.into())?;

    // Get the current TEB.
    let teb_addr = kthread_addr
        .checked_add(kd_debugger_data_block.offset_kthread_teb.into())
        .ok_or(KdmpParserError::Overflow("offset kthread teb"))?;
    let teb_addr = virt_read_struct::<u64>(reader, physmem, table_base, teb_addr.into())?;
    if teb_addr == 0 {
        return Ok(None);
    }

    // Get the PEB.
    // 1: kd> dt _TEB ProcessEnvironmentBlock
    // win32k!_TEB
    //    +0x060 ProcessEnvironmentBlock : Ptr64 _PEB
    let peb_offset = 0x60;
    let peb_addr = teb_addr
        .checked_add(peb_offset)
        .ok_or(KdmpParserError::Overflow("peb offset"))?;
    let peb_addr = virt_read_struct::<u64>(reader, physmem, table_base, peb_addr.into())?;

    // Get the _PEB_LDR_DATA.
    // 1: kd> dt nt!_PEB Ldr
    // +0x018 Ldr              : Ptr64 _PEB_LDR_DATA
    let ldr_offset = 0x18;
    let peb_ldr_addr = peb_addr
        .checked_add(ldr_offset)
        .ok_or(KdmpParserError::Overflow("ldr offset"))?;
    let peb_ldr_addr = virt_read_struct::<u64>(reader, physmem, table_base, peb_ldr_addr.into())?;

    // Grab the InLoadOrderModuleList.
    //     kd> dt nt!_PEB_LDR_DATA InLoadOrderModuleList
    //    +0x010 InLoadOrderModuleList : _LIST_ENTRY

    let in_load_order_module_list_offset = 0x10;
    let module_list_entry_addr = peb_ldr_addr
        .checked_add(in_load_order_module_list_offset)
        .ok_or(KdmpParserError::Overflow(
            "in load order module list offset",
        ))?;

    Ok(Some(read_module_map(
        reader,
        physmem,
        table_base,
        module_list_entry_addr.into(),
    )?))
}

/// A module map. The key is the range of where the module lives at and the
/// value is a path to the module or it's name if no path is available.
pub type ModuleMap = HashMap<Range<Gva>, String>;

/// A kernel dump parser that gives access to the physical memory space stored
/// in the dump. It also offers virtual to physical memory translation as well
/// as a virtual read facility.
pub struct KernelDumpParser<'reader> {
    /// Which type of dump is it?
    dump_type: DumpType,
    /// Context header.
    context: Box<Context>,
    /// The dump headers.
    headers: Box<DumpHeader64>,
    /// This maps a physical address to a file offset. Seeking there gives the
    /// page content.
    physmem: PhysmemMap,
    /// The [`Reader`] object that allows us to seek / read the dump file which
    /// could be memory mapped, read from a file, etc.
    reader: RefCell<Box<dyn Reader + 'reader>>,
    /// The driver modules loaded when the crash-dump was taken. Extracted from
    /// the nt!PsLoadedModuleList.
    kernel_modules: ModuleMap,
    user_modules: ModuleMap,
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
        let headers = Box::new(read_struct::<DumpHeader64>(&mut reader)?);
        if headers.signature != DUMP_HEADER64_EXPECTED_SIGNATURE {
            return Err(KdmpParserError::InvalidSignature(headers.signature));
        }

        if headers.valid_dump != DUMP_HEADER64_EXPECTED_VALID_DUMP {
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

        // Extract the kernel modules.
        let kernel_modules = extract_kernel_modules(&mut reader, &physmem, &headers)?;

        // Now let's try to find out user-modules.
        // First, we read the KDDEBUGGER_DATA_BLOCK structure to know where the PCRBs
        // are.
        let kd_debugger_data_block = Box::new(virt_read_struct::<KdDebuggerData64>(
            &mut reader,
            &physmem,
            headers.directory_table_base.into(),
            headers.kd_debugger_data_block.into(),
        )?);

        let user_modules = if let Some(prcb_addr) = find_prcb(
            &mut reader,
            &physmem,
            &headers,
            &kd_debugger_data_block,
            &context,
        )? {
            extract_user_modules(
                &mut reader,
                &physmem,
                &headers,
                &kd_debugger_data_block,
                prcb_addr,
            )
        } else {
            Ok(None)
        };

        let user_modules = match user_modules {
            Ok(o) => o,
            Err(KdmpParserError::PhysTranslate(..)) => None,
            Err(KdmpParserError::VirtTranslate(..)) => None,
            Err(e) => return Err(e),
        }
        .unwrap_or_default();

        let reader: RefCell<Box<dyn Reader>> = RefCell::new(Box::new(reader));

        Ok(Self {
            dump_type,
            context,
            headers,
            physmem,
            reader,
            kernel_modules,
            user_modules,
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
    pub fn headers(&self) -> &DumpHeader64 {
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

    /// Read physical memory starting at `gpa` into a `buffer`.
    pub fn phys_read(&self, gpa: Gpa, buffer: &mut [u8]) -> Result<usize> {
        phys_read(
            &mut self.reader.borrow_mut().as_mut(),
            &self.physmem,
            gpa,
            buffer,
        )
    }

    /// Read an exact amount of physical memory starting at `gpa` into a
    /// `buffer`.
    pub fn phys_read_exact(&self, gpa: Gpa, buffer: &mut [u8]) -> Result<()> {
        phys_read_exact(
            &mut self.reader.borrow_mut().as_mut(),
            &self.physmem,
            gpa,
            buffer,
        )
    }

    /// Read a `u64` in physical memory at `gpa`.
    pub fn phys_read8(&self, gpa: Gpa) -> Result<u64> {
        phys_read8(&mut self.reader.borrow_mut().as_mut(), &self.physmem, gpa)
    }

    /// Translate a [`Gva`] into a [`Gpa`].
    pub fn virt_translate(&self, gva: Gva) -> Result<Gpa> {
        virt_translate(
            &mut self.reader.borrow_mut().as_mut(),
            &self.physmem,
            Gpa::from(self.headers.directory_table_base),
            gva,
        )
    }

    /// Read virtual memory starting at `gva` into a `buffer`.
    pub fn virt_read(&self, gva: Gva, buffer: &mut [u8]) -> Result<usize> {
        virt_read(
            &mut self.reader.borrow_mut().as_mut(),
            &self.physmem,
            Gpa::from(self.headers.directory_table_base),
            gva,
            buffer,
        )
    }

    /// Read virtual memory starting at `gva`
    pub fn virt_read_exact(&self, gva: Gva, buffer: &mut [u8]) -> Result<()> {
        virt_read_exact(
            &mut self.reader.borrow_mut().as_mut(),
            &self.physmem,
            Gpa::from(self.headers.directory_table_base),
            gva,
            buffer,
        )
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
    fn full_physmem(headers: &DumpHeader64, reader: &mut impl Reader) -> Result<PhysmemMap> {
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
                let pa = gpa_from_bitmap(bitmap_idx, bit_idx)
                    .ok_or_else(|| KdmpParserError::Overflow("pfn in bitmap"))?;

                let insert = physmem.insert(pa, page_offset);
                debug_assert!(insert.is_none());
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
                    .ok_or_else(|| KdmpParserError::Overflow("w/ pfn_range"))?;
                let insert = physmem.insert(gpa, page_offset);
                debug_assert!(insert.is_none());
                page_offset = page_offset
                    .checked_add(Page::size())
                    .ok_or_else(|| KdmpParserError::Overflow("w/ page_offset"))?;
            }

            page_count = page_count
                .checked_add(pfn_range.number_of_pages)
                .ok_or_else(|| KdmpParserError::Overflow("w/ page_count"))?;
        }

        Ok(physmem)
    }

    fn build_physmem(
        dump_type: DumpType,
        headers: &DumpHeader64,
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
