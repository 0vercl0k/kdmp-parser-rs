// Axel '0vercl0k' Souchet - February 25 2024
//! This has all the parsing logic for parsing kernel crash-dumps.
use core::slice;
use std::cell::RefCell;
use std::cmp::min;
use std::collections::HashMap;
use std::fmt::{self, Debug};
use std::fs::File;
use std::mem::MaybeUninit;
use std::ops::Range;
use std::path::Path;
use std::{io, mem};

use crate::bits::Bits;
use crate::error::{PxeNotPresent, Result};
use crate::gxa::Gxa;
use crate::map::{MappedFileReader, Reader};
use crate::structs::{
    BmpHeader64, Context, DUMP_HEADER64_EXPECTED_SIGNATURE, DUMP_HEADER64_EXPECTED_VALID_DUMP,
    DumpType, ExceptionRecord64, FullRdmpHeader64, Header64, KdDebuggerData64, KernelRdmpHeader64,
    LdrDataTableEntry, ListEntry, PageKind, PfnRange, PhysmemDesc, PhysmemMap, PhysmemRun,
    UnicodeString, read_struct,
};
use crate::{AddrTranslationError, Gpa, Gva, KdmpParserError, Pfn, Pxe};

/// The details related to a virtual to physical address translation.
///
/// If you are wondering why there is no 'readable' field, it is because
/// [`KernelDumpParser::virt_translate`] returns an error if one of the PXE is
/// marked as not present. In other words, if the translation succeeds, the page
/// is at least readable.
#[derive(Debug)]
pub struct VirtTranslationDetails {
    /// The physical address backing the virtual address that was requested.
    pub pfn: Pfn,
    /// The byte offset in that physical page.
    pub offset: u64,
    /// The kind of physical page.
    pub page_kind: PageKind,
    /// Is the page writable?
    pub writable: bool,
    /// Is the page executable?
    pub executable: bool,
    /// Is the page user accessible?
    pub user_accessible: bool,
}

impl VirtTranslationDetails {
    pub fn new(pxes: &[Pxe], gva: Gva) -> Self {
        let writable = pxes.iter().all(Pxe::writable);
        let executable = pxes.iter().all(Pxe::executable);
        let user_accessible = pxes.iter().all(Pxe::user_accessible);
        let pfn = pxes.last().map(|p| p.pfn).expect("at least one pxe");
        let page_kind = match pxes.len() {
            4 => PageKind::Normal,
            3 => PageKind::Large,
            2 => PageKind::Huge,
            _ => unreachable!("pxes len should be between 2 and 4"),
        };
        let offset = page_kind.page_offset(gva.u64());

        Self {
            pfn,
            offset,
            page_kind,
            writable,
            executable,
            user_accessible,
        }
    }

    #[must_use]
    pub fn gpa(&self) -> Gpa {
        self.pfn.gpa_with_offset(self.offset)
    }
}

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

/// This trait is used to implement generic behavior for both 32/64-bit.
/// It is implemented for both [`u32`] & [`u64`].
trait PtrSize: Sized + Copy + Into<u64> + From<u32> {
    fn checked_add(self, rhs: Self) -> Option<Self>;
}

macro_rules! impl_checked_add {
    ($($ty:ident),*) => {
        $(impl PtrSize for $ty {
            fn checked_add(self, rhs: $ty) -> Option<Self> {
                $ty::checked_add(self, rhs)
            }
        })*
    };
}

impl_checked_add!(u32, u64);

/// Walk a `LIST_ENTRY` of `LdrDataTableEntry`. It is used to dump both the user
/// & driver / module lists.
fn try_read_module_map<P>(parser: &mut KernelDumpParser, head: Gva) -> Result<Option<ModuleMap>>
where
    P: PtrSize,
{
    let mut modules = ModuleMap::new();
    let Some(entry) = parser.try_virt_read_struct::<ListEntry<P>>(head)? else {
        return Ok(None);
    };

    let mut entry_addr = Gva::new(entry.flink.into());
    // We'll walk it until we hit the starting point (it is circular).
    while entry_addr != head {
        // Read the table entry..
        let Some(data) = parser.try_virt_read_struct::<LdrDataTableEntry<P>>(entry_addr)? else {
            return Ok(None);
        };

        // ..and read it. We first try to read `full_dll_name` but will try
        // `base_dll_name` is we couldn't read the former.
        let Some(dll_name) = parser
            .try_virt_read_unicode_string::<P>(&data.full_dll_name)
            .and_then(|s| {
                if s.is_none() {
                    // If we failed to read the `full_dll_name`, give `base_dll_name` a shot.
                    parser.try_virt_read_unicode_string::<P>(&data.base_dll_name)
                } else {
                    Ok(s)
                }
            })?
        else {
            return Ok(None);
        };

        // Shove it into the map.
        let dll_end_addr = data
            .dll_base
            .checked_add(data.size_of_image.into())
            .ok_or(KdmpParserError::Overflow("module address"))?;
        let at = Gva::new(data.dll_base.into())..Gva::new(dll_end_addr.into());
        let inserted = modules.insert(at, dll_name);
        debug_assert!(inserted.is_none());

        // Go to the next entry.
        entry_addr = Gva::new(data.in_load_order_links.flink.into());
    }

    Ok(Some(modules))
}

/// Extract the drivers / modules out of the `PsLoadedModuleList`.
fn try_extract_kernel_modules(parser: &mut KernelDumpParser) -> Result<Option<ModuleMap>> {
    // Walk the LIST_ENTRY!
    try_read_module_map::<u64>(parser, parser.headers().ps_loaded_module_list.into())
}

/// Try to find the right `nt!_KPRCB` by walking them and finding one that has
/// the same `Rsp` than in the dump headers' context.
fn try_find_prcb(
    parser: &mut KernelDumpParser,
    kd_debugger_data_block: &KdDebuggerData64,
) -> Result<Option<Gva>> {
    let mut processor_block = kd_debugger_data_block.ki_processor_block;
    for _ in 0..parser.headers().number_processors {
        // Read the KPRCB pointer.
        let Some(kprcb_addr) = parser.try_virt_read_struct::<u64>(processor_block.into())? else {
            return Ok(None);
        };

        // Calculate the address of where the CONTEXT pointer is at..
        let kprcb_context_addr = kprcb_addr
            .checked_add(kd_debugger_data_block.offset_prcb_context.into())
            .ok_or(KdmpParserError::Overflow("offset_prcb"))?;

        // ..and read it.
        let Some(kprcb_context_addr) =
            parser.try_virt_read_struct::<u64>(kprcb_context_addr.into())?
        else {
            return Ok(None);
        };

        // Read the context..
        let Some(kprcb_context) =
            parser.try_virt_read_struct::<Context>(kprcb_context_addr.into())?
        else {
            return Ok(None);
        };

        // ..and compare it to ours.
        let kprcb_context = Box::new(kprcb_context);
        if kprcb_context.rsp == parser.context_record().rsp {
            // The register match so we'll assume the current KPRCB is the one describing
            // the 'foreground' processor in the crash-dump.
            return Ok(Some(kprcb_addr.into()));
        }

        // Otherwise, let's move on to the next pointer.
        processor_block = processor_block
            .checked_add(mem::size_of::<u64>() as _)
            .ok_or(KdmpParserError::Overflow("kprcb ptr"))?;
    }

    Ok(None)
}

/// Extract the user modules list by grabbing the current thread from the KPRCB.
/// Then, walk the `PEB.Ldr.InLoadOrderModuleList`.
fn try_extract_user_modules(
    parser: &mut KernelDumpParser,
    kd_debugger_data_block: &KdDebuggerData64,
    prcb_addr: Gva,
) -> Result<Option<ModuleMap>> {
    // Get the current _KTHREAD..
    let kthread_addr = prcb_addr
        .u64()
        .checked_add(kd_debugger_data_block.offset_prcb_current_thread.into())
        .ok_or(KdmpParserError::Overflow("offset prcb current thread"))?;
    let Some(kthread_addr) = parser.try_virt_read_struct::<u64>(kthread_addr.into())? else {
        return Ok(None);
    };

    // ..then its TEB..
    let teb_addr = kthread_addr
        .checked_add(kd_debugger_data_block.offset_kthread_teb.into())
        .ok_or(KdmpParserError::Overflow("offset kthread teb"))?;
    let Some(teb_addr) = parser.try_virt_read_struct::<u64>(teb_addr.into())? else {
        return Ok(None);
    };

    if teb_addr == 0 {
        return Ok(None);
    }

    // ..then its PEB..
    // ```
    // kd> dt nt!_TEB ProcessEnvironmentBlock
    // nt!_TEB
    //    +0x060 ProcessEnvironmentBlock : Ptr64 _PEB
    // ```
    let peb_offset = 0x60;
    let peb_addr = teb_addr
        .checked_add(peb_offset)
        .ok_or(KdmpParserError::Overflow("peb offset"))?;
    let Some(peb_addr) = parser.try_virt_read_struct::<u64>(peb_addr.into())? else {
        return Ok(None);
    };

    // ..then its _PEB_LDR_DATA..
    // ```
    // kd> dt nt!_PEB Ldr
    // +0x018 Ldr              : Ptr64 _PEB_LDR_DATA
    // ```
    let ldr_offset = 0x18;
    let peb_ldr_addr = peb_addr
        .checked_add(ldr_offset)
        .ok_or(KdmpParserError::Overflow("ldr offset"))?;
    let Some(peb_ldr_addr) = parser.try_virt_read_struct::<u64>(peb_ldr_addr.into())? else {
        return Ok(None);
    };

    // ..and finally the `InLoadOrderModuleList`.
    // ```
    // kd> dt nt!_PEB_LDR_DATA InLoadOrderModuleList
    // +0x010 InLoadOrderModuleList : _LIST_ENTRY
    // ````
    let in_load_order_module_list_offset = 0x10;
    let module_list_entry_addr = peb_ldr_addr
        .checked_add(in_load_order_module_list_offset)
        .ok_or(KdmpParserError::Overflow(
            "in load order module list offset",
        ))?;

    // From there, we walk the list!
    let Some(mut modules) = try_read_module_map::<u64>(parser, module_list_entry_addr.into())?
    else {
        return Ok(None);
    };

    // Now, it's time to dump the TEB32 if there's one.
    //
    // TEB32 is at offset 0x2000 from TEB and PEB32 is at +0x30:
    // ```
    // kd> dt nt!_TEB32 ProcessEnvironmentBlock
    // nt!_TEB32
    // +0x030 ProcessEnvironmentBlock : Uint4B
    // ```
    let teb32_offset = 0x2_000;
    let teb32_addr = teb_addr
        .checked_add(teb32_offset)
        .ok_or(KdmpParserError::Overflow("teb32 offset"))?;
    let peb32_offset = 0x30;
    let peb32_addr = teb32_addr
        .checked_add(peb32_offset)
        .ok_or(KdmpParserError::Overflow("peb32 offset"))?;
    let Some(peb32_addr) = parser.try_virt_read_struct::<u32>(peb32_addr.into())? else {
        return Ok(Some(modules));
    };

    // ..then its _PEB_LDR_DATA.. (32-bit)
    // ```
    // kd> dt nt!_PEB32 Ldr
    // +0x00c Ldr              : Uint4B
    // ```
    let ldr_offset = 0x0c;
    let peb32_ldr_addr = peb32_addr
        .checked_add(ldr_offset)
        .ok_or(KdmpParserError::Overflow("ldr32 offset"))?;
    let Some(peb32_ldr_addr) =
        parser.try_virt_read_struct::<u32>(Gva::new(peb32_ldr_addr.into()))?
    else {
        return Ok(Some(modules));
    };

    // ..and finally the `InLoadOrderModuleList`.
    // ```
    // 0:000> dt ntdll!_PEB_LDR_DATA InLoadOrderModuleList
    // +0x00c InLoadOrderModuleList : _LIST_ENTRY
    // ````
    let in_load_order_module_list_offset = 0xc;
    let module_list_entry_addr = peb32_ldr_addr
        .checked_add(in_load_order_module_list_offset)
        .ok_or(KdmpParserError::Overflow(
            "in load order module list offset",
        ))?;

    // From there, we walk the list!
    let Some(modules32) =
        try_read_module_map::<u32>(parser, Gva::new(module_list_entry_addr.into()))?
    else {
        return Ok(Some(modules));
    };

    // Merge the lists.
    modules.extend(modules32);

    // We're done!
    Ok(Some(modules))
}

/// Filter out [`AddrTranslationError`] errors and turn them into `None`. This
/// makes it easier for caller code to write logic that can recover from a
/// memory read failure by bailing out for example, and not bubbling up an
/// error.
fn filter_addr_translation_err<T>(res: Result<T>) -> Result<Option<T>> {
    match res {
        Ok(o) => Ok(Some(o)),
        // If we encountered a memory reading error, we won't consider this as a failure.
        Err(KdmpParserError::AddrTranslation(..)) => Ok(None),
        Err(e) => Err(e),
    }
}

/// A module map. The key is the range of where the module lives at and the
/// value is a path to the module or it's name if no path is available.
pub type ModuleMap = HashMap<Range<Gva>, String>;

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
    physmem: PhysmemMap,
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
    /// Create an instance from a file path. This memory maps the file and
    /// parses it.
    pub fn with_reader(mut reader: impl Reader + 'static) -> Result<Self> {
        // Parse the dump header and check if things look right.
        let headers = Box::new(read_struct::<Header64>(&mut reader)?);
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
        if let Some(kernel_modules) = try_extract_kernel_modules(&mut parser)? {
            parser.kernel_modules.extend(kernel_modules);
        }

        // Now let's try to find out user-modules. For that we need the
        // KDDEBUGGER_DATA_BLOCK structure to know where a bunch of things are.
        // If we can't read the block, we'll have to stop the adventure here as we won't
        // be able to read the things we need to keep going.
        let Some(kd_debugger_data_block) = parser.try_virt_read_struct::<KdDebuggerData64>(
            parser.headers().kd_debugger_data_block.into(),
        )?
        else {
            return Ok(parser);
        };
        let kd_debugger_data_block = Box::new(kd_debugger_data_block);

        // We need to figure out which PRCB is the one that crashed.
        let Some(prcb_addr) = try_find_prcb(&mut parser, &kd_debugger_data_block)? else {
            return Ok(parser);
        };

        // Finally, we're ready to extract the user modules!
        let Some(user_modules) =
            try_extract_user_modules(&mut parser, &kd_debugger_data_block, prcb_addr)?
        else {
            return Ok(parser);
        };

        parser.user_modules.extend(user_modules);

        Ok(parser)
    }

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

    /// Translate a [`Gpa`] into a file offset of where the content of the page
    /// resides in.
    pub fn phys_translate(&self, gpa: Gpa) -> Result<u64> {
        let offset = *self
            .physmem
            .get(&gpa.page_align())
            .ok_or(AddrTranslationError::Phys(gpa))?;

        offset
            .checked_add(gpa.offset())
            .ok_or(KdmpParserError::Overflow("w/ gpa offset"))
    }

    /// Read physical memory starting at `gpa` into a `buffer`.
    pub fn phys_read(&self, gpa: Gpa, buf: &mut [u8]) -> Result<usize> {
        // Amount of bytes left to read.
        let mut amount_left = buf.len();
        // Total amount of bytes that we have successfully read.
        let mut total_read = 0;
        // The current gpa we are reading from.
        let mut addr = gpa;
        // Let's try to read as much as the user wants.
        while amount_left > 0 {
            // Translate the gpa into a file offset..
            let phy_offset = self.phys_translate(addr)?;
            // ..and seek the reader there.
            self.seek(io::SeekFrom::Start(phy_offset))?;
            // We need to take care of reads that straddle different physical memory pages.
            // So let's figure out the maximum amount of bytes we can read off this page.
            // Either, we read it until its end, or we stop if the user wants us to read
            // less.
            let left_in_page = usize::try_from(PageKind::Normal.size() - gpa.offset()).unwrap();
            let amount_wanted = min(amount_left, left_in_page);
            // Figure out where we should read into.
            let slice = &mut buf[total_read..total_read + amount_wanted];
            // Read the physical memory!
            let amount_read = self.read(slice)?;
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
    pub fn phys_read_exact(&self, gpa: Gpa, buf: &mut [u8]) -> Result<()> {
        // Read physical memory.
        let len = self.phys_read(gpa, buf)?;

        // If we read as many bytes as we wanted, then it's a win..
        if len == buf.len() {
            Ok(())
        }
        // ..otherwise, we call it quits.
        else {
            Err(KdmpParserError::PartialPhysRead)
        }
    }

    /// Read a `T` from physical memory.
    pub fn phys_read_struct<T>(&self, gpa: Gpa) -> Result<T> {
        let mut t: MaybeUninit<T> = MaybeUninit::uninit();
        let size_of_t = size_of_val(&t);
        let slice_over_t =
            unsafe { slice::from_raw_parts_mut(t.as_mut_ptr().cast::<u8>(), size_of_t) };

        self.phys_read_exact(gpa, slice_over_t)?;

        Ok(unsafe { t.assume_init() })
    }

    /// Translate a [`Gva`] into a [`Gpa`].
    pub fn virt_translate(&self, gva: Gva) -> Result<VirtTranslationDetails> {
        self.virt_translate_with_dtb(gva, Gpa::new(self.headers.directory_table_base))
    }

    /// Translate a [`Gva`] into a [`Gpa`] using a specific directory table base
    /// / set of page tables.
    #[allow(clippy::similar_names)]
    pub fn virt_translate_with_dtb(&self, gva: Gva, dtb: Gpa) -> Result<VirtTranslationDetails> {
        // Aligning in case PCID bits are set (bits 11:0)
        let pml4_base = dtb.page_align();
        let pml4e_gpa = Gpa::new(pml4_base.u64() + (gva.pml4e_idx() * 8));
        let pml4e = Pxe::from(self.phys_read_struct::<u64>(pml4e_gpa)?);
        if !pml4e.present() {
            return Err(AddrTranslationError::Virt(gva, PxeNotPresent::Pml4e).into());
        }

        let pdpt_base = pml4e.pfn.gpa();
        let pdpte_gpa = Gpa::new(pdpt_base.u64() + (gva.pdpe_idx() * 8));
        let pdpte = Pxe::from(self.phys_read_struct::<u64>(pdpte_gpa)?);
        if !pdpte.present() {
            return Err(AddrTranslationError::Virt(gva, PxeNotPresent::Pdpte).into());
        }

        // huge pages:
        // 7 (PS) - Page size; must be 1 (otherwise, this entry references a page
        // directory; see Table 4-1.
        let pd_base = pdpte.pfn.gpa();
        if pdpte.large_page() {
            return Ok(VirtTranslationDetails::new(&[pml4e, pdpte], gva));
        }

        let pde_gpa = Gpa::new(pd_base.u64() + (gva.pde_idx() * 8));
        let pde = Pxe::from(self.phys_read_struct::<u64>(pde_gpa)?);
        if !pde.present() {
            return Err(AddrTranslationError::Virt(gva, PxeNotPresent::Pde).into());
        }

        // large pages:
        // 7 (PS) - Page size; must be 1 (otherwise, this entry references a page
        // table; see Table 4-18.
        let pt_base = pde.pfn.gpa();
        if pde.large_page() {
            return Ok(VirtTranslationDetails::new(&[pml4e, pdpte, pde], gva));
        }

        let pte_gpa = Gpa::new(pt_base.u64() + (gva.pte_idx() * 8));
        let pte = Pxe::from(self.phys_read_struct::<u64>(pte_gpa)?);
        if !pte.present() {
            // We'll allow reading from a transition PTE, so return an error only if it's
            // not one, otherwise we'll carry on.
            if !pte.transition() {
                return Err(AddrTranslationError::Virt(gva, PxeNotPresent::Pte).into());
            }
        }

        Ok(VirtTranslationDetails::new(&[pml4e, pdpte, pde, pte], gva))
    }

    /// Read virtual memory starting at `gva` into a `buffer`.
    pub fn virt_read(&self, gva: Gva, buf: &mut [u8]) -> Result<usize> {
        self.virt_read_with_dtb(gva, buf, Gpa::new(self.headers.directory_table_base))
    }

    /// Read virtual memory starting at `gva` into a `buffer` using a specific
    /// directory table base / set of page tables.
    pub fn virt_read_with_dtb(&self, gva: Gva, buf: &mut [u8], dtb: Gpa) -> Result<usize> {
        // Amount of bytes left to read.
        let mut amount_left = buf.len();
        // Total amount of bytes that we have successfully read.
        let mut total_read = 0;
        // The current gva we are reading from.
        let mut addr = gva;
        // Let's try to read as much as the user wants.
        while amount_left > 0 {
            // Translate the gva into a gpa. But make sure to not early return if an error
            // occured if we already have read some bytes.
            let translation = match self.virt_translate_with_dtb(addr, dtb) {
                Ok(tr) => tr,
                Err(e) => {
                    if total_read > 0 {
                        // If we already read some bytes, return how many we read.
                        return Ok(total_read);
                    }

                    return Err(e);
                }
            };

            // We need to take care of reads that straddle different virtual memory pages.
            // First, figure out the maximum amount of bytes we can read off this page.
            let left_in_page =
                usize::try_from(translation.page_kind.size() - translation.offset).unwrap();
            // Then, either we read it until its end, or we stop before if we can get by
            // with less.
            let amount_wanted = min(amount_left, left_in_page);
            // Figure out where we should read into.
            let slice = &mut buf[total_read..total_read + amount_wanted];

            // Read the physical memory!
            let amount_read = self.phys_read(translation.gpa(), slice)?;
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

    /// Try to read virtual memory starting at `gva` into a `buffer`. If a
    /// memory translation error occurs, it'll return `None` instead of an
    /// error.
    pub fn try_virt_read(&self, gva: Gva, buf: &mut [u8]) -> Result<Option<usize>> {
        filter_addr_translation_err(self.virt_read(gva, buf))
    }

    /// Try to read virtual memory starting at `gva` into a `buffer` using a
    /// specific directory table base / set of page tables. If a
    /// memory translation error occurs, it'll return `None` instead of an
    /// error.
    pub fn try_virt_read_with_dtb(
        &self,
        gva: Gva,
        buf: &mut [u8],
        dtb: Gpa,
    ) -> Result<Option<usize>> {
        filter_addr_translation_err(self.virt_read_with_dtb(gva, buf, dtb))
    }

    /// Read an exact amount of virtual memory starting at `gva`.
    pub fn virt_read_exact(&self, gva: Gva, buf: &mut [u8]) -> Result<()> {
        self.virt_read_exact_with_dtb(gva, buf, Gpa::new(self.headers.directory_table_base))
    }

    /// Read an exact amount of virtual memory starting at `gva` using a
    /// specific directory table base / set of page tables.
    pub fn virt_read_exact_with_dtb(&self, gva: Gva, buf: &mut [u8], dtb: Gpa) -> Result<()> {
        // Read virtual memory.
        let len = self.virt_read_with_dtb(gva, buf, dtb)?;

        // If we read as many bytes as we wanted, then it's a win..
        if len == buf.len() {
            Ok(())
        }
        // ..otherwise, we call it quits.
        else {
            Err(KdmpParserError::PartialVirtRead)
        }
    }

    /// Try to read an exact amount of virtual memory starting at `gva`. If a
    /// memory translation error occurs, it'll return `None` instead of an
    /// error.
    pub fn try_virt_read_exact(&self, gva: Gva, buf: &mut [u8]) -> Result<Option<()>> {
        self.try_virt_read_exact_with_dtb(gva, buf, Gpa::new(self.headers.directory_table_base))
    }

    /// Try to read an exact amount of virtual memory starting at `gva` using a
    /// specific directory table base / set of page tables. If a
    /// memory translation error occurs, it'll return `None` instead of an
    /// error.
    pub fn try_virt_read_exact_with_dtb(
        &self,
        gva: Gva,
        buf: &mut [u8],
        dtb: Gpa,
    ) -> Result<Option<()>> {
        filter_addr_translation_err(self.virt_read_exact_with_dtb(gva, buf, dtb))
    }

    /// Read a `T` from virtual memory.
    pub fn virt_read_struct<T>(&self, gva: Gva) -> Result<T> {
        self.virt_read_struct_with_dtb(gva, Gpa::new(self.headers.directory_table_base))
    }

    /// Read a `T` from virtual memory using a specific directory table base /
    /// set of page tables.
    pub fn virt_read_struct_with_dtb<T>(&self, gva: Gva, dtb: Gpa) -> Result<T> {
        let mut t: MaybeUninit<T> = MaybeUninit::uninit();
        let size_of_t = size_of_val(&t);
        let slice_over_t =
            unsafe { slice::from_raw_parts_mut(t.as_mut_ptr().cast::<u8>(), size_of_t) };

        self.virt_read_exact_with_dtb(gva, slice_over_t, dtb)?;

        Ok(unsafe { t.assume_init() })
    }

    /// Try to read a `T` from virtual memory . If a memory translation error
    /// occurs, it'll return `None` instead of an error.
    pub fn try_virt_read_struct<T>(&self, gva: Gva) -> Result<Option<T>> {
        self.try_virt_read_struct_with_dtb::<T>(gva, Gpa::new(self.headers.directory_table_base))
    }

    /// Try to read a `T` from virtual memory using a specific directory table
    /// base / set of page tables. If a memory translation error occurs, it'
    /// ll return `None` instead of an error.
    pub fn try_virt_read_struct_with_dtb<T>(&self, gva: Gva, dtb: Gpa) -> Result<Option<T>> {
        filter_addr_translation_err(self.virt_read_struct_with_dtb::<T>(gva, dtb))
    }

    pub fn seek(&self, pos: io::SeekFrom) -> Result<u64> {
        Ok(self.reader.borrow_mut().seek(pos)?)
    }

    pub fn read(&self, buf: &mut [u8]) -> Result<usize> {
        Ok(self.reader.borrow_mut().read(buf)?)
    }

    /// Try to read a `UNICODE_STRING`.
    fn try_virt_read_unicode_string<P>(
        &self,
        unicode_str: &UnicodeString<P>,
    ) -> Result<Option<String>>
    where
        P: PtrSize,
    {
        self.try_virt_read_unicode_string_with_dtb(
            unicode_str,
            Gpa::new(self.headers.directory_table_base),
        )
    }

    /// Try to read a `UNICODE_STRING` using a specific directory table base /
    /// set of page tables.
    fn try_virt_read_unicode_string_with_dtb<P>(
        &self,
        unicode_str: &UnicodeString<P>,
        dtb: Gpa,
    ) -> Result<Option<String>>
    where
        P: PtrSize,
    {
        if (unicode_str.length % 2) != 0 {
            return Err(KdmpParserError::InvalidUnicodeString);
        }

        let mut buffer = vec![0; unicode_str.length.into()];
        match self.virt_read_exact_with_dtb(Gva::new(unicode_str.buffer.into()), &mut buffer, dtb) {
            Ok(()) => {}
            // If we encountered a memory translation error, we don't consider this a failure.
            Err(KdmpParserError::AddrTranslation(_)) => return Ok(None),
            Err(e) => return Err(e),
        }

        let n = unicode_str.length / 2;

        Ok(Some(String::from_utf16(unsafe {
            slice::from_raw_parts(buffer.as_ptr().cast(), n.into())
        })?))
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
                    .ok_or(KdmpParserError::PhysAddrOverflow(run_idx, page_idx))?;

                // We now know where this page lives at, insert it into the physmem map.
                if physmem.insert(phys_addr, page_offset).is_some() {
                    return Err(KdmpParserError::DuplicateGpa(phys_addr));
                }

                // Move the page offset along.
                page_offset = page_offset
                    .checked_add(PageKind::Normal.size())
                    .ok_or(KdmpParserError::PageOffsetOverflow(run_idx, page_idx))?;
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
                let pa = gpa_from_bitmap(bitmap_idx, bit_idx)
                    .ok_or(KdmpParserError::Overflow("pfn in bitmap"))?;

                let insert = physmem.insert(pa, page_offset);
                debug_assert!(insert.is_none());
                page_offset = page_offset.checked_add(PageKind::Normal.size()).ok_or(
                    KdmpParserError::BitmapPageOffsetOverflow(bitmap_idx, bit_idx),
                )?;
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
                    .ok_or(KdmpParserError::Overflow("w/ pfn_range"))?;
                let insert = physmem.insert(gpa, page_offset);
                debug_assert!(insert.is_none());
                page_offset = page_offset
                    .checked_add(PageKind::Normal.size())
                    .ok_or(KdmpParserError::Overflow("w/ page_offset"))?;
            }

            page_count = page_count
                .checked_add(pfn_range.number_of_pages)
                .ok_or(KdmpParserError::Overflow("w/ page_count"))?;
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
