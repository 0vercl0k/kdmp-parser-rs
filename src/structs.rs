// Axel '0vercl0k' Souchet - February 25 2024
//! This has all the raw structures that makes up Windows kernel crash-dumps.
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::io::SeekFrom;
use std::mem::MaybeUninit;
use std::slice;

use crate::error::Result;
use crate::{Gpa, KdmpParserError, Reader};

/// The different kind of physical pages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageKind {
    /// A normal 4kb page.
    Normal,
    /// A large 2mb page.
    Large,
    /// A huge 1gb page.
    Huge,
}

impl PageKind {
    /// Size in bytes of the page.
    #[must_use]
    pub fn size(&self) -> u64 {
        match self {
            Self::Normal => 4 * 1_024,
            Self::Large => 2 * 1_024 * 1_024,
            Self::Huge => 1_024 * 1_024 * 1_024,
        }
    }

    /// Extract the page offset of `addr`.
    #[must_use]
    pub fn page_offset(&self, addr: u64) -> u64 {
        let mask = self.size() - 1;

        addr & mask
    }
}

/// Types of kernel crash dump.
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u32)]
pub enum DumpType {
    // Old dump types from `dbgeng.dll`.
    Full = 0x1,
    Bmp = 0x5,
    /// Produced by `.dump /m`.
    // Mini = 0x4,
    /// (22H2+) Produced by `TaskMgr > System > Create live kernel Memory Dump`.
    LiveKernelMemory = 0x6,
    /// Produced by `.dump /k`.
    KernelMemory = 0x8,
    /// Produced by `.dump /ka`.
    KernelAndUserMemory = 0x9,
    /// Produced by `.dump /f`.
    CompleteMemory = 0xa,
}

/// The physical memory map maps a physical address to a file offset.
pub type PhysmemMap = BTreeMap<Gpa, u64>;

impl TryFrom<u32> for DumpType {
    type Error = KdmpParserError;

    fn try_from(value: u32) -> Result<Self> {
        match value {
            x if x == DumpType::Full as u32 => Ok(DumpType::Full),
            x if x == DumpType::Bmp as u32 => Ok(DumpType::Bmp),
            x if x == DumpType::KernelMemory as u32 => Ok(DumpType::KernelMemory),
            x if x == DumpType::KernelAndUserMemory as u32 => Ok(DumpType::KernelAndUserMemory),
            x if x == DumpType::CompleteMemory as u32 => Ok(DumpType::CompleteMemory),
            x if x == DumpType::LiveKernelMemory as u32 => Ok(DumpType::LiveKernelMemory),
            _ => Err(KdmpParserError::UnknownDumpType(value)),
        }
    }
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct ExceptionRecord64 {
    pub exception_code: u32,
    pub exception_flags: u32,
    pub exception_record: u64,
    pub exception_address: u64,
    pub number_parameters: u32,
    unused_alignment1: u32,
    pub exception_information: [u64; 15],
}

pub const DUMP_HEADER64_EXPECTED_SIGNATURE: u32 = 0x45_47_41_50; // 'EGAP'
pub const DUMP_HEADER64_EXPECTED_VALID_DUMP: u32 = 0x34_36_55_44; // '46UD'

/// Adjusted C struct for `DUMP_HEADERS64` from MS Rust docs. Padding
/// adjustment added from reversing `nt!IoFillDumpHeader`.
// https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Diagnostics/Debug/struct.DUMP_HEADER64.html#structfield.DumpType
#[repr(C)]
pub struct Header64 {
    pub signature: u32,
    pub valid_dump: u32,
    pub major_version: u32,
    pub minor_version: u32,
    pub directory_table_base: u64,
    pub pfn_database: u64,
    pub ps_loaded_module_list: u64,
    pub ps_active_process_head: u64,
    pub machine_image_type: u32,
    pub number_processors: u32,
    pub bug_check_code: u32,
    padding1: u32,
    pub bug_check_code_parameters: [u64; 4],
    pub version_user: [u8; 32],
    pub kd_debugger_data_block: u64,
    pub physical_memory_block_buffer: [u8; 700],
    padding2: u32,
    pub context_record_buffer: [u8; 3_000],
    pub exception: ExceptionRecord64,
    pub dump_type: u32,
    padding3: u32,
    pub required_dump_space: i64,
    pub system_time: i64,
    pub comment: [u8; 128],
    pub system_up_time: i64,
    pub minidump_fields: u32,
    pub secondary_data_state: u32,
    pub product_type: u32,
    pub suite_mask: u32,
    pub writer_status: u32,
    unused1: u8,
    pub kd_secondary_version: u8,
    unused2: [u8; 2],
    pub attributes: u32,
    pub boot_id: u32,
    reserved1: [u8; 4008],
}

impl Debug for Header64 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Header64")
            .field("signature", &self.signature)
            .field("valid_dump", &self.valid_dump)
            .field("major_version", &self.major_version)
            .field("minor_version", &self.minor_version)
            .field("directory_table_base", &self.directory_table_base)
            .field("pfn_database", &self.pfn_database)
            .field("ps_loaded_module_list", &self.ps_loaded_module_list)
            .field("ps_active_process_head", &self.ps_active_process_head)
            .field("machine_image_type", &self.machine_image_type)
            .field("number_processors", &self.number_processors)
            .field("bug_check_code", &self.bug_check_code)
            .field("bug_check_code_parameters", &self.bug_check_code_parameters)
            .field("version_user", &self.version_user)
            .field("kd_debugger_data_block", &self.kd_debugger_data_block)
            .field("exception", &self.exception)
            .field("dump_type", &self.dump_type)
            .field("required_dump_space", &self.required_dump_space)
            .field("system_time", &self.system_time)
            .field("comment", &self.comment)
            .field("system_up_time", &self.system_up_time)
            .field("minidump_fields", &self.minidump_fields)
            .field("secondary_data_state", &self.secondary_data_state)
            .field("product_type", &self.product_type)
            .field("suite_mask", &self.suite_mask)
            .field("writer_status", &self.writer_status)
            .field("kd_secondary_version", &self.kd_secondary_version)
            .field("attributes", &self.attributes)
            .field("boot_id", &self.boot_id)
            .finish_non_exhaustive()
    }
}

const BMPHEADER64_EXPECTED_SIGNATURE: u32 = 0x50_4D_44_53; // 'PMDS'
const BMPHEADER64_EXPECTED_SIGNATURE2: u32 = 0x50_4D_44_46; // 'PMDF'
const BMPHEADER64_EXPECTED_VALID_DUMP: u32 = 0x50_4D_55_44; // 'PMUD'

#[derive(Debug, Default)]
#[repr(C)]
pub struct BmpHeader64 {
    pub signature: u32,
    pub valid_dump: u32,
    // According to rekall there's a gap there:
    // 'ValidDump': [0x4, ['String', dict(
    //    length=4,
    //    term=None,
    //    )]],
    // # The offset of the first page in the file.
    // 'FirstPage': [0x20, ['unsigned long long']],
    padding1: [u8; 0x20 - (0x4 + size_of::<u32>())],
    /// The offset of the first page in the file.
    pub first_page: u64,
    /// Total number of pages present in the bitmap.
    pub total_present_pages: u64,
    /// Total number of pages in image. This dictates the total size of the
    /// bitmap. This is not the same as the `TotalPresentPages` which is only
    /// the sum of the bits set to 1.
    pub pages: u64,
    // Bitmap follows
}

impl BmpHeader64 {
    pub fn looks_good(&self) -> bool {
        (self.signature == BMPHEADER64_EXPECTED_SIGNATURE
            || self.signature == BMPHEADER64_EXPECTED_SIGNATURE2)
            && self.valid_dump == BMPHEADER64_EXPECTED_VALID_DUMP
    }
}

#[derive(Debug, Default)]
#[repr(C)]
pub struct PhysmemRun {
    pub base_page: u64,
    pub page_count: u64,
}

impl PhysmemRun {
    /// Calculate a physical address from a run and an index.
    ///
    /// The formulae is: (`base_page` + `page_idx`) * `PageKind::Normal.size()`.
    pub fn phys_addr(&self, page_idx: u64) -> Option<Gpa> {
        debug_assert!(page_idx < self.page_count);

        self.base_page
            .checked_add(page_idx)?
            .checked_mul(PageKind::Normal.size())
            .map(Gpa::new)
    }
}

#[derive(Debug, Default)]
#[repr(C)]
pub struct PhysmemDesc {
    pub number_of_runs: u32,
    padding1: u32,
    pub number_of_pages: u64,
    // PHYSMEM_RUN Run[1]; follows
}

impl TryFrom<&[u8]> for PhysmemDesc {
    type Error = KdmpParserError;

    fn try_from(slice: &[u8]) -> Result<Self> {
        let expected_len = size_of::<Self>();
        if slice.len() < expected_len {
            return Err(KdmpParserError::InvalidData("physmem desc is too small"));
        }

        let number_of_runs = u32::from_le_bytes((&slice[0..4]).try_into().unwrap());
        let number_of_pages = u64::from_le_bytes((&slice[4..12]).try_into().unwrap());

        Ok(Self {
            number_of_runs,
            number_of_pages,
            ..Default::default()
        })
    }
}

#[derive(PartialEq)]
#[repr(C)]
pub struct Context {
    pub p1_home: u64,
    pub p2_home: u64,
    pub p3_home: u64,
    pub p4_home: u64,
    pub p5_home: u64,
    pub p6_home: u64,
    pub context_flags: u32,
    pub mxcsr: u32,
    pub seg_cs: u16,
    pub seg_ds: u16,
    pub seg_es: u16,
    pub seg_fs: u16,
    pub seg_gs: u16,
    pub seg_ss: u16,
    pub eflags: u32,
    pub dr0: u64,
    pub dr1: u64,
    pub dr2: u64,
    pub dr3: u64,
    pub dr6: u64,
    pub dr7: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub control_word: u16,
    pub status_word: u16,
    pub tag_word: u8,
    reserved1: u8,
    pub error_opcode: u16,
    pub error_offset: u32,
    pub error_selector: u16,
    reserved2: u16,
    pub data_offset: u32,
    pub data_selector: u16,
    reserved3: u16,
    pub mxcsr2: u32,
    pub mxcsr_mask: u32,
    pub float_registers: [u128; 8],
    pub xmm_registers: [u128; 16],
    reserved4: [u8; 96],
    pub vector_register: [u128; 26],
    pub vector_control: u64,
    pub debug_control: u64,
    pub last_branch_to_rip: u64,
    pub last_branch_from_rip: u64,
    pub last_exception_to_rip: u64,
    pub last_exception_from_rip: u64,
}

impl Debug for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Context")
            .field("p1_home", &self.p1_home)
            .field("p2_home", &self.p2_home)
            .field("p3_home", &self.p3_home)
            .field("p4_home", &self.p4_home)
            .field("p5_home", &self.p5_home)
            .field("p6_home", &self.p6_home)
            .field("context_flags", &self.context_flags)
            .field("mxcsr", &self.mxcsr)
            .field("seg_cs", &self.seg_cs)
            .field("seg_ds", &self.seg_ds)
            .field("seg_es", &self.seg_es)
            .field("seg_fs", &self.seg_fs)
            .field("seg_gs", &self.seg_gs)
            .field("seg_ss", &self.seg_ss)
            .field("eflags", &self.eflags)
            .field("dr0", &self.dr0)
            .field("dr1", &self.dr1)
            .field("dr2", &self.dr2)
            .field("dr3", &self.dr3)
            .field("dr6", &self.dr6)
            .field("dr7", &self.dr7)
            .field("rax", &self.rax)
            .field("rcx", &self.rcx)
            .field("rdx", &self.rdx)
            .field("rbx", &self.rbx)
            .field("rsp", &self.rsp)
            .field("rbp", &self.rbp)
            .field("rsi", &self.rsi)
            .field("rdi", &self.rdi)
            .field("r8", &self.r8)
            .field("r9", &self.r9)
            .field("r10", &self.r10)
            .field("r11", &self.r11)
            .field("r12", &self.r12)
            .field("r13", &self.r13)
            .field("r14", &self.r14)
            .field("r15", &self.r15)
            .field("rip", &self.rip)
            .field("control_word", &self.control_word)
            .field("status_word", &self.status_word)
            .field("tag_word", &self.tag_word)
            .field("error_opcode", &self.error_opcode)
            .field("error_offset", &self.error_offset)
            .field("error_selector", &self.error_selector)
            .field("data_offset", &self.data_offset)
            .field("data_selector", &self.data_selector)
            .field("mxcsr2", &self.mxcsr2)
            .field("mxcsr_mask", &self.mxcsr_mask)
            .field("float_registers", &self.float_registers)
            .field("xmm_registers", &self.xmm_registers)
            .field("vector_register", &self.vector_register)
            .field("vector_control", &self.vector_control)
            .field("debug_control", &self.debug_control)
            .field("last_branch_to_rip", &self.last_branch_to_rip)
            .field("last_branch_from_rip", &self.last_branch_from_rip)
            .field("last_exception_to_rip", &self.last_exception_to_rip)
            .field("last_exception_from_rip", &self.last_exception_from_rip)
            .finish_non_exhaustive()
    }
}

/// Peek for a `T` from the cursor.
pub fn peek_struct<T>(reader: &mut impl Reader) -> Result<T> {
    let mut s: MaybeUninit<T> = MaybeUninit::uninit();
    let size_of_s = size_of_val(&s);
    let slice_over_s = unsafe { slice::from_raw_parts_mut(s.as_mut_ptr().cast::<u8>(), size_of_s) };

    let pos = reader.stream_position()?;
    reader.read_exact(slice_over_s)?;
    reader.seek(SeekFrom::Start(pos))?;

    Ok(unsafe { s.assume_init() })
}

/// Read a `T` from the cursor.
pub fn read_struct<T>(reader: &mut impl Reader) -> Result<T> {
    let s = peek_struct(reader)?;
    let size_of_s = size_of_val(&s);

    reader.seek(SeekFrom::Current(size_of_s.try_into().unwrap()))?;

    Ok(s)
}

const RDMP_HEADER64_EXPECTED_MARKER: u32 = 0x40;
const RDMP_HEADER64_EXPECTED_SIGNATURE: u32 = 0x50_4D_44_52; // 'PMDR'
const RDMP_HEADER64_EXPECTED_VALID_DUMP: u32 = 0x50_4D_55_44; // 'PMUD'

#[repr(C)]
#[derive(Debug, Default)]
pub struct RdmpHeader64 {
    pub marker: u32,
    pub signature: u32,
    pub valid_dump: u32,
    reserved1: u32,
    pub metadata_size: u64,
    pub first_page_offset: u64,
    // Bitmap follows
}

impl RdmpHeader64 {
    pub fn looks_good(&self) -> bool {
        if self.marker != RDMP_HEADER64_EXPECTED_MARKER {
            return false;
        }

        if self.signature != RDMP_HEADER64_EXPECTED_SIGNATURE {
            return false;
        }

        if self.valid_dump != RDMP_HEADER64_EXPECTED_VALID_DUMP {
            return false;
        }

        if self.metadata_size - 0x20 != self.first_page_offset - 0x20_40 {
            return false;
        }

        true
    }
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct KernelRdmpHeader64 {
    pub hdr: RdmpHeader64,
    unknown1: u64,
    unknown2: u64,
    // Bitmap follows
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct FullRdmpHeader64 {
    pub hdr: RdmpHeader64,
    pub number_of_ranges: u32,
    reserved1: u16,
    reserved2: u16,
    pub total_number_of_pages: u64,
    // Bitmap follows
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct PfnRange {
    pub page_file_number: u64,
    pub number_of_pages: u64,
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct ListEntry<P> {
    pub flink: P,
    pub blink: P,
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct UnicodeString<P> {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: P,
}

#[derive(Debug, Default)]
#[repr(C)]
pub struct LdrDataTableEntry<P> {
    pub in_load_order_links: ListEntry<P>,
    pub in_memory_order_links: ListEntry<P>,
    pub in_initialization_order_links: ListEntry<P>,
    pub dll_base: P,
    pub entry_point: P,
    pub size_of_image: u32,
    pub full_dll_name: UnicodeString<P>,
    pub base_dll_name: UnicodeString<P>,
}

// Copied from `WDBGEXTS.H`.
#[repr(C)]
#[derive(Debug, Default)]
pub struct DbgKdDebugDataHeader64 {
    /// Link to other blocks
    pub list: ListEntry<u64>,
    /// This is a unique tag to identify the owner of the block.
    /// If your component only uses one pool tag, use it for this, too.
    pub owner_tag: u32,
    /// This must be initialized to the size of the data block,
    /// including this structure.
    pub size: u32,
}

// https://github.com/tpn/winsdk-10/blob/9b69fd26ac0c7d0b83d378dba01080e93349c2ed/Include/10.0.14393.0/um/WDBGEXTS.H#L1206C16-L1206C34
#[repr(C)]
#[derive(Debug, Default)]
pub struct KdDebuggerData64 {
    pub header: DbgKdDebugDataHeader64,
    /// Base address of kernel image
    pub kern_base: u64,
    /// `DbgBreakPointWithStatus` is a function which takes an argument
    /// and hits a breakpoint. This field contains the address of the
    /// breakpoint instruction. When the debugger sees a breakpoint
    /// at this address, it may retrieve the argument from the first
    /// argument register, or on x86 the eax register.
    pub breakpoint_with_status: u64,
    /// Address of the saved context record during a bugcheck
    /// N.B. This is an automatic in `KeBugcheckEx`'s frame, and
    /// is only valid after a bugcheck.
    pub saved_context: u64,
    /// The address of the thread structure is provided in the
    /// `WAIT_STATE_CHANGE` packet.  This is the offset from the base of
    /// the thread structure to the pointer to the kernel stack frame
    /// for the currently active usermode callback.
    pub th_callback_stack: u16,
    //// saved pointer to next callback frame
    pub next_callback: u16,
    /// saved frame pointer
    pub frame_pointer: u16,
    /// pad to a quad boundary
    pub pae_enabled: u16,
    /// Address of the kernel callout routine.
    pub ki_call_user_mode: u64,
    /// Address of the usermode entry point for callbacks (in ntdll).
    pub ke_user_callback_dispatcher: u64,
    pub ps_loaded_module_list: u64,
    pub ps_active_process_head: u64,
    pub psp_cid_table: u64,
    pub exp_system_resources_list: u64,
    pub exp_paged_pool_descriptor: u64,
    pub exp_number_of_paged_pools: u64,
    pub ke_time_increment: u64,
    pub ke_bug_check_callback_list_head: u64,
    pub ki_bugcheck_data: u64,
    pub iop_error_log_list_head: u64,
    pub obp_root_directory_object: u64,
    pub obp_type_object_type: u64,
    pub mm_system_cache_start: u64,
    pub mm_system_cache_end: u64,
    pub mm_system_cache_ws: u64,
    pub mm_pfn_database: u64,
    pub mm_system_ptes_start: u64,
    pub mm_system_ptes_end: u64,
    pub mm_subsection_base: u64,
    pub mm_number_of_paging_files: u64,
    pub mm_lowest_physical_page: u64,
    pub mm_highest_physical_page: u64,
    pub mm_number_of_physical_pages: u64,
    pub mm_maximum_non_paged_pool_in_bytes: u64,
    pub mm_non_paged_system_start: u64,
    pub mm_non_paged_pool_start: u64,
    pub mm_non_paged_pool_end: u64,
    pub mm_paged_pool_start: u64,
    pub mm_paged_pool_end: u64,
    pub mm_paged_pool_information: u64,
    pub mm_page_size: u64,
    pub mm_size_of_paged_pool_in_bytes: u64,
    pub mm_total_commit_limit: u64,
    pub mm_total_committed_pages: u64,
    pub mm_shared_commit: u64,
    pub mm_driver_commit: u64,
    pub mm_process_commit: u64,
    pub mm_paged_pool_commit: u64,
    pub mm_extended_commit: u64,
    pub mm_zeroed_page_list_head: u64,
    pub mm_free_page_list_head: u64,
    pub mm_standby_page_list_head: u64,
    pub mm_modified_page_list_head: u64,
    pub mm_modified_no_write_page_list_head: u64,
    pub mm_available_pages: u64,
    pub mm_resident_available_pages: u64,
    pub pool_track_table: u64,
    pub non_paged_pool_descriptor: u64,
    pub mm_highest_user_address: u64,
    pub mm_system_range_start: u64,
    pub mm_user_probe_address: u64,
    pub kd_print_circular_buffer: u64,
    pub kd_print_circular_buffer_end: u64,
    pub kd_print_write_pointer: u64,
    pub kd_print_rollover_count: u64,
    pub mm_loaded_user_image_list: u64,
    // NT 5.1 Addition
    pub nt_build_lab: u64,
    pub ki_normal_system_call: u64,
    // NT 5.0 hotfix addition
    pub ki_processor_block: u64,
    pub mm_unloaded_drivers: u64,
    pub mm_last_unloaded_driver: u64,
    pub mm_triage_action_taken: u64,
    pub mm_special_pool_tag: u64,
    pub kernel_verifier: u64,
    pub mm_verifier_data: u64,
    pub mm_allocated_non_paged_pool: u64,
    pub mm_peak_commitment: u64,
    pub mm_total_commit_limit_maximum: u64,
    pub cm_nt_csd_version: u64,
    // NT 5.1 Addition
    pub mm_physical_memory_block: u64,
    pub mm_session_base: u64,
    pub mm_session_size: u64,
    pub mm_system_parent_table_page: u64,
    // Server 2003 addition
    pub mm_virtual_translation_base: u64,
    pub offset_kthread_next_processor: u16,
    pub offset_kthread_teb: u16,
    pub offset_kthread_kernel_stack: u16,
    pub offset_kthread_initial_stack: u16,
    pub offset_kthread_apc_process: u16,
    pub offset_kthread_state: u16,
    pub offset_kthread_b_store: u16,
    pub offset_kthread_b_store_limit: u16,
    pub size_eprocess: u16,
    pub offset_eprocess_peb: u16,
    pub offset_eprocess_parent_cid: u16,
    pub offset_eprocess_directory_table_base: u16,
    pub size_prcb: u16,
    pub offset_prcb_dpc_routine: u16,
    pub offset_prcb_current_thread: u16,
    pub offset_prcb_mhz: u16,
    pub offset_prcb_cpu_type: u16,
    pub offset_prcb_vendor_string: u16,
    pub offset_prcb_proc_state_context: u16,
    pub offset_prcb_number: u16,
    pub size_ethread: u16,
    pub kd_print_circular_buffer_ptr: u64,
    pub kd_print_buffer_size: u64,
    pub ke_loader_block: u64,
    pub size_pcr: u16,
    pub offset_pcr_self_pcr: u16,
    pub offset_pcr_current_prcb: u16,
    pub offset_pcr_contained_prcb: u16,
    pub offset_pcr_initial_b_store: u16,
    pub offset_pcr_b_store_limit: u16,
    pub offset_pcr_initial_stack: u16,
    pub offset_pcr_stack_limit: u16,
    pub offset_prcb_pcr_page: u16,
    pub offset_prcb_proc_state_special_reg: u16,
    pub gdt_r0_code: u16,
    pub gdt_r0_data: u16,
    pub gdt_r0_pcr: u16,
    pub gdt_r3_code: u16,
    pub gdt_r3_data: u16,
    pub gdt_r3_teb: u16,
    pub gdt_ldt: u16,
    pub gdt_tss: u16,
    pub gdt64_r3_cm_code: u16,
    pub gdt64_r3_cm_teb: u16,
    pub iop_num_triage_dump_data_blocks: u64,
    pub iop_triage_dump_data_blocks: u64,
    // Longhorn addition
    pub vf_crash_data_block: u64,
    pub mm_bad_pages_detected: u64,
    pub mm_zeroed_page_single_bit_errors_detected: u64,
    // Windows 7 addition
    pub etwp_debugger_data: u64,
    pub offset_prcb_context: u16,
    // ...
}

#[cfg(test)]
mod tests {
    use std::mem;

    use crate::structs::{Context, Header64, PhysmemDesc, PhysmemRun};

    /// Ensure that the sizes of key structures are right.
    #[test]
    fn layout() {
        assert_eq!(mem::size_of::<PhysmemDesc>(), 0x10);
        assert_eq!(mem::size_of::<PhysmemRun>(), 0x10);
        assert_eq!(mem::size_of::<Header64>(), 0x2_000);
        assert_eq!(mem::size_of::<Context>(), 0x4d0);
    }
}
