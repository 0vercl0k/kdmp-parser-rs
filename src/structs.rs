// Axel '0vercl0k' Souchet - February 25 2024
//! This has all the raw structures that makes up Windows kernel crash-dumps.
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::{io, mem, slice};

use crate::error::Result;
use crate::{Gpa, KdmpParserError, Reader};

/// A page.
pub struct Page;

impl Page {
    /// Get the size of a memory page.
    pub const fn size() -> u64 {
        0x1_000
    }
}

/// Types of kernel crash dump.
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u32)]
pub enum DumpType {
    // Old dump types from dbgeng.dll
    Full = 0x1,
    Bmp = 0x5,
    /// Produced by `.dump /m`.
    // Mini = 0x4,
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
    __unused_alignment: u32,
    pub exception_information: [u64; 15],
}

pub const HEADER64_EXPECTED_SIGNATURE: u32 = 0x45_47_41_50; // 'EGAP'
pub const HEADER64_EXPECTED_VALID_DUMP: u32 = 0x34_36_55_44; // '46UD'

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
    __padding0: u32,
    pub bug_check_code_parameters: [u64; 4],
    pub version_user: [u8; 32],
    pub kd_debugger_data_block: u64,
    //   /* 0x0088 */ union DUMP_HEADER64_0 {
    //     PHYSMEM_DESC PhysicalMemoryBlock;
    //     std::array<uint8_t, 700> PhysicalMemoryBlockBuffer;
    //   } u1;
    pub physical_memory_block_buffer: [u8; 700],
    // 0x0344
    __padding1: u32,
    //   /* 0x0348 */ union CONTEXT_RECORD64_0 {
    //     CONTEXT ContextRecord;
    //     std::array<uint8_t, 3000> ContextRecordBuffer;
    //   } u2;
    pub context_record_buffer: [u8; 3_000],
    pub exception: ExceptionRecord64,
    pub dump_type: u32,
    __padding2: u32,
    pub required_dump_space: i64,
    pub system_time: i64,
    pub comment: [u8; 128],
    pub system_up_time: i64,
    pub minidump_fields: u32,
    pub secondary_data_state: u32,
    pub product_type: u32,
    pub suite_mask: u32,
    pub writer_status: u32,
    __unused0: u8,
    pub kd_secondary_version: u8,
    __unused1: [u8; 2],
    pub attributes: u32,
    pub boot_id: u32,
    __reserved0: [u8; 4008],
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
            .finish()
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
    pub __padding0: [u8; 0x20 - (0x4 + mem::size_of::<u32>())],
    /// The offset of the first page in the file.
    pub first_page: u64,
    /// Total number of pages present in the bitmap.
    pub total_present_pages: u64,
    /// Total number of pages in image. This dictates the total size of the
    /// bitmap.This is not the same as the TotalPresentPages which is only
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
    /// The formulae is: (`base_page` + `page_idx`) * `Page::size()`.
    pub fn phys_addr(&self, page_idx: u64) -> Option<Gpa> {
        debug_assert!(page_idx < self.page_count);

        self.base_page
            .checked_add(page_idx)?
            .checked_mul(Page::size())
            .map(Gpa::new)
    }
}

#[derive(Debug, Default)]
#[repr(C)]
pub struct PhysmemDesc {
    pub number_of_runs: u32,
    __padding0: u32,
    pub number_of_pages: u64,
    // PHYSMEM_RUN Run[1]; follows
}

impl TryFrom<&[u8]> for PhysmemDesc {
    type Error = KdmpParserError;

    fn try_from(slice: &[u8]) -> Result<Self> {
        let expected_len = mem::size_of::<Self>();
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

#[derive(Debug)]
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

/// Peek for a `T` from the cursor.
pub fn peek_struct<T>(reader: &mut impl Reader) -> Result<T> {
    let mut s = mem::MaybeUninit::uninit();
    let size_of_s = mem::size_of_val(&s);
    let slice_over_s = unsafe { slice::from_raw_parts_mut(s.as_mut_ptr() as *mut u8, size_of_s) };

    let pos = reader.stream_position()?;
    reader.read_exact(slice_over_s)?;
    reader.seek(io::SeekFrom::Start(pos))?;

    Ok(unsafe { s.assume_init() })
}

/// Read a `T` from the cursor.
pub fn read_struct<T>(reader: &mut impl Reader) -> Result<T> {
    let s = peek_struct(reader)?;
    let size_of_s = mem::size_of_val(&s);

    reader.seek(io::SeekFrom::Current(size_of_s.try_into().unwrap()))?;

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
