// Axel '0vercl0k' Souchet - March 17 2024
use std::collections::HashSet;
use std::fs::File;
use std::io::{Cursor, Read, SeekFrom};
use std::ops::Range;
use std::path::PathBuf;
use std::sync::LazyLock;
use std::{env, fs};

use kdmp_parser::error::{Error, PageReadError, PxeKind};
use kdmp_parser::gxa::{Gpa, Gva};
use kdmp_parser::parse::KernelDumpParser;
use kdmp_parser::structs::{
    BMPHEADER64_EXPECTED_SIGNATURE, BMPHEADER64_EXPECTED_VALID_DUMP, BmpHeader64, DumpType,
    Header64, KernelRdmpHeader64, PageKind, PfnRange, PhysmemDesc, PhysmemRun, Pod,
    RDMP_HEADER64_EXPECTED_MARKER, RDMP_HEADER64_EXPECTED_SIGNATURE,
    RDMP_HEADER64_EXPECTED_VALID_DUMP, RdmpHeader64,
};
use kdmp_parser::{phys, virt};
use serde::Deserialize;

/// Convert an hexadecimal encoded integer string into a `u64`.
#[must_use]
fn hex_str(s: &str) -> u64 {
    u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap()
}

#[derive(Debug, Deserialize)]
struct M {
    name: String,
    start: String,
    end: String,
}

#[derive(Debug)]
struct Module {
    name: String,
    at: Range<Gva>,
}

impl From<M> for Module {
    fn from(value: M) -> Self {
        Self {
            name: value.name,
            at: hex_str(&value.start).into()..hex_str(&value.end).into(),
        }
    }
}

struct TestcaseValues<'test> {
    file: PathBuf,
    dump_type: DumpType,
    size: u64,
    phys_addr: u64,
    phys_bytes: [u8; 16],
    virt_addr: u64,
    virt_bytes: [u8; 16],
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    rip: u64,
    rsp: u64,
    rbp: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    modules: &'test [Module],
}

fn compare_modules(parser: &KernelDumpParser, modules: &[Module]) -> bool {
    let parser_modules = parser.user_modules().chain(parser.kernel_modules());
    let mut seen = HashSet::new();
    for (r, name) in parser_modules {
        if seen.contains(&r.start) {
            eprintln!("already seen {}", r.start);
            return false;
        }

        let found_mod = modules.iter().find(|m| m.at == *r).unwrap();
        seen.insert(r.start);

        let filename = name.rsplit_once('\\').map_or(name, |(_, s)| s);
        if filename.to_lowercase() != found_mod.name.to_lowercase() {
            if found_mod.name == "nt" && filename == "ntoskrnl.exe" {
                continue;
            }

            eprintln!("name: {name} filename: {filename} found_mod: {found_mod:#x?}");
            return false;
        }
    }

    seen.len() == modules.len()
}

static BASE_PATH: LazyLock<PathBuf> = LazyLock::new(|| {
    PathBuf::from(env::var("TESTDATAS").expect("I need the TESTDATAS env var to work"))
});

static TEST_DIR: LazyLock<PathBuf> =
    LazyLock::new(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests"));

// Extract the info with WinDbg w/ the below:
// ```
// dx -r2 @$curprocess.Modules.Select(p => new {start=p.BaseAddress, end=p.BaseAddress + p.Size, name=p.Name})
// ```
static BMP_PATH: LazyLock<PathBuf> = LazyLock::new(|| BASE_PATH.join("bmp.dmp"));

static FULL_PATH: LazyLock<PathBuf> = LazyLock::new(|| BASE_PATH.join("full.dmp"));

static KERNEL_DUMP_PATH: LazyLock<PathBuf> = LazyLock::new(|| BASE_PATH.join("kerneldump.dmp"));

static KERNEL_USER_DUMP_PATH: LazyLock<PathBuf> =
    LazyLock::new(|| BASE_PATH.join("kerneluserdump.dmp"));

static COMPLETE_DUMP_PATH: LazyLock<PathBuf> = LazyLock::new(|| BASE_PATH.join("completedump.dmp"));

static LIVE_KERNEL_PATH: LazyLock<PathBuf> =
    LazyLock::new(|| BASE_PATH.join("fulllivekernelmemory.dmp"));

static WOW64_DUMP_PATH: LazyLock<PathBuf> =
    LazyLock::new(|| BASE_PATH.join("wow64_kernelactive.dmp"));

#[expect(clippy::too_many_lines)]
#[test]
fn regressions() {
    let modules_1: Vec<M> =
        serde_json::from_reader(File::open(TEST_DIR.join("modules_1.json")).unwrap()).unwrap();
    let modules_1 = modules_1
        .into_iter()
        .map(Into::into)
        .collect::<Vec<Module>>();
    // kd> r
    // rax=0000000000000003 rbx=fffff8050f4e9f70 rcx=0000000000000001
    // rdx=fffff805135684d0 rsi=0000000000000100 rdi=fffff8050f4e9f80
    // rip=fffff805108776a0 rsp=fffff805135684f8 rbp=fffff80513568600
    // r8=0000000000000003  r9=fffff805135684b8 r10=0000000000000000
    // r11=ffffa8848825e000 r12=fffff8050f4e9f80 r13=fffff80510c3c958
    // r14=0000000000000000 r15=0000000000000052
    // iopl=0         nv up ei pl nz na pe nc
    // cs=0010  ss=0018  ds=002b  es=002b  fs=0053  gs=002b efl=00040202
    let bmp = TestcaseValues {
        file: BMP_PATH.to_path_buf(),
        dump_type: DumpType::Bmp,
        size: 0x54_4b,
        phys_addr: 0x6d_4d_22,
        phys_bytes: [
            0x6d, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x63, 0x88, 0x75, 0x00, 0x00, 0x00, 0x00, 0x0a,
            0x63, 0x98,
        ],
        virt_addr: 0xffff_f805_1087_76a0,
        virt_bytes: [
            0xcc, 0xc3, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ],
        rax: 0x0000_0000_0000_0003,
        rbx: 0xffff_f805_0f4e_9f70,
        rcx: 0x0000_0000_0000_0001,
        rdx: 0xffff_f805_1356_84d0,
        rsi: 0x0000_0000_0000_0100,
        rdi: 0xffff_f805_0f4e_9f80,
        rip: 0xffff_f805_1087_76a0,
        rsp: 0xffff_f805_1356_84f8,
        rbp: 0xffff_f805_1356_8600,
        r8: 0x0000_0000_0000_0003,
        r9: 0xffff_f805_1356_84b8,
        r10: 0x0000_0000_0000_0000,
        r11: 0xffff_a884_8825_e000,
        r12: 0xffff_f805_0f4e_9f80,
        r13: 0xffff_f805_10c3_c958,
        r14: 0x0000_0000_0000_0000,
        r15: 0x0000_0000_0000_0052,
        modules: modules_1.as_slice(),
    };

    let full = TestcaseValues {
        file: FULL_PATH.to_path_buf(),
        dump_type: DumpType::Full,
        size: 0x03_fb_e6,
        phys_addr: 0x6d_4d_22,
        phys_bytes: [
            0x6d, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x63, 0x88, 0x75, 0x00, 0x00, 0x00, 0x00, 0x0a,
            0x63, 0x98,
        ],
        virt_addr: 0xffff_f805_1087_76a0,
        virt_bytes: [
            0xcc, 0xc3, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ],
        rax: 0x0000_0000_0000_0003,
        rbx: 0xffff_f805_0f4e_9f70,
        rcx: 0x0000_0000_0000_0001,
        rdx: 0xffff_f805_1356_84d0,
        rsi: 0x0000_0000_0000_0100,
        rdi: 0xffff_f805_0f4e_9f80,
        rip: 0xffff_f805_1087_76a0,
        rsp: 0xffff_f805_1356_84f8,
        rbp: 0xffff_f805_1356_8600,
        r8: 0x0000_0000_0000_0003,
        r9: 0xffff_f805_1356_84b8,
        r10: 0x0000_0000_0000_0000,
        r11: 0xffff_a884_8825_e000,
        r12: 0xffff_f805_0f4e_9f80,
        r13: 0xffff_f805_10c3_c958,
        r14: 0x0000_0000_0000_0000,
        r15: 0x0000_0000_0000_0052,
        modules: &modules_1,
    };

    let modules_2: Vec<M> =
        serde_json::from_reader(File::open(TEST_DIR.join("modules_2.json")).unwrap()).unwrap();
    let modules_2 = modules_2
        .into_iter()
        .map(Into::into)
        .collect::<Vec<Module>>();

    let kernel_dump = TestcaseValues {
        file: KERNEL_DUMP_PATH.to_path_buf(),
        dump_type: DumpType::KernelMemory,
        size: 0xa0_2e,
        phys_addr: 0x0258_92f0,
        phys_bytes: [
            0x10, 0x8c, 0x24, 0x50, 0x0c, 0xc0, 0xff, 0xff, 0xa0, 0x19, 0x38, 0x51, 0x0c, 0xc0,
            0xff, 0xff,
        ],
        virt_addr: 0xffff_f803_f2c3_5470,
        virt_bytes: [
            0xcc, 0xc3, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ],
        rax: 0x0000_0000_0000_7a01,
        rbx: 0xffff_c00c_5191_e010,
        rcx: 0x0000_0000_0000_0001,
        rdx: 0x0000_0012_0000_0000,
        rsi: 0xffff_c00c_5190_7bb0,
        rdi: 0x0000_0000_0000_0002,
        rip: 0xffff_f803_f2c3_5470,
        rsp: 0xffff_f803_f515_ec28,
        rbp: 0x0000_0000_0c1c_9800,
        r8: 0x0000_0000_0000_00b0,
        r9: 0xffff_c00c_502f_f000,
        r10: 0x0000_0000_0000_0057,
        r11: 0xffff_f803_f3a0_4500,
        r12: 0xffff_f803_f515_ee60,
        r13: 0x0000_0000_0000_0003,
        r14: 0xffff_f803_f1e9_a180,
        r15: 0x0000_0000_0000_001f,
        modules: &modules_2,
    };

    let modules_3: Vec<M> =
        serde_json::from_reader(File::open(TEST_DIR.join("modules_3.json")).unwrap()).unwrap();
    let modules_3 = modules_3
        .into_iter()
        .map(Into::into)
        .collect::<Vec<Module>>();

    let kernel_user_dump = TestcaseValues {
        file: KERNEL_USER_DUMP_PATH.to_path_buf(),
        dump_type: DumpType::KernelAndUserMemory,
        size: 0x01_f7_c7,
        phys_addr: 0x0258_92f0,
        phys_bytes: [
            0x10, 0x8c, 0x24, 0x50, 0x0c, 0xc0, 0xff, 0xff, 0xa0, 0x19, 0x38, 0x51, 0x0c, 0xc0,
            0xff, 0xff,
        ],
        virt_addr: 0xffff_f803_f2c3_5470,
        virt_bytes: [
            0xcc, 0xc3, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ],
        rax: 0x0000_0000_0000_7a01,
        rbx: 0xffff_c00c_5191_e010,
        rcx: 0x0000_0000_0000_0001,
        rdx: 0x0000_0012_0000_0000,
        rsi: 0xffff_c00c_5190_7bb0,
        rdi: 0x0000_0000_0000_0002,
        rip: 0xffff_f803_f2c3_5470,
        rsp: 0xffff_f803_f515_ec28,
        rbp: 0x0000_0000_0c1c_9800,
        r8: 0x0000_0000_0000_00b0,
        r9: 0xffff_c00c_502f_f000,
        r10: 0x0000_0000_0000_0057,
        r11: 0xffff_f803_f3a0_4500,
        r12: 0xffff_f803_f515_ee60,
        r13: 0x0000_0000_0000_0003,
        r14: 0xffff_f803_f1e9_a180,
        r15: 0x0000_0000_0000_001f,
        modules: &modules_3,
    };

    let complete_dump = TestcaseValues {
        file: COMPLETE_DUMP_PATH.to_path_buf(),
        dump_type: DumpType::CompleteMemory,
        size: 0x01_fb_f9,
        phys_addr: 0x0258_92f0,
        phys_bytes: [
            0x10, 0x8c, 0x24, 0x50, 0x0c, 0xc0, 0xff, 0xff, 0xa0, 0x19, 0x38, 0x51, 0x0c, 0xc0,
            0xff, 0xff,
        ],
        virt_addr: 0xffff_f803_f2c3_5470,
        virt_bytes: [
            0xcc, 0xc3, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ],
        rax: 0x0000_0000_0000_7a01,
        rbx: 0xffff_c00c_5191_e010,
        rcx: 0x0000_0000_0000_0001,
        rdx: 0x0000_0012_0000_0000,
        rsi: 0xffff_c00c_5190_7bb0,
        rdi: 0x0000_0000_0000_0002,
        rip: 0xffff_f803_f2c3_5470,
        rsp: 0xffff_f803_f515_ec28,
        rbp: 0x0000_0000_0c1c_9800,
        r8: 0x0000_0000_0000_00b0,
        r9: 0xffff_c00c_502f_f000,
        r10: 0x0000_0000_0000_0057,
        r11: 0xffff_f803_f3a0_4500,
        r12: 0xffff_f803_f515_ee60,
        r13: 0x0000_0000_0000_0003,
        r14: 0xffff_f803_f1e9_a180,
        r15: 0x0000_0000_0000_001f,
        modules: &modules_3,
    };

    let modules_4: Vec<M> =
        serde_json::from_reader(File::open(TEST_DIR.join("modules_4.json")).unwrap()).unwrap();
    let modules_4 = modules_4
        .into_iter()
        .map(Into::into)
        .collect::<Vec<Module>>();

    let live_kernel = TestcaseValues {
        file: LIVE_KERNEL_PATH.to_path_buf(),
        dump_type: DumpType::LiveKernelMemory,
        size: 0x01_54_f5,
        phys_addr: 0xd96a_9000,
        phys_bytes: [
            0x67, 0xd8, 0xb6, 0xdd, 0x00, 0x00, 0x00, 0x0a, 0x67, 0xa8, 0x1d, 0xd6, 0x00, 0x00,
            0x00, 0x0a,
        ],
        virt_addr: 0xffff_f807_50a9_8b6d,
        virt_bytes: [
            0x48, 0x8d, 0x8f, 0x00, 0x01, 0x00, 0x00, 0xe8, 0x17, 0x2a, 0x98, 0xff, 0x48, 0x81,
            0xc3, 0x48,
        ],
        rax: 0x0000_0000_0000_0004,
        rbx: 0xffff_d20f_d855_3000,
        rcx: 0xffff_a100_0ed8_4a00,
        rdx: 0x0000_0000_0000_0000,
        rsi: 0xffff_d20f_d3be_eae0,
        rdi: 0xffff_f807_4fb4_b180,
        rip: 0xffff_f807_50a9_8b6d,
        rsp: 0xffff_fd8d_6bca_ed10,
        rbp: 0x0000_0000_0000_0000,
        r8: 0x0000_0000_0000_0b80,
        r9: 0xffff_d20f_d855_3348,
        r10: 0x0000_0000_0000_0000,
        r11: 0xffff_d20f_d855_3000,
        r12: 0x0000_0000_0000_0002,
        r13: 0x0000_0000_0000_0000,
        r14: 0xffff_d20f_d48d_5080,
        r15: 0x0000_0000_0000_0001,
        modules: &modules_4,
    };

    let modules_5: Vec<M> =
        serde_json::from_reader(File::open(TEST_DIR.join("modules_5.json")).unwrap()).unwrap();
    let modules_5 = modules_5
        .into_iter()
        .map(Into::into)
        .collect::<Vec<Module>>();

    let wow64 = TestcaseValues {
        file: WOW64_DUMP_PATH.to_path_buf(),
        dump_type: DumpType::KernelAndUserMemory,
        size: 0x03_ec_ff,
        phys_addr: 0x0623_5000,
        phys_bytes: [
            0xcc, 0x33, 0xc0, 0xc3, 0x3b, 0x0d, 0x00, 0x50, 0x46, 0x00, 0x75, 0x01, 0xc3, 0xe9,
            0x79, 0x02,
        ],
        virt_addr: 0x0045_1000,
        virt_bytes: [
            0xcc, 0x33, 0xc0, 0xc3, 0x3b, 0x0d, 0x00, 0x50, 0x46, 0x00, 0x75, 0x01, 0xc3, 0xe9,
            0x79, 0x02,
        ],
        rax: 0x0046_5e58,
        rbx: 0x0062_d000,
        rcx: 0x0000_0000,
        rdx: 0x420e_1d36,
        rsi: 0x009e_f4c0,
        rdi: 0x009f_0d30,
        rip: 0x0045_1000,
        rsp: 0x0056_fbcc,
        rbp: 0x0056_fc10,
        r8: 0x0000_002b,
        r9: 0x77cb_2c0c,
        r10: 0x0000_0000,
        r11: 0x0038_e450,
        r12: 0x0062_e000,
        r13: 0x0038_fda0,
        r14: 0x0038_ed40,
        r15: 0x77c3_4660,
        modules: &modules_5,
    };

    let tests = [
        &bmp,
        &full,
        &kernel_dump,
        &kernel_user_dump,
        &complete_dump,
        &live_kernel,
        &wow64,
    ];

    for test in tests {
        let parser = KernelDumpParser::new(&test.file).unwrap();
        let virt_reader = virt::Reader::new(&parser);
        let phys_reader = phys::Reader::new(&parser);
        eprintln!("{parser:?}");
        assert_eq!(parser.dump_type(), test.dump_type);
        assert_eq!(parser.gpas().len(), usize::try_from(test.size).unwrap());
        let mut buf = [0; 16];
        phys_reader
            .read_exact(Gpa::new(test.phys_addr), &mut buf)
            .unwrap();
        assert_eq!(buf, test.phys_bytes);
        virt_reader
            .read_exact(Gva::new(test.virt_addr), &mut buf)
            .unwrap();
        assert_eq!(buf, test.virt_bytes);
        let ctx = parser.context_record();
        assert_eq!(ctx.rax, test.rax);
        assert_eq!(ctx.rbx, test.rbx);
        assert_eq!(ctx.rcx, test.rcx);
        assert_eq!(ctx.rdx, test.rdx);
        assert_eq!(ctx.rsi, test.rsi);
        assert_eq!(ctx.rdi, test.rdi);
        assert_eq!(ctx.rip, test.rip);
        assert_eq!(ctx.rsp, test.rsp);
        assert_eq!(ctx.rbp, test.rbp);
        assert_eq!(ctx.r8, test.r8);
        assert_eq!(ctx.r9, test.r9);
        assert_eq!(ctx.r10, test.r10);
        assert_eq!(ctx.r11, test.r11);
        assert_eq!(ctx.r12, test.r12);
        assert_eq!(ctx.r13, test.r13);
        assert_eq!(ctx.r14, test.r14);
        assert_eq!(ctx.r15, test.r15);
        assert!(compare_modules(&parser, test.modules));
    }
}

#[test]
fn transition_pte() {
    // Example of a transition PTE readable by WinDbg (in kerneluserdump.dmp):
    // ```text
    // kd> db 0x1a42ea30240 l10
    // 000001a4`2ea30240  e0 07 a3 2e a4 01 00 00-80 f2 a2 2e a4 01 00 00  ................
    // kd> !pte 0x1a42ea30240
    //                                            VA 000001a42ea30240
    // PXE at FFFFECF67B3D9018    PPE at FFFFECF67B203480    PDE at FFFFECF640690BA8    PTE at FFFFEC80D2175180
    // contains 0A0000000ECC0867  contains 0A00000013341867  contains 0A000000077AF867  contains 00000000166B7880
    // pfn ecc0      ---DA--UWEV  pfn 13341     ---DA--UWEV  pfn 77af      ---DA--UWEV  not valid
    //                                                                                  Transition: 166b7
    //                                                                                  Protect: 4 - ReadWrite
    // ```
    let parser = KernelDumpParser::new(KERNEL_USER_DUMP_PATH.as_path()).unwrap();
    let reader = virt::Reader::new(&parser);
    let mut buffer = [0; 16];
    let expected_buffer = [
        0xe0, 0x07, 0xa3, 0x2e, 0xa4, 0x01, 0x00, 0x00, 0x80, 0xf2, 0xa2, 0x2e, 0xa4, 0x01, 0x00,
        0x00,
    ];
    assert!(
        reader
            .read(0x01a4_2ea3_0240.into(), &mut buffer)
            .inspect_err(|e| eprintln!("{e:?}"))
            .is_ok()
    );
    assert_eq!(buffer, expected_buffer);
}

#[test]
fn valid_pte_no_backing() {
    // Examples of a valid PTE that don't have a physical page backing it (in
    // kerneldump.dmp):
    // ```text
    // kd> !pte 0x1a42ea30240
    //     VA 000001a42ea30240
    // PXE at FFFFECF67B3D9018    PPE at FFFFECF67B203480    PDE at FFFFECF640690BA8    PTE at FFFFEC80D2175180
    // contains 0A0000000ECC0867  contains 0A00000013341867  contains 0A000000077AF867  contains 00000000166B7880
    // pfn ecc0      ---DA--UWEV  pfn 13341     ---DA--UWEV  pfn 77af      ---DA--UWEV  not valid
    //                                                                                  Transition: 166b7
    //                                                                                  Protect: 4 - ReadWrite
    // kd> !db 166b7240
    // Physical memory read at 166b7240 failed
    // ```
    //
    // ```text
    // kd> !pte 0x16e23fa060
    //     VA 00000016e23fa060
    // PXE at FFFFECF67B3D9000    PPE at FFFFECF67B2002D8    PDE at FFFFECF64005B888    PTE at FFFFEC800B711FD0
    // contains 0A00000001FEB867  contains 0A00000019A08867  contains 0A00000019A07867  contains 8000000001BC4867
    // pfn 1feb      ---DA--UWEV  pfn 19a08     ---DA--UWEV  pfn 19a07     ---DA--UWEV  pfn 1bc4      ---DA--UW-V
    // kd> !db 1bc4000
    // Physical memory read at 1bc4000 failed
    // ```
    let parser = KernelDumpParser::new(KERNEL_DUMP_PATH.as_path()).unwrap();
    let virt_reader = virt::Reader::new(&parser);
    let mut buffer = [0];
    assert!(matches!(
        virt_reader
            .read(0x01a4_2ea3_0240.into(), &mut buffer)
            .inspect_err(|e| eprintln!("{e:?}")),
        Ok(0)
    ));

    assert!(matches!(
        virt_reader.read_exact(0x01a4_2ea3_0240.into(), &mut buffer).inspect_err(|e| eprintln!("{e:?}")),
            Err(Error::PartialRead { reason: PageReadError::NotInDump { gva: Some((gva, None)), gpa }, ..}
        ) if gpa == 0x166b_7240.into() && gva == 0x01a4_2ea3_0240.into()
    ));

    assert!(matches!(
        virt_reader
            .try_read_exact(0x01a4_2ea3_0240.into(), &mut buffer)
            .inspect_err(|e| eprintln!("{e:?}")),
        Ok(None)
    ));

    let phys_reader = phys::Reader::new(&parser);
    assert!(matches!(
        phys_reader
            .read(Gpa::new(0x166b_7240), &mut buffer)
            .inspect_err(|e| eprintln!("{e:?}")),
        Ok(0)
    ));

    assert!(matches!(
        phys_reader.read_exact(Gpa::new(0x166b_7240), &mut buffer).inspect_err(|e| eprintln!("{e:?}")),
        Err(Error::PartialRead { reason: PageReadError::NotInDump { gva: None, gpa }, ..
        }) if gpa == 0x166b_7240.into()
    ));

    assert!(matches!(
        virt_reader.read_exact(0x0016_e23f_a060.into(), &mut buffer).inspect_err(|e| eprintln!("{e:?}")),
        Err(Error::PartialRead { reason: PageReadError::NotInDump { gva: Some((gva, None)), gpa }, ..}
        ) if gpa == 0x01bc_4060.into() && gva == 0x0016_e23f_a060.into()
    ));

    assert!(matches!(
        virt_reader
            .try_read_exact(0x0016_e23f_a060.into(), &mut buffer)
            .inspect_err(|e| eprintln!("{e:?}")),
        Ok(None)
    ));
}

#[test]
fn bug_10() {
    // BUG: https://github.com/0vercl0k/kdmp-parser-rs/issues/10
    // When reading the end of a virtual memory page that has no available
    // memory behind, there was an issue in the virtual read algorithm. The
    // first time the loop ran, it reads as much as it could and if the user
    // wanted more, then the loop runs a second time to virt translate the next
    // page. However, because there is nothing mapped the virtual to physical
    // translation fails & bails (because of `?`) which suggests to the user
    // that the read operation completely failed when it was in fact able to
    // read some amount of bytes.
    //
    // ```text
    // kd> db 00007ff7`ab766ff7
    // 00007ff7`ab766ff7  00 00 00 00 00 00 00 00-00 ?? ?? ?? ?? ?? ?? ??  .........???????
    // ```
    //
    // ```text
    // kdmp-parser-rs>cargo r --example parser -- mem.dmp --mem 00007ff7`ab766ff7 --virt --len 10
    //     Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.09s
    //      Running `target\debug\examples\parser.exe mem.dmp --mem 00007ff7`ab766ff7 --virt --len 10`
    // There is no virtual memory available at 0x7ff7ab766ff7
    // ```
    //
    // The below address mirrors the same behavior than in the issue's dump:
    //
    // ```text
    // kd> db fffff803`f3086fef
    // fffff803`f3086fef  9d f5 de ff 48 85 c0 74-0a 40 8a cf e8 80 ee ba  ....H..t.@......
    // fffff803`f3086fff  ff ?? ?? ?? ?? ?? ?? ??-?? ?? ?? ?? ?? ?? ?? ??  .???????????????
    // fffff803`f308700f  ?? ?? ?? ?? ?? ?? ?? ??-?? ?? ?? ?? ?? ?? ?? ??  ????????????????
    // ```
    let parser = KernelDumpParser::new(KERNEL_DUMP_PATH.as_path()).unwrap();
    let virt_reader = virt::Reader::new(&parser);

    let mut buffer = [0; 32];
    assert!(matches!(
        virt_reader
            .read_exact(0xffff_f803_f308_6fef.into(), &mut buffer)
            .inspect_err(|e| eprintln!("{e:?}")),
        Err(
            Error::PartialRead {
            expected_amount: 32,
            actual_amount: 17,
            reason: PageReadError::NotPresent { gva, which_pxe }
        }) if gva == 0xffff_f803_f308_7000.into() && which_pxe == PxeKind::Pte,
    ));

    assert!(matches!(
        virt_reader
            .read(0xffff_f803_f308_6fef.into(), &mut buffer)
            .inspect_err(|e| eprintln!("{e:?}")),
        Ok(17)
    ));

    // ```text
    // kd> !process 0 0
    // PROCESS ffffc00c5120d580
    //     SessionId: 1  Cid: 0d24    Peb: 3a8dcfb000  ParentCid: 02b4
    //     DirBase: 0ea00002  ObjectTable: ffffd106e2336a80  HandleCount: 201.
    //     Image: RuntimeBroker.exe
    // kd> .process /p ffffc00c5120d580; !peb 3a8dcfb000
    // kd> db 0x15cc6603908
    // 0000015c`c6603908  43 00 3a 00 5c 00 57 00-69 00 6e 00 64 00 6f 00  C.:.\.W.i.n.d.o.
    // 0000015c`c6603918  77 00 73 00 5c 00 53 00-79 00 73 00 74 00 65 00  w.s.\.S.y.s.t.e.
    // 0000015c`c6603928  6d 00 33 00 32 00 5c 00-52 00 75 00 6e 00 74 00  m.3.2.\.R.u.n.t.
    // 0000015c`c6603938  69 00 6d 00 65 00 42 00-72 00 6f 00 6b 00 65 00  i.m.e.B.r.o.k.e.
    // ```
    let parser = KernelDumpParser::new(COMPLETE_DUMP_PATH.as_path()).unwrap();
    let virt_reader = virt::Reader::with_dtb(&parser, 0x0ea0_0002.into());
    let mut buffer = [0; 64];
    virt_reader
        .read_exact(0x015c_c660_3908.into(), &mut buffer)
        .unwrap();

    assert_eq!(buffer, [
        0x43, 0x00, 0x3a, 0x00, 0x5c, 0x00, 0x57, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x64, 0x00, 0x6f,
        0x00, 0x77, 0x00, 0x73, 0x00, 0x5c, 0x00, 0x53, 0x00, 0x79, 0x00, 0x73, 0x00, 0x74, 0x00,
        0x65, 0x00, 0x6d, 0x00, 0x33, 0x00, 0x32, 0x00, 0x5c, 0x00, 0x52, 0x00, 0x75, 0x00, 0x6e,
        0x00, 0x74, 0x00, 0x69, 0x00, 0x6d, 0x00, 0x65, 0x00, 0x42, 0x00, 0x72, 0x00, 0x6f, 0x00,
        0x6b, 0x00, 0x65, 0x00
    ]);
}

#[test]
fn large_page() {
    // Read from the middle of a large page.
    //
    // ```text
    // 32.1: kd> !pte nt
    //                                            VA fffff80122800000
    // PXE at FFFFF5FAFD7EBF80    PPE at FFFFF5FAFD7F0020    PDE at FFFFF5FAFE0048A0    PTE at FFFFF5FC00914000
    // contains 0000000002709063  contains 000000000270A063  contains 8A000000048001A1  contains 0000000000000000
    // pfn 2709      ---DA--KWEV  pfn 270a      ---DA--KWEV  pfn 4800      -GL-A--KR-V  LARGE PAGE pfn 4800
    // ```
    let parser = KernelDumpParser::new(WOW64_DUMP_PATH.as_path()).unwrap();
    let virt_reader = virt::Reader::new(&parser);
    let tr = virt_reader.translate(0xffff_f801_2280_0000.into()).unwrap();
    assert!(matches!(tr.page_kind, PageKind::Large));
    assert!(matches!(tr.pfn.u64(), 0x48_00));
    let mut buffer = [0; 0x10];
    // ```text
    // 32.1: kd> db 0xfffff80122800000 + 0x100000 - 8
    // 002b:fffff801`228ffff8  70 72 05 00 04 3a 65 00-54 3a 65 00 bc 82 0c 00  pr...:e.T:e.....
    // ```
    virt_reader
        .read_exact(
            Gva::new(0xffff_f801_2280_0000 + 0x10_00_00 - 8),
            &mut buffer,
        )
        .unwrap();

    assert_eq!(buffer, [
        0x70, 0x72, 0x05, 0x00, 0x04, 0x3a, 0x65, 0x00, 0x54, 0x3a, 0x65, 0x00, 0xbc, 0x82, 0x0c,
        0x00
    ]);

    // Read from two straddling large pages.
    //
    // ```text
    // 32.1: kd> !pte 0xfffff80122800000 + 0x200000 - 0x8
    //                                            VA fffff801229ffff8
    // PXE at FFFFF5FAFD7EBF80    PPE at FFFFF5FAFD7F0020    PDE at FFFFF5FAFE0048A0    PTE at FFFFF5FC00914FF8
    // contains 0000000002709063  contains 000000000270A063  contains 8A000000048001A1  contains 0000000000000000
    // pfn 2709      ---DA--KWEV  pfn 270a      ---DA--KWEV  pfn 4800      -GL-A--KR-V  LARGE PAGE pfn 49ff
    //
    // 32.1: kd> !pte 0xfffff80122800000 + 0x200000
    //                                            VA fffff80122a00000
    // PXE at FFFFF5FAFD7EBF80    PPE at FFFFF5FAFD7F0020    PDE at FFFFF5FAFE0048A8    PTE at FFFFF5FC00915000
    // contains 0000000002709063  contains 000000000270A063  contains 0A00000004A001A1  contains 0000000000000000
    // pfn 2709      ---DA--KWEV  pfn 270a      ---DA--KWEV  pfn 4a00      -GL-A--KREV  LARGE PAGE pfn 4a00
    // 32.1: kd> db 0xfffff80122800000 + 0x200000 - 0x8
    // 002b:fffff801`229ffff8  63 00 72 00 6f 00 73 00-cc cc cc cc cc cc cc cc  c.r.o.s.........
    // ```
    let mut buffer = [0; 0x10];
    virt_reader
        .read_exact(
            Gva::new(0xffff_f801_2280_0000 + 0x20_00_00 - 0x8),
            &mut buffer,
        )
        .unwrap();

    assert_eq!(buffer, [
        0x63, 0x00, 0x72, 0x00, 0x6f, 0x00, 0x73, 0x00, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
        0xcc
    ]);

    // This is `@rsp` / stack memory.
    //
    // ```text
    // 32.1: kd> !pte 0x56fbcc
    //                                            VA 000000000056fbcc
    // PXE at FFFFF5FAFD7EB000    PPE at FFFFF5FAFD600000    PDE at FFFFF5FAC0000010    PTE at FFFFF58000002B78
    // contains 0A0000005DC78867  contains 0A0000005DC79867  contains 0A0000005DC7A867  contains 81000000625D5867
    // pfn 5dc78     ---DA--UWEV  pfn 5dc79     ---DA--UWEV  pfn 5dc7a     ---DA--UWEV  pfn 625d5     ---DA--UW-V
    // ```
    let tr = virt_reader.translate(0x56_fb_cc.into()).unwrap();
    assert!(tr.writable);
    assert!(!tr.executable);
    assert!(tr.user_accessible);

    // This is `@rip` / executable memory
    //
    // ```text
    // 32.1: kd> !pte 0000000000451000
    //                                            VA 0000000000451000
    // PXE at FFFFF5FAFD7EB000    PPE at FFFFF5FAFD600000    PDE at FFFFF5FAC0000010    PTE at FFFFF58000002288
    // contains 0A0000005DC78867  contains 0A0000005DC79867  contains 0A0000005DC7A867  contains 0100000006235025
    // pfn 5dc78     ---DA--UWEV  pfn 5dc79     ---DA--UWEV  pfn 5dc7a     ---DA--UWEV  pfn 6235      ----A--UREV
    // ```
    let tr = virt_reader.translate(0x45_10_00.into()).unwrap();
    assert!(!tr.writable);
    assert!(tr.executable);
    assert!(tr.user_accessible);

    // This is `nt!NtCreateProcess` in a large page of nt.
    //
    // ```text
    // 32.1: kd> !pte fffff801`23103ba0
    //                                         VA fffff80123103ba0
    // PXE at FFFFF5FAFD7EBF80    PPE at FFFFF5FAFD7F0020    PDE at FFFFF5FAFE0048C0    PTE at FFFFF5FC00918818
    // contains 0000000002709063  contains 000000000270A063  contains 0A000000050001A1  contains 0000000000000000
    // pfn 2709      ---DA--KWEV  pfn 270a      ---DA--KWEV  pfn 5000      -GL-A--KREV  LARGE PAGE pfn 5103
    // ```
    let tr = virt_reader.translate(0xffff_f801_2310_3ba0.into()).unwrap();
    assert!(!tr.writable);
    assert!(tr.executable);
    assert!(!tr.user_accessible);

    // This is kernel stack.
    //
    // ```text
    // 32.1: kd> !pte ffffa587dcc2f650
    //                                            VA ffffa587dcc2f650
    // PXE at FFFFF5FAFD7EBA58    PPE at FFFFF5FAFD74B0F8    PDE at FFFFF5FAE961F730    PTE at FFFFF5D2C3EE6178
    // contains 0A00000104B61863  contains 0A00000104B62863  contains 0A000000EA030863  contains 8A000000408FF963
    // pfn 104b61    ---DA--KWEV  pfn 104b62    ---DA--KWEV  pfn ea030     ---DA--KWEV  pfn 408ff     -G-DA--KW-V
    // ```
    let tr = virt_reader.translate(0xffff_a587_dcc2_f650.into()).unwrap();
    assert!(tr.writable);
    assert!(!tr.executable);
    assert!(!tr.user_accessible);

    // This is unaccessible memory.
    //
    // ```text
    // 32.1: kd> !pte 0
    //                                            VA 0000000000000000
    // PXE at FFFFF5FAFD7EB000    PPE at FFFFF5FAFD600000    PDE at FFFFF5FAC0000000    PTE at FFFFF58000000000
    // contains 0A0000005DC78867  contains 0A0000005DC79867  contains 0000000000000000
    // pfn 5dc78     ---DA--UWEV  pfn 5dc79     ---DA--UWEV  contains 0000000000000000
    // not valid
    // ```
    //
    // ```text
    // 32.1: kd> !pte ffffffffffffffff
    //                                            VA ffffffffffffffff
    // PXE at FFFFF5FAFD7EBFF8    PPE at FFFFF5FAFD7FFFF8    PDE at FFFFF5FAFFFFFFF8    PTE at FFFFF5FFFFFFFFF8
    // contains 0000000002725063  contains 0000000002726063  contains 0000000002728063  contains 0000FFFFFFFFF000
    // pfn 2725      ---DA--KWEV  pfn 2726      ---DA--KWEV  pfn 2728      ---DA--KWEV  not valid
    //                                                                                   Page has been freed
    // ```
    let gva = 0.into();
    assert!(matches!(
        virt_reader.translate(gva),
        Err(Error::PageRead(
            PageReadError::NotPresent { gva: fault_gva, which_pxe: PxeKind::Pde }
        )) if fault_gva == gva
    ));

    let gva = 0xffff_ffff_ffff_ffff.into();
    assert!(matches!(
        virt_reader.translate(gva),
        Err(Error::PageRead(
            PageReadError::NotPresent { gva: fault_gva, which_pxe: PxeKind::Pte }
        )) if fault_gva == gva
    ));
}

#[test]
fn partial_phys() {
    let parser = KernelDumpParser::new(WOW64_DUMP_PATH.as_path()).unwrap();
    let phys_reader = phys::Reader::new(&parser);

    let mut buffer = [0; 0x11];
    // ```text
    // kd> !db 0x14ff0 l10
    // #   14ff0 00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00 ................
    // kd> !db 0x15000 l1
    // Physical memory read at 15000 failed
    // ```
    assert!(matches!(
        phys_reader.read(0x01_4f_f0.into(), &mut buffer),
        Ok(0x10)
    ));

    assert!(matches!(
        phys_reader.read_exact(0x01_4f_f0.into(), &mut buffer).inspect(|e| eprintln!("{e:?}")),
        Err(Error::PartialRead {
            expected_amount,
            actual_amount: 0x10,
            reason: PageReadError::NotInDump { gva: None, gpa }
        }) if expected_amount == buffer.len() && gpa == 0x01_50_00.into()
    ));

    // ```text
    // kd> !db 0000000000016000 - 10 l10
    // Physical memory read at 15ff0 failed
    // kd> !db 16000 l10
    // #   16000 00 04 04 03 50 6e 70 5a-00 00 00 00 00 00 00 00 ....PnpZ........
    // ```
    assert!(matches!(
        phys_reader.read(0x01_5f_f0.into(), &mut buffer),
        Ok(0)
    ));

    assert!(matches!(
        phys_reader.read_exact(0x01_5f_f0.into(), &mut buffer).inspect(|e| eprintln!("{e:?}")),
        Err(Error::PartialRead { reason: PageReadError::NotInDump { gva: None, gpa }, .. }) if gpa == 0x01_5f_f0.into()
    ));
}

fn pod_mut<T: Pod>(bytes: &mut [u8]) -> Option<&mut T> {
    if bytes.len() < size_of::<T>() {
        return None;
    }

    let ptr = bytes.as_mut_ptr().cast::<T>();

    if !ptr.is_aligned() {
        return None;
    }

    Some(unsafe { &mut *ptr })
}

/// Builds a dump from the [`Header64`] of a real dump, but change the dump type
/// and add a tail to that.
fn synthetic_dump(dump_type: DumpType, patch: impl Fn(&mut [u8]), tail: &[u8]) -> Vec<u8> {
    let mut f = File::open(BMP_PATH.as_path()).unwrap();
    let mut data = vec![0; size_of::<Header64>()];
    f.read_exact(&mut data).unwrap();

    pod_mut::<Header64>(&mut data).unwrap().dump_type = dump_type as u32;
    patch(&mut data);
    data.extend_from_slice(tail);

    data
}

/// Builds a one-range RDMP dump declaring `pages`, with one backed page
/// (PFN:0x1'000).
fn synthetic_rdmp_dump(dump_type: DumpType, pages: u64) -> Vec<u8> {
    #[repr(C)]
    struct Synthetic {
        hdr: RdmpHeader64,
        desc: PhysmemDesc,
        range: PfnRange,
    }

    unsafe impl Pod for Synthetic {}

    let mut data = vec![0u8; size_of::<Synthetic>()];
    let d = pod_mut::<Synthetic>(&mut data).unwrap();
    d.hdr.marker = RDMP_HEADER64_EXPECTED_MARKER;
    d.hdr.signature = RDMP_HEADER64_EXPECTED_SIGNATURE;
    d.hdr.valid_dump = RDMP_HEADER64_EXPECTED_VALID_DUMP;
    d.hdr.metadata_size = (size_of::<PhysmemDesc>() + size_of::<PfnRange>()) as u64;
    d.hdr.first_page_offset = (size_of::<Header64>() + size_of::<Synthetic>()) as u64;
    d.desc.number_of_runs = 1;
    d.desc.number_of_pages = pages;
    d.range.page_file_number = 1;
    d.range.number_of_pages = pages;

    // A single physical page (full of 0x41s) backing PFN:0x1'000.
    data.extend_from_slice(&[0x41; 0x1_000]);
    synthetic_dump(dump_type, |_| {}, &data)
}

#[test]
fn rdmp_range_table_does_not_include_page_data() {
    for dump_type in [
        DumpType::KernelMemory,
        DumpType::KernelAndUserMemory,
        DumpType::CompleteMemory,
    ] {
        let parser =
            KernelDumpParser::with_reader(Cursor::new(synthetic_rdmp_dump(dump_type, 1))).unwrap();
        assert_eq!(parser.gpas().collect::<Vec<_>>(), [Gpa::new(0x1_000)]);

        let mut buffer = [0; 0x1_000];
        phys::Reader::new(&parser)
            .read_exact(Gpa::new(0x1_000), &mut buffer)
            .unwrap();
        assert_eq!(buffer, [0x41; 0x1_000]);
    }
}

#[test]
fn rdmp_range_table_bounds_are_checked() {
    let mut truncated = synthetic_rdmp_dump(DumpType::KernelMemory, 1);
    truncated.truncate(
        size_of::<Header64>() + size_of::<KernelRdmpHeader64>() + size_of::<PfnRange>() - 1,
    );

    let mut unaligned = synthetic_rdmp_dump(DumpType::KernelMemory, 1);
    let h = pod_mut::<RdmpHeader64>(&mut unaligned[size_of::<Header64>()..]).unwrap();
    h.metadata_size += 1;
    h.first_page_offset += 1;

    for (data, expected) in [
        (
            truncated,
            "PFN range table extends past the end of the file",
        ),
        (
            unaligned,
            "PFN range table size is not a multiple of sizeof::<PfnRange>()",
        ),
    ] {
        let res = KernelDumpParser::with_reader(Cursor::new(data));
        assert!(
            matches!(res, Err(Error::InvalidData(e)) if e == expected),
            "expected {expected:?}, got {res:?}"
        );
    }
}

#[test]
fn header_counts_checked_against_file_length() {
    let bmp_header = |pages: u64, first_page: u64| {
        let mut data = vec![0; size_of::<BmpHeader64>()];
        let h = pod_mut::<BmpHeader64>(&mut data).unwrap();
        h.signature = BMPHEADER64_EXPECTED_SIGNATURE;
        h.valid_dump = BMPHEADER64_EXPECTED_VALID_DUMP;
        h.first_page = first_page;
        h.total_present_pages = pages;
        h.pages = pages;

        data
    };

    let cases = [
        // Full dump whose single run declares 2^36 pages.
        (
            synthetic_dump(
                DumpType::Full,
                |d| {
                    #[repr(C)]
                    struct Synthetic {
                        desc: PhysmemDesc,
                        run: PhysmemRun,
                    }

                    unsafe impl Pod for Synthetic {}

                    let h = pod_mut::<Header64>(d).unwrap();
                    let p = pod_mut::<Synthetic>(&mut h.physical_memory_block_buffer).unwrap();
                    p.desc.number_of_runs = 1;
                    p.desc.number_of_pages = 1 << 36;
                    p.run.base_page = 0;
                    p.run.page_count = 1 << 36;
                },
                &[0; 0x1_000],
            ),
            "run doesn't fit",
        ),
        // Bitmap dump marking 8M pages present with no page data behind it.
        (
            synthetic_dump(
                DumpType::Bmp,
                |_| {},
                &[bmp_header(8 << 20, 0x2_038 + (1 << 20)), vec![
                    0xff;
                    1 << 20
                ]]
                .concat(),
            ),
            "bitmap doesn't fit",
        ),
        // Bitmap dump declaring 2^40 pages in a short file.
        (
            synthetic_dump(
                DumpType::Bmp,
                |_| {},
                &[bmp_header(1 << 40, 0x3_000), vec![0xff; 0x1_000]].concat(),
            ),
            "bitmap extends past the end of the file",
        ),
        // Kernel dump with a range of 2^36 pages (but only one backed page).
        (
            synthetic_rdmp_dump(DumpType::KernelMemory, 1 << 36),
            "run doesn't fit",
        ),
    ];

    for (i, (data, expected)) in cases.into_iter().enumerate() {
        let res = KernelDumpParser::with_reader(Cursor::new(data.clone()));
        eprintln!("{res:?}");
        assert!(
            matches!(res, Err(Error::InvalidData(e)) if e == expected),
            "case {i}"
        );
    }
}

#[test]
fn cyclic_module_list_is_dropped() {
    // Point the first loaded-module entry at itself so the walk never reaches
    // the list head again.
    let data = fs::read(BMP_PATH.as_path()).unwrap();
    let parser = KernelDumpParser::with_reader(Cursor::new(data.clone())).unwrap();
    let virt_reader = virt::Reader::new(&parser);
    let head = Gva::new(parser.headers().ps_loaded_module_list);
    let first = virt_reader.read_struct::<u64>(head).unwrap();
    let gpa = virt_reader.translate(Gva::new(first)).unwrap().gpa();
    let SeekFrom::Start(offset) = phys::Reader::new(&parser).translate(gpa).unwrap() else {
        unreachable!()
    };
    let offset = usize::try_from(offset).unwrap();
    let mut bad = data;
    bad[offset..offset + 8].copy_from_slice(&first.to_le_bytes());

    // The parse succeeds and the module list is simply absent.
    let parser = KernelDumpParser::with_reader(Cursor::new(bad)).unwrap();
    assert_eq!(parser.kernel_modules().len(), 0);
}

#[test]
fn small_rdmp_sizes_do_not_underflow() {
    // Invalid sizes must fail header validation, not a later parser check.
    // The final case would wrap to metadata_offset - 1 with unchecked addition.
    let metadata_offset = (size_of::<Header64>() + size_of::<RdmpHeader64>()) as u64;
    for (metadata_size, first_page_offset) in [
        (0x20 - 1, 0x20_40),
        (0x20, 0x20_40 - 1),
        (0x20 - 1, 0x20_40 - 1),
        (u64::MAX, metadata_offset - 1),
    ] {
        let mut data = vec![0; size_of::<KernelRdmpHeader64>()];
        let h = pod_mut::<KernelRdmpHeader64>(&mut data).unwrap();
        h.hdr.marker = RDMP_HEADER64_EXPECTED_MARKER;
        h.hdr.signature = RDMP_HEADER64_EXPECTED_SIGNATURE;
        h.hdr.valid_dump = RDMP_HEADER64_EXPECTED_VALID_DUMP;
        h.hdr.metadata_size = metadata_size;
        h.hdr.first_page_offset = first_page_offset;
        let data = synthetic_dump(DumpType::KernelMemory, |_| {}, &data);
        let res = KernelDumpParser::with_reader(Cursor::new(data));

        assert!(
            matches!(
                res,
                Err(Error::InvalidData("RdmpHeader64 doesn't look right"))
            ),
            "metadata_size={metadata_size:#x}, first_page_offset={first_page_offset:#x}: {res:?}"
        );
    }
}
