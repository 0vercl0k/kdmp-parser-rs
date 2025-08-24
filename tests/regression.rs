// Axel '0vercl0k' Souchet - March 17 2024
use std::collections::HashSet;
use std::env;
use std::fs::File;
use std::ops::Range;
use std::path::PathBuf;

use kdmp_parser::{AddrTranslationError, Gpa, Gva, KdmpParserError, KernelDumpParser, PageKind};
use serde::Deserialize;

/// Convert an hexadecimal encoded integer string into a `u64`.
pub fn hex_str(s: &str) -> u64 {
    let prefix = s.strip_prefix("0x");

    u64::from_str_radix(prefix.unwrap_or(s), 16).unwrap()
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
    dump_type: kdmp_parser::DumpType,
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

        let filename = name.rsplit_once('\\').map(|(_, s)| s).unwrap_or(name);
        if filename.to_lowercase() != found_mod.name.to_lowercase() {
            if found_mod.name == "nt" && filename == "ntoskrnl.exe" {
                continue;
            }

            eprintln!("{name} {found_mod:?}");
            return false;
        }
    }

    seen.len() == modules.len()
}

// Extract the info with WinDbg w/ the below:
// ```
// dx -r2 @$curprocess.Modules.Select(p => new {start=p.BaseAddress, end=p.BaseAddress + p.Size, name=p.Name})
// ```
#[test]
fn regressions() {
    let base_path =
        PathBuf::from(env::var("TESTDATAS").expect("I need the TESTDATAS env var to work"));

    let test_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");
    let modules_1: Vec<M> =
        serde_json::from_reader(File::open(test_dir.join("modules_1.json")).unwrap()).unwrap();
    let modules_1 = modules_1
        .into_iter()
        .map(|m| m.into())
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
        file: base_path.join("bmp.dmp"),
        dump_type: kdmp_parser::DumpType::Bmp,
        size: 0x54_4b,
        phys_addr: 0x6d_4d_22,
        phys_bytes: [
            0x6d, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x63, 0x88, 0x75, 0x00, 0x00, 0x00, 0x00, 0x0a,
            0x63, 0x98,
        ],
        virt_addr: 0xfffff805_108776a0,
        virt_bytes: [
            0xcc, 0xc3, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ],
        rax: 0x00000000_00000003,
        rbx: 0xfffff805_0f4e9f70,
        rcx: 0x00000000_00000001,
        rdx: 0xfffff805_135684d0,
        rsi: 0x00000000_00000100,
        rdi: 0xfffff805_0f4e9f80,
        rip: 0xfffff805_108776a0,
        rsp: 0xfffff805_135684f8,
        rbp: 0xfffff805_13568600,
        r8: 0x00000000_00000003,
        r9: 0xfffff805_135684b8,
        r10: 0x00000000_00000000,
        r11: 0xffffa884_8825e000,
        r12: 0xfffff805_0f4e9f80,
        r13: 0xfffff805_10c3c958,
        r14: 0x00000000_00000000,
        r15: 0x00000000_00000052,
        modules: modules_1.as_slice(),
    };

    let full = TestcaseValues {
        file: base_path.join("full.dmp"),
        dump_type: kdmp_parser::DumpType::Full,
        size: 0x03_fb_e6,
        phys_addr: 0x6d_4d_22,
        phys_bytes: [
            0x6d, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x63, 0x88, 0x75, 0x00, 0x00, 0x00, 0x00, 0x0a,
            0x63, 0x98,
        ],
        virt_addr: 0xfffff805_108776a0,
        virt_bytes: [
            0xcc, 0xc3, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ],
        rax: 0x00000000_00000003,
        rbx: 0xfffff805_0f4e9f70,
        rcx: 0x00000000_00000001,
        rdx: 0xfffff805_135684d0,
        rsi: 0x00000000_00000100,
        rdi: 0xfffff805_0f4e9f80,
        rip: 0xfffff805_108776a0,
        rsp: 0xfffff805_135684f8,
        rbp: 0xfffff805_13568600,
        r8: 0x00000000_00000003,
        r9: 0xfffff805_135684b8,
        r10: 0x00000000_00000000,
        r11: 0xffffa884_8825e000,
        r12: 0xfffff805_0f4e9f80,
        r13: 0xfffff805_10c3c958,
        r14: 0x00000000_00000000,
        r15: 0x00000000_00000052,
        modules: &modules_1,
    };

    let modules_2: Vec<M> =
        serde_json::from_reader(File::open(test_dir.join("modules_2.json")).unwrap()).unwrap();
    let modules_2 = modules_2
        .into_iter()
        .map(|m| m.into())
        .collect::<Vec<Module>>();

    let kernel_dump = TestcaseValues {
        file: base_path.join("kerneldump.dmp"),
        dump_type: kdmp_parser::DumpType::KernelMemory,
        size: 0xa0_2e,
        phys_addr: 0x02_58_92_f0,
        phys_bytes: [
            0x10, 0x8c, 0x24, 0x50, 0x0c, 0xc0, 0xff, 0xff, 0xa0, 0x19, 0x38, 0x51, 0x0c, 0xc0,
            0xff, 0xff,
        ],
        virt_addr: 0xfffff803_f2c35470,
        virt_bytes: [
            0xcc, 0xc3, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ],
        rax: 0x00000000_00007a01,
        rbx: 0xffffc00c_5191e010,
        rcx: 0x00000000_00000001,
        rdx: 0x00000012_00000000,
        rsi: 0xffffc00c_51907bb0,
        rdi: 0x00000000_00000002,
        rip: 0xfffff803_f2c35470,
        rsp: 0xfffff803_f515ec28,
        rbp: 0x00000000_0c1c9800,
        r8: 0x00000000_000000b0,
        r9: 0xffffc00c_502ff000,
        r10: 0x00000000_00000057,
        r11: 0xfffff803_f3a04500,
        r12: 0xfffff803_f515ee60,
        r13: 0x00000000_00000003,
        r14: 0xfffff803_f1e9a180,
        r15: 0x00000000_0000001f,
        modules: &modules_2,
    };

    let modules_3: Vec<M> =
        serde_json::from_reader(File::open(test_dir.join("modules_3.json")).unwrap()).unwrap();
    let modules_3 = modules_3
        .into_iter()
        .map(|m| m.into())
        .collect::<Vec<Module>>();

    let kernel_user_dump = TestcaseValues {
        file: base_path.join("kerneluserdump.dmp"),
        dump_type: kdmp_parser::DumpType::KernelAndUserMemory,
        size: 0x01_f7_c7,
        phys_addr: 0x02_58_92_f0,
        phys_bytes: [
            0x10, 0x8c, 0x24, 0x50, 0x0c, 0xc0, 0xff, 0xff, 0xa0, 0x19, 0x38, 0x51, 0x0c, 0xc0,
            0xff, 0xff,
        ],
        virt_addr: 0xfffff803_f2c35470,
        virt_bytes: [
            0xcc, 0xc3, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ],
        rax: 0x00000000_00007a01,
        rbx: 0xffffc00c_5191e010,
        rcx: 0x00000000_00000001,
        rdx: 0x00000012_00000000,
        rsi: 0xffffc00c_51907bb0,
        rdi: 0x00000000_00000002,
        rip: 0xfffff803_f2c35470,
        rsp: 0xfffff803_f515ec28,
        rbp: 0x00000000_0c1c9800,
        r8: 0x00000000_000000b0,
        r9: 0xffffc00c_502ff000,
        r10: 0x00000000_00000057,
        r11: 0xfffff803_f3a04500,
        r12: 0xfffff803_f515ee60,
        r13: 0x00000000_00000003,
        r14: 0xfffff803_f1e9a180,
        r15: 0x00000000_0000001f,
        modules: &modules_3,
    };

    let complete_dump = TestcaseValues {
        file: base_path.join("completedump.dmp"),
        dump_type: kdmp_parser::DumpType::CompleteMemory,
        size: 0x01_fb_f9,
        phys_addr: 0x02_58_92_f0,
        phys_bytes: [
            0x10, 0x8c, 0x24, 0x50, 0x0c, 0xc0, 0xff, 0xff, 0xa0, 0x19, 0x38, 0x51, 0x0c, 0xc0,
            0xff, 0xff,
        ],
        virt_addr: 0xfffff803_f2c35470,
        virt_bytes: [
            0xcc, 0xc3, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ],
        rax: 0x00000000_00007a01,
        rbx: 0xffffc00c_5191e010,
        rcx: 0x00000000_00000001,
        rdx: 0x00000012_00000000,
        rsi: 0xffffc00c_51907bb0,
        rdi: 0x00000000_00000002,
        rip: 0xfffff803_f2c35470,
        rsp: 0xfffff803_f515ec28,
        rbp: 0x00000000_0c1c9800,
        r8: 0x00000000_000000b0,
        r9: 0xffffc00c_502ff000,
        r10: 0x00000000_00000057,
        r11: 0xfffff803_f3a04500,
        r12: 0xfffff803_f515ee60,
        r13: 0x00000000_00000003,
        r14: 0xfffff803_f1e9a180,
        r15: 0x00000000_0000001f,
        modules: &modules_3,
    };

    let modules_4: Vec<M> =
        serde_json::from_reader(File::open(test_dir.join("modules_4.json")).unwrap()).unwrap();
    let modules_4 = modules_4
        .into_iter()
        .map(|m| m.into())
        .collect::<Vec<Module>>();

    let live_kernel = TestcaseValues {
        file: base_path.join("fulllivekernelmemory.dmp"),
        dump_type: kdmp_parser::DumpType::LiveKernelMemory,
        size: 0x01_54_f5,
        phys_addr: 0xd9_6a_90_00,
        phys_bytes: [
            0x67, 0xd8, 0xb6, 0xdd, 0x00, 0x00, 0x00, 0x0a, 0x67, 0xa8, 0x1d, 0xd6, 0x00, 0x00,
            0x00, 0x0a,
        ],
        virt_addr: 0xfffff807_50a98b6d,
        virt_bytes: [
            0x48, 0x8d, 0x8f, 0x00, 0x01, 0x00, 0x00, 0xe8, 0x17, 0x2a, 0x98, 0xff, 0x48, 0x81,
            0xc3, 0x48,
        ],
        rax: 0x00000000_00000004,
        rbx: 0xffffd20f_d8553000,
        rcx: 0xffffa100_0ed84a00,
        rdx: 0x00000000_00000000,
        rsi: 0xffffd20f_d3beeae0,
        rdi: 0xfffff807_4fb4b180,
        rip: 0xfffff807_50a98b6d,
        rsp: 0xfffffd8d_6bcaed10,
        rbp: 0x00000000_00000000,
        r8: 0x00000000_00000b80,
        r9: 0xffffd20f_d8553348,
        r10: 0x00000000_00000000,
        r11: 0xffffd20f_d8553000,
        r12: 0x00000000_00000002,
        r13: 0x00000000_00000000,
        r14: 0xffffd20f_d48d5080,
        r15: 0x00000000_00000001,
        modules: &modules_4,
    };

    let modules_5: Vec<M> =
        serde_json::from_reader(File::open(test_dir.join("modules_5.json")).unwrap()).unwrap();
    let modules_5 = modules_5
        .into_iter()
        .map(|m| m.into())
        .collect::<Vec<Module>>();

    let wow64 = TestcaseValues {
        file: base_path.join("wow64_kernelactive.dmp"),
        dump_type: kdmp_parser::DumpType::KernelAndUserMemory,
        size: 0x03_ec_ff,
        phys_addr: 0x06_23_50_00,
        phys_bytes: [
            0xcc, 0x33, 0xc0, 0xc3, 0x3b, 0x0d, 0x00, 0x50, 0x46, 0x00, 0x75, 0x01, 0xc3, 0xe9,
            0x79, 0x02,
        ],
        virt_addr: 0x00451000,
        virt_bytes: [
            0xcc, 0x33, 0xc0, 0xc3, 0x3b, 0x0d, 0x00, 0x50, 0x46, 0x00, 0x75, 0x01, 0xc3, 0xe9,
            0x79, 0x02,
        ],
        rax: 0x00465e58,
        rbx: 0x0062d000,
        rcx: 0x00000000,
        rdx: 0x420e1d36,
        rsi: 0x009ef4c0,
        rdi: 0x009f0d30,
        rip: 0x00451000,
        rsp: 0x0056fbcc,
        rbp: 0x0056fc10,
        r8: 0x0000002b,
        r9: 0x77cb2c0c,
        r10: 0x00000000,
        r11: 0x0038e450,
        r12: 0x0062e000,
        r13: 0x0038fda0,
        r14: 0x0038ed40,
        r15: 0x77c34660,
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
        eprintln!("{parser:?}");
        assert_eq!(parser.dump_type(), test.dump_type);
        assert_eq!(parser.physmem().len(), test.size as usize);
        let mut buf = [0; 16];
        parser
            .phys_read_exact(Gpa::new(test.phys_addr), &mut buf)
            .unwrap();
        assert_eq!(buf, test.phys_bytes);
        parser
            .virt_read_exact(Gva::new(test.virt_addr), &mut buf)
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

    // Example of a transition PTE readable by WinDbg (in kerneluserdump.dmp):
    // ```
    // kd> db 0x1a42ea30240 l10
    // 000001a4`2ea30240  e0 07 a3 2e a4 01 00 00-80 f2 a2 2e a4 01 00 00  ................
    // kd> !pte 0x1a42ea30240
    //                                            VA 000001a42ea30240
    // PXE at FFFFECF67B3D9018    PPE at FFFFECF67B203480    PDE at FFFFECF640690BA8    PTE at FFFFEC80D2175180
    // contains 0A0000000ECC0867  contains 0A00000013341867  contains 0A000000077AF867  contains 00000000166B7880
    // pfn ecc0      ---DA--UWEV  pfn 13341     ---DA--UWEV  pfn 77af      ---DA--UWEV  not valid
    //                                                                               Transition: 166b7
    // Protect: 4 - ReadWrite
    // ```
    let parser = KernelDumpParser::new(&kernel_user_dump.file).unwrap();
    let mut buffer = [0; 16];
    let expected_buffer = [
        0xe0, 0x07, 0xa3, 0x2e, 0xa4, 0x01, 0x00, 0x00, 0x80, 0xf2, 0xa2, 0x2e, 0xa4, 0x01, 0x00,
        0x00,
    ];
    assert!(parser.virt_read(0x1a42ea30240.into(), &mut buffer).is_ok());
    assert_eq!(buffer, expected_buffer);

    // Example of a valid PTE that don't have a physical page backing it (in
    // kerneldump.dmp):
    // ```
    // kd> !pte 0x1a42ea30240
    //     VA 000001a42ea30240
    // PXE at FFFFECF67B3D9018    PPE at FFFFECF67B203480    PDE at FFFFECF640690BA8    PTE at FFFFEC80D2175180
    // contains 0A0000000ECC0867  contains 0A00000013341867  contains 0A000000077AF867  contains 00000000166B7880
    // pfn ecc0      ---DA--UWEV  pfn 13341     ---DA--UWEV  pfn 77af      ---DA--UWEV  not valid
    //                                            Transition: 166b7
    //                                            Protect: 4 - ReadWrite
    // kd> !db 166b7240
    // Physical memory read at 166b7240 failed
    //
    // kd> !pte 0x16e23fa060
    //     VA 00000016e23fa060
    // PXE at FFFFECF67B3D9000    PPE at FFFFECF67B2002D8    PDE at FFFFECF64005B888    PTE at FFFFEC800B711FD0
    // contains 0A00000001FEB867  contains 0A00000019A08867  contains 0A00000019A07867  contains 8000000001BC4867
    // pfn 1feb      ---DA--UWEV  pfn 19a08     ---DA--UWEV  pfn 19a07     ---DA--UWEV  pfn 1bc4      ---DA--UW-V
    // kd> !db 1bc4000
    // Physical memory read at 1bc4000 failed
    // ```
    let parser = KernelDumpParser::new(&kernel_dump.file).unwrap();
    let mut buffer = [0];
    assert!(matches!(
        parser.virt_read(0x1a42ea30240.into(), &mut buffer),
        Err(KdmpParserError::AddrTranslation(
            AddrTranslationError::Phys(gpa)
        )) if gpa == 0x166b7240.into()
    ));

    assert!(matches!(
        parser.virt_read(0x16e23fa060.into(), &mut buffer),
        Err(KdmpParserError::AddrTranslation(
            AddrTranslationError::Phys(gpa)
        )) if gpa == 0x1bc4060.into()
    ));

    // BUG: https://github.com/0vercl0k/kdmp-parser-rs/issues/10
    // When reading the end of a virtual memory page that has no available
    // memory behind, there was an issue in the virtual read algorithm. The
    // first time the loop ran, it reads as much as it can and if the user
    // wanted more, then the loop runs a second time to virt translate the next
    // page. However, because there is nothing mapped the virtual to physical
    // translation fails & bails (because of `?`) which suggests to the user
    // that the read operation completely failed when it was in fact able to
    // read some amount of bytes.
    // ```text
    // kd> db 00007ff7`ab766ff7
    // 00007ff7`ab766ff7  00 00 00 00 00 00 00 00-00 ?? ?? ?? ?? ?? ?? ??  .........???????
    // ...
    // kdmp-parser-rs>cargo r --example parser -- mem.dmp --mem 00007ff7`ab766ff7 --virt --len 10
    //     Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.09s
    //      Running `target\debug\examples\parser.exe mem.dmp --mem 00007ff7`ab766ff7 --virt --len 10`
    // There is no virtual memory available at 0x7ff7ab766ff7
    // ```
    // ```text
    // kd> db fffff803`f3086fef
    // fffff803`f3086fef  9d f5 de ff 48 85 c0 74-0a 40 8a cf e8 80 ee ba  ....H..t.@......
    // fffff803`f3086fff  ff ?? ?? ?? ?? ?? ?? ??-?? ?? ?? ?? ?? ?? ?? ??  .???????????????
    // fffff803`f308700f  ?? ?? ?? ?? ?? ?? ?? ??-?? ?? ?? ?? ?? ?? ?? ??  ????????????????
    // ```
    let mut buffer = [0; 32];
    assert_eq!(
        parser
            .virt_read(0xfffff803f3086fef.into(), &mut buffer)
            .unwrap(),
        17
    );

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
    let parser = KernelDumpParser::new(&complete_dump.file).unwrap();
    let mut buffer = [0; 64];
    assert!(
        parser
            .virt_read_exact_with_dtb(0x15cc6603908.into(), &mut buffer, 0xea00002.into())
            .is_ok()
    );

    assert_eq!(buffer, [
        0x43, 0x00, 0x3a, 0x00, 0x5c, 0x00, 0x57, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x64, 0x00, 0x6f,
        0x00, 0x77, 0x00, 0x73, 0x00, 0x5c, 0x00, 0x53, 0x00, 0x79, 0x00, 0x73, 0x00, 0x74, 0x00,
        0x65, 0x00, 0x6d, 0x00, 0x33, 0x00, 0x32, 0x00, 0x5c, 0x00, 0x52, 0x00, 0x75, 0x00, 0x6e,
        0x00, 0x74, 0x00, 0x69, 0x00, 0x6d, 0x00, 0x65, 0x00, 0x42, 0x00, 0x72, 0x00, 0x6f, 0x00,
        0x6b, 0x00, 0x65, 0x00
    ]);

    // Read from the middle of a large page.
    // ```text
    // 32.1: kd> !pte nt
    //                                            VA fffff80122800000
    // PXE at FFFFF5FAFD7EBF80    PPE at FFFFF5FAFD7F0020    PDE at FFFFF5FAFE0048A0    PTE at FFFFF5FC00914000
    // contains 0000000002709063  contains 000000000270A063  contains 8A000000048001A1  contains 0000000000000000
    // pfn 2709      ---DA--KWEV  pfn 270a      ---DA--KWEV  pfn 4800      -GL-A--KR-V  LARGE PAGE pfn 4800
    // ```
    let parser = KernelDumpParser::new(&wow64.file).unwrap();
    let tr = parser
        .virt_translate_with_dtb(0xfffff80122800000.into(), 0x5dc6f000.into())
        .unwrap();
    assert!(matches!(tr.page_kind, PageKind::Large));
    assert!(matches!(tr.pfn.u64(), 0x4800));
    let mut buffer = [0; 0x10];
    // ```text
    // 32.1: kd> db 0xfffff80122800000 + 0x100000 - 8
    // 002b:fffff801`228ffff8  70 72 05 00 04 3a 65 00-54 3a 65 00 bc 82 0c 00  pr...:e.T:e.....
    // ```
    assert!(
        parser
            .virt_read_exact(Gva::new(0xfffff80122800000 + 0x100000 - 8), &mut buffer)
            .is_ok()
    );
    assert_eq!(buffer, [
        0x70, 0x72, 0x05, 0x00, 0x04, 0x3a, 0x65, 0x00, 0x54, 0x3a, 0x65, 0x00, 0xbc, 0x82, 0x0c,
        0x00
    ]);

    // Read from two straddling large pages.
    // ```text
    // 32.1: kd> !pte fffff80122a00000 - 10
    //                                            VA fffff801229ffff0
    // PXE at FFFFF5FAFD7EBF80    PPE at FFFFF5FAFD7F0020    PDE at FFFFF5FAFE0048A0    PTE at FFFFF5FC00914FF8
    // contains 0000000002709063  contains 000000000270A063  contains 8A000000048001A1  contains 0000000000000000
    // pfn 2709      ---DA--KWEV  pfn 270a      ---DA--KWEV  pfn 4800      -GL-A--KR-V  LARGE PAGE pfn 49ff
    //
    // 32.1: kd> !pte fffff80122a00000
    //                                            VA fffff80122a00000
    // PXE at FFFFF5FAFD7EBF80    PPE at FFFFF5FAFD7F0020    PDE at FFFFF5FAFE0048A8    PTE at FFFFF5FC00915000
    // contains 0000000002709063  contains 000000000270A063  contains 0A00000004A001A1  contains 0000000000000000
    // pfn 2709      ---DA--KWEV  pfn 270a      ---DA--KWEV  pfn 4a00      -GL-A--KREV  LARGE PAGE pfn 4a00
    // 32.1: kd> db fffff80122a00000 - 10
    // 002b:fffff801`229ffff0  65 00 5c 00 4d 00 69 00-63 00 72 00 6f 00 73 00  e.\.M.i.c.r.o.s.
    // ```
    let mut buffer = [0; 0x10];
    assert!(
        parser
            .virt_read_exact(Gva::new(0xfffff80122a00000 - 10), &mut buffer)
            .is_ok()
    );
    assert_eq!(buffer, [
        0x65, 0x00, 0x5c, 0x00, 0x4d, 0x00, 0x69, 0x00, 0x63, 0x00, 0x72, 0x00, 0x6f, 0x00, 0x73,
        0x00
    ]);
}
