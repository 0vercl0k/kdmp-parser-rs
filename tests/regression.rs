// Axel '0vercl0k' Souchet - March 17 2024
use std::env;
use std::path::PathBuf;

use kdmp_parser::{Gpa, Gva, KernelDumpParser};

struct TestcaseValues {
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
}

#[test]
fn regressions() {
    let base_path =
        PathBuf::from(env::var("TESTDATAS").expect("I need the TESTDATAS env var to work"));

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
    };

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
    };

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
    };

    let tests = [&bmp, &full, &kernel_dump, &kernel_user_dump, &complete_dump];
    for test in tests {
        let parser = KernelDumpParser::new(&test.file).unwrap();
        assert_eq!(parser.dump_type(), test.dump_type);
        assert_eq!(parser.physmem().len(), test.size as usize);
        let mut buffer = [0; 16];
        parser
            .phys_read_exact(Gpa::new(test.phys_addr), &mut buffer)
            .unwrap();
        assert_eq!(buffer, test.phys_bytes);
        parser
            .virt_read_exact(Gva::new(test.virt_addr), &mut buffer)
            .unwrap();
        assert_eq!(buffer, test.virt_bytes);
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
    }
}
