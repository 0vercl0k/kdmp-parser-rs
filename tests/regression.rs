// Axel '0vercl0k' Souchet - March 17 2024
use std::collections::HashSet;
use std::env;
use std::ops::Range;
use std::path::PathBuf;

use kdmp_parser::{Gpa, Gva, KernelDumpParser};

#[derive(Debug)]
struct M {
    name: &'static str,
    at: Range<Gva>,
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
    kernel_modules: &'test [M],
}

fn compare_kernel_modules(parser: &KernelDumpParser, modules: &[M]) -> bool {
    let parser_modules = parser.kernel_modules();
    if parser_modules.len() != modules.len() {
        return false;
    }

    let mut seen = HashSet::new();
    for (r, name) in parser_modules {
        if seen.contains(&r.start) {
            return false;
        }

        let found_mod = modules.iter().find(|m| m.at == *r).unwrap();
        seen.insert(r.start);

        let filename = name.rsplit_once('\\').map(|(_, s)| s).unwrap_or(&name);
        if filename.to_lowercase() != found_mod.name.to_lowercase() {
            if found_mod.name == "nt" && filename == "ntoskrnl.exe" {
                continue;
            }

            return false;
        }
    }

    true
}

#[test]
fn regressions() {
    let base_path =
        PathBuf::from(env::var("TESTDATAS").expect("I need the TESTDATAS env var to work"));

    let kernel_modules = [
        M {
            at: 0xfffff80510610000.into()..0xfffff805106b3000.into(),
            name: "hal.dll",
        },
        M {
            at: 0xfffff805106b3000.into()..0xfffff80511165000.into(),
            name: "nt",
        },
        M {
            at: 0xfffff80511200000.into()..0xfffff8051120c000.into(),
            name: "kdstub.dll",
        },
        M {
            at: 0xfffff80511210000.into()..0xfffff80511259000.into(),
            name: "kdnet.dll",
        },
        M {
            at: 0xfffff80511260000.into()..0xfffff80511461000.into(),
            name: "mcupdate_GenuineIntel.dll",
        },
        M {
            at: 0xfffff80511470000.into()..0xfffff80511481000.into(),
            name: "werkernel.sys",
        },
        M {
            at: 0xfffff80511490000.into()..0xfffff805114ba000.into(),
            name: "ksecdd.sys",
        },
        M {
            at: 0xfffff805114c0000.into()..0xfffff80511520000.into(),
            name: "msrpc.sys",
        },
        M {
            at: 0xfffff80511530000.into()..0xfffff80511557000.into(),
            name: "tm.sys",
        },
        M {
            at: 0xfffff80511560000.into()..0xfffff805115c8000.into(),
            name: "CLFS.sys",
        },
        M {
            at: 0xfffff805115d0000.into()..0xfffff805115ea000.into(),
            name: "PSHED.dll",
        },
        M {
            at: 0xfffff805115f0000.into()..0xfffff805115fb000.into(),
            name: "BOOTVID.dll",
        },
        M {
            at: 0xfffff80511900000.into()..0xfffff80511a05000.into(),
            name: "clipsp.sys",
        },
        M {
            at: 0xfffff80511a10000.into()..0xfffff80511a81000.into(),
            name: "FLTMGR.sys",
        },
        M {
            at: 0xfffff80511a90000.into()..0xfffff80511a9e000.into(),
            name: "cmimcext.sys",
        },
        M {
            at: 0xfffff80511aa0000.into()..0xfffff80511aac000.into(),
            name: "ntosext.sys",
        },
        M {
            at: 0xfffff80511ab0000.into()..0xfffff80511b8c000.into(),
            name: "CI.dll",
        },
        M {
            at: 0xfffff80511b90000.into()..0xfffff80511c4c000.into(),
            name: "cng.sys",
        },
        M {
            at: 0xfffff80511c50000.into()..0xfffff80511cea000.into(),
            name: "VerifierExt.sys",
        },
        M {
            at: 0xfffff80511cf0000.into()..0xfffff80511cff000.into(),
            name: "SleepStudyHelper.sys",
        },
        M {
            at: 0xfffff80511d00000.into()..0xfffff80511dd5000.into(),
            name: "Wdf01000.sys",
        },
        M {
            at: 0xfffff80511de0000.into()..0xfffff80511df3000.into(),
            name: "WDFLDR.sys",
        },
        M {
            at: 0xfffff80511e00000.into()..0xfffff80511e10000.into(),
            name: "WppRecorder.sys",
        },
        M {
            at: 0xfffff80511e20000.into()..0xfffff80511e45000.into(),
            name: "acpiex.sys",
        },
        M {
            at: 0xfffff80511e50000.into()..0xfffff80511e99000.into(),
            name: "mssecflt.sys",
        },
        M {
            at: 0xfffff80511ea0000.into()..0xfffff80511eba000.into(),
            name: "SgrmAgent.sys",
        },
        M {
            at: 0xfffff80511ec0000.into()..0xfffff80511f8c000.into(),
            name: "ACPI.sys",
        },
        M {
            at: 0xfffff80511f90000.into()..0xfffff80511f9c000.into(),
            name: "WMILIB.sys",
        },
        M {
            at: 0xfffff80511fa0000.into()..0xfffff80511fb0000.into(),
            name: "WdBoot.sys",
        },
        M {
            at: 0xfffff80511fc0000.into()..0xfffff80512009000.into(),
            name: "intelpep.sys",
        },
        M {
            at: 0xfffff80512010000.into()..0xfffff80512027000.into(),
            name: "WindowsTrustedRT.sys",
        },
        M {
            at: 0xfffff80512030000.into()..0xfffff8051203b000.into(),
            name: "WindowsTrustedRTProxy.sys",
        },
        M {
            at: 0xfffff80512040000.into()..0xfffff80512055000.into(),
            name: "pcw.sys",
        },
        M {
            at: 0xfffff80512060000.into()..0xfffff80512073000.into(),
            name: "vdrvroot.sys",
        },
        M {
            at: 0xfffff80512080000.into()..0xfffff805120c1000.into(),
            name: "ucx01000.sys",
        },
        M {
            at: 0xfffff805120d0000.into()..0xfffff80512103000.into(),
            name: "pdc.sys",
        },
        M {
            at: 0xfffff80512110000.into()..0xfffff80512129000.into(),
            name: "CEA.sys",
        },
        M {
            at: 0xfffff80512130000.into()..0xfffff80512160000.into(),
            name: "partmgr.sys",
        },
        M {
            at: 0xfffff80512170000.into()..0xfffff80512215000.into(),
            name: "spaceport.sys",
        },
        M {
            at: 0xfffff80512220000.into()..0xfffff8051223a000.into(),
            name: "volmgr.sys",
        },
        M {
            at: 0xfffff80512240000.into()..0xfffff8051228e000.into(),
            name: "sdbus.sys",
        },
        M {
            at: 0xfffff80512290000.into()..0xfffff805122f3000.into(),
            name: "volmgrx.sys",
        },
        M {
            at: 0xfffff80512300000.into()..0xfffff8051232c000.into(),
            name: "vmbus.sys",
        },
        M {
            at: 0xfffff80512330000.into()..0xfffff80512358000.into(),
            name: "hvsocket.sys",
        },
        M {
            at: 0xfffff80512360000.into()..0xfffff805123f4000.into(),
            name: "NETIO.sys",
        },
        M {
            at: 0xfffff80512400000.into()..0xfffff80512572000.into(),
            name: "NDIS.sys",
        },
        M {
            at: 0xfffff80512580000.into()..0xfffff8051259d000.into(),
            name: "vmbkmcl.sys",
        },
        M {
            at: 0xfffff805125a0000.into()..0xfffff805125b2000.into(),
            name: "winhv.sys",
        },
        M {
            at: 0xfffff805125c0000.into()..0xfffff805125d8000.into(),
            name: "urscx01000.sys",
        },
        M {
            at: 0xfffff805125e0000.into()..0xfffff805125ff000.into(),
            name: "mountmgr.sys",
        },
        M {
            at: 0xfffff80512600000.into()..0xfffff8051261b000.into(),
            name: "EhStorClass.sys",
        },
        M {
            at: 0xfffff80512620000.into()..0xfffff8051263a000.into(),
            name: "fileinfo.sys",
        },
        M {
            at: 0xfffff80512640000.into()..0xfffff8051267d000.into(),
            name: "Wof.sys",
        },
        M {
            at: 0xfffff80512680000.into()..0xfffff805126d4000.into(),
            name: "WdFilter.sys",
        },
        M {
            at: 0xfffff805126e0000.into()..0xfffff80512713000.into(),
            name: "usbccgp.sys",
        },
        M {
            at: 0xfffff80512720000.into()..0xfffff8051272e000.into(),
            name: "USBD.sys",
        },
        M {
            at: 0xfffff80512730000.into()..0xfffff8051273d000.into(),
            name: "urschipidea.sys",
        },
        M {
            at: 0xfffff80512740000.into()..0xfffff8051274f000.into(),
            name: "storvsc.sys",
        },
        M {
            at: 0xfffff80512750000.into()..0xfffff805127f2000.into(),
            name: "storport.sys",
        },
        M {
            at: 0xfffff80512800000.into()..0xfffff8051281d000.into(),
            name: "usbehci.sys",
        },
        M {
            at: 0xfffff80512820000.into()..0xfffff8051289a000.into(),
            name: "USBPORT.sys",
        },
        M {
            at: 0xfffff805128a0000.into()..0xfffff805128ad000.into(),
            name: "Fs_Rec.sys",
        },
        M {
            at: 0xfffff805128b0000.into()..0xfffff805128e2000.into(),
            name: "ksecpkg.sys",
        },
        M {
            at: 0xfffff805128f0000.into()..0xfffff805128fb000.into(),
            name: "volume.sys",
        },
        M {
            at: 0xfffff80512900000.into()..0xfffff80512b9e000.into(),
            name: "Ntfs.sys",
        },
        M {
            at: 0xfffff80512ba0000.into()..0xfffff80512c2a000.into(),
            name: "usbhub.sys",
        },
        M {
            at: 0xfffff80512c30000.into()..0xfffff80512ccc000.into(),
            name: "UsbHub3.sys",
        },
        M {
            at: 0xfffff80512cd0000.into()..0xfffff80512fba000.into(),
            name: "tcpip.sys",
        },
        M {
            at: 0xfffff80512fc0000.into()..0xfffff8051303a000.into(),
            name: "fwpkclnt.sys",
        },
        M {
            at: 0xfffff80513040000.into()..0xfffff80513070000.into(),
            name: "wfplwfs.sys",
        },
        M {
            at: 0xfffff80513080000.into()..0xfffff80513149000.into(),
            name: "fvevol.sys",
        },
        M {
            at: 0xfffff80513150000.into()..0xfffff805131bd000.into(),
            name: "volsnap.sys",
        },
        M {
            at: 0xfffff805131c0000.into()..0xfffff80513249000.into(),
            name: "USBXHCI.sys",
        },
        M {
            at: 0xfffff80513250000.into()..0xfffff80513275000.into(),
            name: "USBSTOR.sys",
        },
        M {
            at: 0xfffff80513280000.into()..0xfffff80513298000.into(),
            name: "uaspstor.sys",
        },
        M {
            at: 0xfffff805132a0000.into()..0xfffff805132be000.into(),
            name: "sdstor.sys",
        },
        M {
            at: 0xfffff805132c0000.into()..0xfffff8051330e000.into(),
            name: "rdyboost.sys",
        },
        M {
            at: 0xfffff80513310000.into()..0xfffff80513335000.into(),
            name: "mup.sys",
        },
        M {
            at: 0xfffff80513340000.into()..0xfffff80513352000.into(),
            name: "iorate.sys",
        },
        M {
            at: 0xfffff80513360000.into()..0xfffff8051336f000.into(),
            name: "hwpolicy.sys",
        },
        M {
            at: 0xfffff80513370000.into()..0xfffff8051338c000.into(),
            name: "disk.sys",
        },
        M {
            at: 0xfffff80513390000.into()..0xfffff805133fb000.into(),
            name: "CLASSPNP.sys",
        },
    ];

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
        kernel_modules: &kernel_modules,
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
        kernel_modules: &kernel_modules,
    };

    let kernel_modules = [
        M {
            at: 0xfffff3eb6ff80000.into()..0xfffff3eb6fffc000.into(),
            name: "win32k.sys",
        },
        M {
            at: 0xfffff3eb70000000.into()..0xfffff3eb70234000.into(),
            name: "win32kbase.sys",
        },
        M {
            at: 0xfffff3eb70240000.into()..0xfffff3eb7027f000.into(),
            name: "cdd.dll",
        },
        M {
            at: 0xfffff3eb704e0000.into()..0xfffff3eb70872000.into(),
            name: "win32kfull.sys",
        },
        M {
            at: 0xfffff803f2a09000.into()..0xfffff803f2a95000.into(),
            name: "hal.dll",
        },
        M {
            at: 0xfffff803f2a95000.into()..0xfffff803f33fa000.into(),
            name: "nt",
        },
        M {
            at: 0xfffff803f3600000.into()..0xfffff803f360c000.into(),
            name: "kdstub.dll",
        },
        M {
            at: 0xfffff803f360c000.into()..0xfffff803f363a000.into(),
            name: "kdnet.dll",
        },
        M {
            at: 0xfffff80d24000000.into()..0xfffff80d24060000.into(),
            name: "msrpc.sys",
        },
        M {
            at: 0xfffff80d24060000.into()..0xfffff80d2408a000.into(),
            name: "ksecdd.sys",
        },
        M {
            at: 0xfffff80d24090000.into()..0xfffff80d240a1000.into(),
            name: "werkernel.sys",
        },
        M {
            at: 0xfffff80d240b0000.into()..0xfffff80d24114000.into(),
            name: "CLFS.sys",
        },
        M {
            at: 0xfffff80d24120000.into()..0xfffff80d24144000.into(),
            name: "tm.sys",
        },
        M {
            at: 0xfffff80d24150000.into()..0xfffff80d24167000.into(),
            name: "PSHED.dll",
        },
        M {
            at: 0xfffff80d24170000.into()..0xfffff80d2417b000.into(),
            name: "BOOTVID.dll",
        },
        M {
            at: 0xfffff80d24180000.into()..0xfffff80d241e9000.into(),
            name: "FLTMGR.sys",
        },
        M {
            at: 0xfffff80d241f0000.into()..0xfffff80d242f2000.into(),
            name: "clipsp.sys",
        },
        M {
            at: 0xfffff80d24300000.into()..0xfffff80d2430e000.into(),
            name: "cmimcext.sys",
        },
        M {
            at: 0xfffff80d24310000.into()..0xfffff80d2431c000.into(),
            name: "ntosext.sys",
        },
        M {
            at: 0xfffff80d24320000.into()..0xfffff80d243d5000.into(),
            name: "CI.dll",
        },
        M {
            at: 0xfffff80d243e0000.into()..0xfffff80d24492000.into(),
            name: "cng.sys",
        },
        M {
            at: 0xfffff80d244a0000.into()..0xfffff80d24584000.into(),
            name: "Wdf01000.sys",
        },
        M {
            at: 0xfffff80d24590000.into()..0xfffff80d245a3000.into(),
            name: "WDFLDR.sys",
        },
        M {
            at: 0xfffff80d245b0000.into()..0xfffff80d245be000.into(),
            name: "WppRecorder.sys",
        },
        M {
            at: 0xfffff80d245c0000.into()..0xfffff80d245cf000.into(),
            name: "SleepStudyHelper.sys",
        },
        M {
            at: 0xfffff80d245d0000.into()..0xfffff80d245f3000.into(),
            name: "acpiex.sys",
        },
        M {
            at: 0xfffff80d24600000.into()..0xfffff80d2464f000.into(),
            name: "mssecflt.sys",
        },
        M {
            at: 0xfffff80d24650000.into()..0xfffff80d24665000.into(),
            name: "SgrmAgent.sys",
        },
        M {
            at: 0xfffff80d24670000.into()..0xfffff80d24715000.into(),
            name: "ACPI.sys",
        },
        M {
            at: 0xfffff80d24720000.into()..0xfffff80d2472c000.into(),
            name: "WMILIB.sys",
        },
        M {
            at: 0xfffff80d24740000.into()..0xfffff80d2476f000.into(),
            name: "intelpep.sys",
        },
        M {
            at: 0xfffff80d24770000.into()..0xfffff80d24786000.into(),
            name: "WindowsTrustedRT.sys",
        },
        M {
            at: 0xfffff80d24790000.into()..0xfffff80d2479b000.into(),
            name: "WindowsTrustedRTProxy.sys",
        },
        M {
            at: 0xfffff80d247a0000.into()..0xfffff80d247b4000.into(),
            name: "pcw.sys",
        },
        M {
            at: 0xfffff80d247c0000.into()..0xfffff80d247d2000.into(),
            name: "vdrvroot.sys",
        },
        M {
            at: 0xfffff80d247e0000.into()..0xfffff80d24808000.into(),
            name: "pdc.sys",
        },
        M {
            at: 0xfffff80d24810000.into()..0xfffff80d24829000.into(),
            name: "CEA.sys",
        },
        M {
            at: 0xfffff80d24830000.into()..0xfffff80d2485d000.into(),
            name: "partmgr.sys",
        },
        M {
            at: 0xfffff80d248a0000.into()..0xfffff80d249f9000.into(),
            name: "mcupdate_GenuineIntel.dll",
        },
        M {
            at: 0xfffff80d24a00000.into()..0xfffff80d24a89000.into(),
            name: "NETIO.sys",
        },
        M {
            at: 0xfffff80d24a90000.into()..0xfffff80d24ab6000.into(),
            name: "hvsocket.sys",
        },
        M {
            at: 0xfffff80d24ac0000.into()..0xfffff80d24ad9000.into(),
            name: "vmbkmcl.sys",
        },
        M {
            at: 0xfffff80d24ae0000.into()..0xfffff80d24af0000.into(),
            name: "winhv.sys",
        },
        M {
            at: 0xfffff80d24af0000.into()..0xfffff80d24b4e000.into(),
            name: "volmgrx.sys",
        },
        M {
            at: 0xfffff80d24b50000.into()..0xfffff80d24b6e000.into(),
            name: "mountmgr.sys",
        },
        M {
            at: 0xfffff80d24b70000.into()..0xfffff80d24b8c000.into(),
            name: "EhStorClass.sys",
        },
        M {
            at: 0xfffff80d24b90000.into()..0xfffff80d24baa000.into(),
            name: "fileinfo.sys",
        },
        M {
            at: 0xfffff80d24bb0000.into()..0xfffff80d24beb000.into(),
            name: "Wof.sys",
        },
        M {
            at: 0xfffff80d24bf0000.into()..0xfffff80d24c47000.into(),
            name: "WdFilter.sys",
        },
        M {
            at: 0xfffff80d24c50000.into()..0xfffff80d24eab000.into(),
            name: "Ntfs.sys",
        },
        M {
            at: 0xfffff80d24eb0000.into()..0xfffff80d24ebf000.into(),
            name: "storvsc.sys",
        },
        M {
            at: 0xfffff80d24ec0000.into()..0xfffff80d24f4f000.into(),
            name: "storport.sys",
        },
        M {
            at: 0xfffff80d24f50000.into()..0xfffff80d24f5d000.into(),
            name: "Fs_Rec.sys",
        },
        M {
            at: 0xfffff80d24f60000.into()..0xfffff80d24f90000.into(),
            name: "ksecpkg.sys",
        },
        M {
            at: 0xfffff80d24f90000.into()..0xfffff80d2502e000.into(),
            name: "afd.sys",
        },
        M {
            at: 0xfffff80d25030000.into()..0xfffff80d250a6000.into(),
            name: "rdbss.sys",
        },
        M {
            at: 0xfffff80d250b0000.into()..0xfffff80d25140000.into(),
            name: "csc.sys",
        },
        M {
            at: 0xfffff80d25140000.into()..0xfffff80d2514a000.into(),
            name: "gpuenergydrv.sys",
        },
        M {
            at: 0xfffff80d25150000.into()..0xfffff80d25179000.into(),
            name: "dfsc.sys",
        },
        M {
            at: 0xfffff80d25190000.into()..0xfffff80d25229000.into(),
            name: "spaceport.sys",
        },
        M {
            at: 0xfffff80d25230000.into()..0xfffff80d25249000.into(),
            name: "volmgr.sys",
        },
        M {
            at: 0xfffff80d25250000.into()..0xfffff80d25274000.into(),
            name: "vmbus.sys",
        },
        M {
            at: 0xfffff80d25280000.into()..0xfffff80d253c1000.into(),
            name: "NDIS.sys",
        },
        M {
            at: 0xfffff80d25400000.into()..0xfffff80d254bc000.into(),
            name: "fvevol.sys",
        },
        M {
            at: 0xfffff80d254c0000.into()..0xfffff80d254cb000.into(),
            name: "volume.sys",
        },
        M {
            at: 0xfffff80d254d0000.into()..0xfffff80d25537000.into(),
            name: "volsnap.sys",
        },
        M {
            at: 0xfffff80d25540000.into()..0xfffff80d2558c000.into(),
            name: "rdyboost.sys",
        },
        M {
            at: 0xfffff80d25590000.into()..0xfffff80d255b4000.into(),
            name: "mup.sys",
        },
        M {
            at: 0xfffff80d255c0000.into()..0xfffff80d255d1000.into(),
            name: "iorate.sys",
        },
        M {
            at: 0xfffff80d255e0000.into()..0xfffff80d255ef000.into(),
            name: "mssmbios.sys",
        },
        M {
            at: 0xfffff80d255f0000.into()..0xfffff80d2560c000.into(),
            name: "disk.sys",
        },
        M {
            at: 0xfffff80d25610000.into()..0xfffff80d2567b000.into(),
            name: "CLASSPNP.sys",
        },
        M {
            at: 0xfffff80d256a0000.into()..0xfffff80d256bc000.into(),
            name: "crashdmp.sys",
        },
        M {
            at: 0xfffff80d25760000.into()..0xfffff80d2578e000.into(),
            name: "cdrom.sys",
        },
        M {
            at: 0xfffff80d25790000.into()..0xfffff80d257a4000.into(),
            name: "filecrypt.sys",
        },
        M {
            at: 0xfffff80d257b0000.into()..0xfffff80d257bd000.into(),
            name: "tbs.sys",
        },
        M {
            at: 0xfffff80d257c0000.into()..0xfffff80d257ca000.into(),
            name: "Null.sys",
        },
        M {
            at: 0xfffff80d257d0000.into()..0xfffff80d257da000.into(),
            name: "Beep.sys",
        },
        M {
            at: 0xfffff80d257e0000.into()..0xfffff80d25a99000.into(),
            name: "dxgkrnl.sys",
        },
        M {
            at: 0xfffff80d25aa0000.into()..0xfffff80d25ab4000.into(),
            name: "watchdog.sys",
        },
        M {
            at: 0xfffff80d25ac0000.into()..0xfffff80d25ada000.into(),
            name: "vmbkmclr.sys",
        },
        M {
            at: 0xfffff80d25ae0000.into()..0xfffff80d25af6000.into(),
            name: "BasicDisplay.sys",
        },
        M {
            at: 0xfffff80d25b00000.into()..0xfffff80d25b10000.into(),
            name: "BasicRender.sys",
        },
        M {
            at: 0xfffff80d25b10000.into()..0xfffff80d25b2b000.into(),
            name: "Npfs.sys",
        },
        M {
            at: 0xfffff80d25b30000.into()..0xfffff80d25b40000.into(),
            name: "Msfs.sys",
        },
        M {
            at: 0xfffff80d25b40000.into()..0xfffff80d25b63000.into(),
            name: "tdx.sys",
        },
        M {
            at: 0xfffff80d25b70000.into()..0xfffff80d25b80000.into(),
            name: "TDI.sys",
        },
        M {
            at: 0xfffff80d25b80000.into()..0xfffff80d25bd4000.into(),
            name: "netbt.sys",
        },
        M {
            at: 0xfffff80d25be0000.into()..0xfffff80d25bf3000.into(),
            name: "afunix.sys",
        },
        M {
            at: 0xfffff80d25c00000.into()..0xfffff80d25c1a000.into(),
            name: "vwififlt.sys",
        },
        M {
            at: 0xfffff80d25c20000.into()..0xfffff80d25c49000.into(),
            name: "pacer.sys",
        },
        M {
            at: 0xfffff80d25c50000.into()..0xfffff80d25c62000.into(),
            name: "netbios.sys",
        },
        M {
            at: 0xfffff80d25c70000.into()..0xfffff80d25f14000.into(),
            name: "tcpip.sys",
        },
        M {
            at: 0xfffff80d25f20000.into()..0xfffff80d25f96000.into(),
            name: "fwpkclnt.sys",
        },
        M {
            at: 0xfffff80d25fa0000.into()..0xfffff80d25fcd000.into(),
            name: "wfplwfs.sys",
        },
        M {
            at: 0xfffff80d25fd0000.into()..0xfffff80d25fe2000.into(),
            name: "nsiproxy.sys",
        },
        M {
            at: 0xfffff80d25ff0000.into()..0xfffff80d25ffd000.into(),
            name: "npsvctrig.sys",
        },
        M {
            at: 0xfffff80d26200000.into()..0xfffff80d26245000.into(),
            name: "ahcache.sys",
        },
        M {
            at: 0xfffff80d26250000.into()..0xfffff80d26261000.into(),
            name: "CompositeBus.sys",
        },
        M {
            at: 0xfffff80d26270000.into()..0xfffff80d2627d000.into(),
            name: "kdnic.sys",
        },
        M {
            at: 0xfffff80d26280000.into()..0xfffff80d26295000.into(),
            name: "umbus.sys",
        },
        M {
            at: 0xfffff80d262a0000.into()..0xfffff80d262b3000.into(),
            name: "dmvsc.sys",
        },
        M {
            at: 0xfffff80d262c0000.into()..0xfffff80d262ce000.into(),
            name: "VMBusHID.sys",
        },
        M {
            at: 0xfffff80d262d0000.into()..0xfffff80d26303000.into(),
            name: "HIDCLASS.sys",
        },
        M {
            at: 0xfffff80d26310000.into()..0xfffff80d26323000.into(),
            name: "HIDPARSE.sys",
        },
        M {
            at: 0xfffff80d26330000.into()..0xfffff80d2633c000.into(),
            name: "hyperkbd.sys",
        },
        M {
            at: 0xfffff80d26340000.into()..0xfffff80d26353000.into(),
            name: "kbdclass.sys",
        },
        M {
            at: 0xfffff80d26360000.into()..0xfffff80d2636f000.into(),
            name: "HyperVideo.sys",
        },
        M {
            at: 0xfffff80d26370000.into()..0xfffff80d2637b000.into(),
            name: "vmgencounter.sys",
        },
        M {
            at: 0xfffff80d26380000.into()..0xfffff80d263bd000.into(),
            name: "intelppm.sys",
        },
        M {
            at: 0xfffff80d263c0000.into()..0xfffff80d263cd000.into(),
            name: "NdisVirtualBus.sys",
        },
        M {
            at: 0xfffff80d263d0000.into()..0xfffff80d263dc000.into(),
            name: "swenum.sys",
        },
        M {
            at: 0xfffff80d263e0000.into()..0xfffff80d2644b000.into(),
            name: "ks.sys",
        },
        M {
            at: 0xfffff80d26450000.into()..0xfffff80d2645e000.into(),
            name: "rdpbus.sys",
        },
        M {
            at: 0xfffff80d26460000.into()..0xfffff80d2646f000.into(),
            name: "mouhid.sys",
        },
        M {
            at: 0xfffff80d26470000.into()..0xfffff80d26481000.into(),
            name: "mouclass.sys",
        },
        M {
            at: 0xfffff80d26490000.into()..0xfffff80d264e6000.into(),
            name: "udfs.sys",
        },
        M {
            at: 0xfffff80d26500000.into()..0xfffff80d2650f000.into(),
            name: "dump_diskdump.sys",
        },
        M {
            at: 0xfffff80d26520000.into()..0xfffff80d2652f000.into(),
            name: "dump_storvsc.sys",
        },
        M {
            at: 0xfffff80d26530000.into()..0xfffff80d26549000.into(),
            name: "dump_vmbkmcl.sys",
        },
        M {
            at: 0xfffff80d26570000.into()..0xfffff80d2658d000.into(),
            name: "dump_dumpfve.sys",
        },
        M {
            at: 0xfffff80d26590000.into()..0xfffff80d265a1000.into(),
            name: "monitor.sys",
        },
        M {
            at: 0xfffff80d265b0000.into()..0xfffff80d26676000.into(),
            name: "dxgmms2.sys",
        },
        M {
            at: 0xfffff80d26680000.into()..0xfffff80d2668d000.into(),
            name: "rdpvideominiport.sys",
        },
        M {
            at: 0xfffff80d26690000.into()..0xfffff80d266c2000.into(),
            name: "rdpdr.sys",
        },
        M {
            at: 0xfffff80d266d0000.into()..0xfffff80d266f5000.into(),
            name: "tsusbhub.sys",
        },
        M {
            at: 0xfffff80d26700000.into()..0xfffff80d26727000.into(),
            name: "luafv.sys",
        },
        M {
            at: 0xfffff80d26730000.into()..0xfffff80d26758000.into(),
            name: "wcifs.sys",
        },
        M {
            at: 0xfffff80d26760000.into()..0xfffff80d267ce000.into(),
            name: "cldflt.sys",
        },
        M {
            at: 0xfffff80d267d0000.into()..0xfffff80d267e9000.into(),
            name: "storqosflt.sys",
        },
        M {
            at: 0xfffff80d267f0000.into()..0xfffff80d26811000.into(),
            name: "bowser.sys",
        },
        M {
            at: 0xfffff80d26820000.into()..0xfffff80d268a2000.into(),
            name: "mrxsmb.sys",
        },
        M {
            at: 0xfffff80d268b0000.into()..0xfffff80d268ed000.into(),
            name: "mrxsmb20.sys",
        },
        M {
            at: 0xfffff80d268f0000.into()..0xfffff80d26906000.into(),
            name: "lltdio.sys",
        },
        M {
            at: 0xfffff80d26910000.into()..0xfffff80d2692a000.into(),
            name: "mslldp.sys",
        },
        M {
            at: 0xfffff80d26930000.into()..0xfffff80d2694a000.into(),
            name: "rspndr.sys",
        },
        M {
            at: 0xfffff80d26950000.into()..0xfffff80d2696b000.into(),
            name: "wanarp.sys",
        },
        M {
            at: 0xfffff80d26970000.into()..0xfffff80d26a72000.into(),
            name: "HTTP.sys",
        },
        M {
            at: 0xfffff80d26a80000.into()..0xfffff80d26a99000.into(),
            name: "mpsdrv.sys",
        },
        M {
            at: 0xfffff80d26aa0000.into()..0xfffff80d26ab3000.into(),
            name: "mmcss.sys",
        },
        M {
            at: 0xfffff80d26ac0000.into()..0xfffff80d26ae7000.into(),
            name: "Ndu.sys",
        },
        M {
            at: 0xfffff80d26af0000.into()..0xfffff80d26b38000.into(),
            name: "srvnet.sys",
        },
        M {
            at: 0xfffff80d26b80000.into()..0xfffff80d26be0000.into(),
            name: "fastfat.sys",
        },
        M {
            at: 0xfffff80d26be0000.into()..0xfffff80d26bf4000.into(),
            name: "bam.sys",
        },
        M {
            at: 0xfffff80d26e00000.into()..0xfffff80d26ec0000.into(),
            name: "peauth.sys",
        },
        M {
            at: 0xfffff80d26ec0000.into()..0xfffff80d26ed3000.into(),
            name: "tcpipreg.sys",
        },
        M {
            at: 0xfffff80d26ee0000.into()..0xfffff80d26efb000.into(),
            name: "rassstp.sys",
        },
        M {
            at: 0xfffff80d26f00000.into()..0xfffff80d26f16000.into(),
            name: "NDProxy.sys",
        },
        M {
            at: 0xfffff80d26f20000.into()..0xfffff80d26f47000.into(),
            name: "AgileVpn.sys",
        },
        M {
            at: 0xfffff80d26f50000.into()..0xfffff80d26f70000.into(),
            name: "rasl2tp.sys",
        },
        M {
            at: 0xfffff80d26f70000.into()..0xfffff80d26f8f000.into(),
            name: "raspptp.sys",
        },
        M {
            at: 0xfffff80d26f90000.into()..0xfffff80d26fab000.into(),
            name: "raspppoe.sys",
        },
        M {
            at: 0xfffff80d26fb0000.into()..0xfffff80d26fbf000.into(),
            name: "ndistapi.sys",
        },
        M {
            at: 0xfffff80d26fc0000.into()..0xfffff80d26ff7000.into(),
            name: "ndiswan.sys",
        },
        M {
            at: 0xfffff80d27000000.into()..0xfffff80d27011000.into(),
            name: "WdNisDrv.sys",
        },
        M {
            at: 0xfffff80d27940000.into()..0xfffff80d279fc000.into(),
            name: "srv2.sys",
        },
    ];

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
        kernel_modules: &kernel_modules,
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
        kernel_modules: &kernel_modules,
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
        kernel_modules: &kernel_modules,
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
        assert!(compare_kernel_modules(&parser, test.kernel_modules));
    }
}
