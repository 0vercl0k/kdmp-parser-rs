// Axel '0vercl0k' Souchet - February 25 2024
use core::default::Default;
use std::fs::File;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use kdmp_parser::{Gpa, Gva, Gxa, KernelDumpParser, MappedFileReader};

#[derive(Debug, Default, Clone, Copy, ValueEnum)]
enum ReaderMode {
    #[default]
    /// The crash-dump is memory-mapped.
    Mmap,
    /// The crash-dump is read as a file on disk.
    File,
}

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// The dump path.
    dump_path: PathBuf,
    /// Dump the dump headers.
    #[arg(long, default_value_t = false)]
    dump_headers: bool,
    /// Dump the context record.
    #[arg(short, long)]
    context_record: bool,
    /// Dump the exception record.
    #[arg(short, long)]
    exception_record: bool,
    /// Dump the first `len` bytes of every physical pages, unless an address is
    /// specified.
    #[arg(short, long, num_args = 0..=1, require_equals = true, default_missing_value = "0xffffffffffffffff")]
    mem: Option<String>,
    /// The address specified is interpreted as a virtual address, not a
    /// physical address.
    #[arg(long, default_value_t = false)]
    virt: bool,
    /// The number of bytes to dump out.
    #[arg(long, default_value_t = 0x10)]
    len: usize,
    /// Reader mode.
    #[arg(short, long, value_enum, default_value_t = ReaderMode::Mmap)]
    reader: ReaderMode,
    /// Dump the list of kernel & user modules.
    #[arg(long, default_value_t = false)]
    modules: bool,
}

/// Print a hexdump of data that started at `address`.
fn hexdump(address: u64, data: &[u8]) {
    let len = data.len();
    let mut it = data.iter();
    for i in (0..len).step_by(16) {
        print!("{:016x}: ", address + (i as u64 * 16));
        let mut row = [None; 16];
        for item in row.iter_mut() {
            if let Some(c) = it.next() {
                *item = Some(*c);
                print!("{:02x}", c);
            } else {
                print!(" ");
            }
        }
        print!(" |");
        for item in &row {
            if let Some(c) = item {
                let c = char::from(*c);
                print!("{}", if c.is_ascii_graphic() { c } else { '.' });
            } else {
                print!(" ");
            }
        }
        println!("|");
    }
}

/// Convert an hexadecimal string to a `u64`.
fn to_hex(s: &str) -> Result<u64> {
    u64::from_str_radix(s.trim_start_matches("0x"), 16).context("failed to convert string to u64")
}

fn main() -> Result<()> {
    let args = Args::parse();
    let parser = match args.reader {
        ReaderMode::Mmap => {
            let mapped_file = MappedFileReader::new(args.dump_path)?;
            KernelDumpParser::with_reader(mapped_file)
        }
        ReaderMode::File => {
            let file = File::open(args.dump_path)?;
            KernelDumpParser::with_reader(file)
        }
    }
    .context("failed to parse the kernel dump")?;

    if args.dump_headers {
        println!("{:?}", parser.headers());
    }

    if args.context_record {
        println!("{:#x?}", parser.context_record());
    }

    if args.exception_record {
        println!("{:#x?}", parser.exception_record());
    }

    if args.modules {
        for (at, module) in parser.user_modules().chain(parser.wow64_user_modules()).chain(parser.kernel_modules()) {
            println!("{:#x}-{:#x}: {module}", at.start.u64(), at.end.u64());
        }
    }

    if let Some(addr) = args.mem {
        let mut buffer = vec![0; args.len];
        let addr = to_hex(&addr)?;
        if addr == u64::MAX {
            for (gpa, _) in parser.physmem() {
                parser.phys_read_exact(gpa, &mut buffer)?;
                hexdump(gpa.u64(), &buffer)
            }
        } else {
            let amount = if args.virt {
                parser.virt_read(Gva::new(addr), &mut buffer)
            } else {
                parser.phys_read(Gpa::new(addr), &mut buffer)
            };

            if let Ok(amount) = amount {
                hexdump(addr, &buffer[..amount]);
            } else {
                println!(
                    "There is no {} memory available for {addr:#x}",
                    if args.virt { "virtual" } else { "physical" }
                );
            }
        }
    }

    Ok(())
}
