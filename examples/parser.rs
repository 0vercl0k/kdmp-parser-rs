// Axel '0vercl0k' Souchet - February 25 2024
use core::default::Default;
use std::cmp::min;
use std::collections::BTreeMap;
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
    #[arg(short, long, num_args = 0..=1, default_missing_value = "0xffffffffffffffff")]
    mem: Option<String>,
    /// The address specified is interpreted as a virtual address, not a
    /// physical address.
    #[arg(long, default_value_t = false)]
    virt: bool,
    /// The number of bytes to dump out.
    #[arg(long, default_value_t = 0x10)]
    len: usize,
    /// Directory table base address to use for virtual memory translations.
    #[arg(long)]
    dtb: Option<Gpa>,
    /// Reader mode.
    #[arg(short, long, value_enum, default_value_t = ReaderMode::Mmap)]
    reader: ReaderMode,
    /// Dump the list of kernel & user modules.
    #[arg(long, default_value_t = false)]
    modules: bool,
}

/// Print a hexdump of data that started at `address` (unmapped memory is
/// displayed with `??`).
fn hexdump(address: u64, data: &[u8], wanted_len: usize) {
    let mut row = [None; 16];
    let mut data_it = data.iter();
    for i in (0..wanted_len).step_by(16) {
        // Calculate how many bytes we have left to print.
        let wanted_left = wanted_len - i;
        // Do we need a full row or less?
        let left_to_display = min(wanted_left, 16);
        print!("{:016x}: ", address + (i as u64 * 16));

        // Iterate over the row now and populate it with the data. We do this because
        // the output first displays the hexadecimal value of every bytes, and then its
        // ASCII representation.
        let mut row_it = row.iter_mut().enumerate().peekable();
        while let Some((idx, item)) = row_it.next() {
            // Drain the data iterator byte by byte and fill the row with the data.
            match data_it.next() {
                Some(c) => {
                    // If we have a byte, then easy peasy.
                    *item = Some(*c);
                    print!("{:02x}", c);
                }
                None => {
                    *item = None;
                    // If we don't have a byte, then we need to figure out what to do. There are two
                    // cases to take care of:
                    let displayed_amount = i + idx;
                    if displayed_amount >= wanted_len {
                        // - either what is left to display is not a full row, in which case we need
                        //   to display spaces to padd the output such that the upcoming ASCII
                        //   representation stays aligned.
                        print!("  ");
                    } else {
                        // - either the user asked a larger length than what is mapped in memory, in
                        //   which case we need to display `??` for those bytes.
                        print!("??");
                    }
                }
            };

            // We separate half of the row with a dash. But we only want to display it if
            // there'll be at least one byte after it (so at least 9 bytes to display in
            // this row; otherwise it'd be surrounded by spaces which looks odd).
            if left_to_display >= 9 && idx == 7 {
                print!("-");
            } else if row_it.peek().is_some() {
                print!(" ");
            }
        }

        // Now print the ASCII representation of the row (full or smaller).
        print!("  ");
        for item in &row[..left_to_display] {
            if let Some(c) = item {
                let c = char::from(*c);
                print!("{}", if c.is_ascii_graphic() { c } else { '.' });
            } else {
                print!("?");
            }
        }
        println!()
    }
}

/// Convert an hexadecimal string to a `u64`.
fn to_hex(s: &str) -> Result<u64> {
    let s = s.replace('`', "");

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
        println!("{:#?}", parser.headers());
    }

    if args.context_record {
        println!("{:#x?}", parser.context_record());
    }

    if args.exception_record {
        println!("{:#x?}", parser.exception_record());
    }

    if args.modules {
        let modules = parser
            .user_modules()
            .chain(parser.kernel_modules())
            .map(|(at, v)| (at.start, (v, at.end)))
            .collect::<BTreeMap<_, _>>();

        for (start, (module, end)) in modules {
            println!("{:#018x}-{:#018x}: {module}", start.u64(), end.u64());
        }
    }

    if let Some(addr) = args.mem {
        let mut buffer = vec![0; args.len];
        let addr = to_hex(&addr)?;
        if addr == u64::MAX {
            for (gpa, _) in parser.physmem() {
                parser.phys_read_exact(gpa, &mut buffer)?;
                hexdump(gpa.u64(), &buffer, args.len)
            }
        } else {
            let amount = if args.virt {
                parser.virt_read_with_dtb(
                    Gva::new(addr),
                    &mut buffer,
                    args.dtb
                        .unwrap_or(Gpa::new(parser.headers().directory_table_base)),
                )
            } else {
                parser.phys_read(Gpa::new(addr), &mut buffer)
            };

            if let Ok(amount) = amount {
                hexdump(addr, &buffer[..amount], args.len);
            } else {
                println!(
                    "There is no {} memory available at {addr:#x}",
                    if args.virt { "virtual" } else { "physical" }
                );
            }
        }
    }

    Ok(())
}
