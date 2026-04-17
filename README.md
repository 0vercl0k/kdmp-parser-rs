<div align='center'>
  <h1><code>kdmp-parser</code></h1>
  <p>
    <strong>A <a href="https://en.wikipedia.org/wiki/KISS_principle">KISS</a>, dependency free, Rust crate to parse Windows kernel crash-dumps created by Windows & its debugger.</strong>
  </p>
  <p>
    <a href="https://crates.io/crates/kdmp-parser"><img src="https://img.shields.io/crates/v/kdmp-parser.svg" /></a>
    <a href="https://docs.rs/kdmp-parser/"><img src="https://docs.rs/kdmp-parser/badge.svg"></a>
    <img src="https://github.com/0vercl0k/kdmp-parser-rs/workflows/Builds/badge.svg"/>
  </p>
  <p>
    <img src="https://github.com/0vercl0k/kdmp-parser-rs/raw/main/pics/kdmp-parser.gif" />
  </p>
</div>

This is a cross-platform crate that parses Windows **kernel** crash-dumps that Windows / WinDbg generates. It exposes read-only access to the physical memory pages as well as the register / exception context. It can also read virtual memory addresses by walking the [page tables](https://en.wikipedia.org/wiki/Page_table).

Compiled binaries are available in the [releases](https://github.com/0vercl0k/kdmp-parser-rs/releases) section.

## How to use?

It starts by parsing a crash-dump file with by creating a [`KernelDumpParser`](https://docs.rs/kdmp-parser/latest/kdmp_parser/parse/struct.KernelDumpParser.html). It gives you access to lists of where user / kernel mode modules are loaded at, as well as their names. It also gives you access to the physical memory pages found in the crash-dump.

To read the physical memory space, use [`phys::Reader`](https://docs.rs/kdmp-parser/latest/kdmp_parser/phys/struct.Reader.html) and [`virt::Reader`](https://docs.rs/kdmp-parser/latest/kdmp_parser/virt/struct.Reader.html) to read the virtual memory space.

Reading the physical or the virtual memory space from a crash-dump can fail because a page that might have been resident in memory when the crash happened, might not have been captured in the dump file; so you're left with a hole. Reading the virtual memory space is even worse because accessing one byte of virtual memory means that you need to read multiple physical pages (as part of the virtual to physical translation) and any of those pages might not exist in the crash-dump.

If you prefer to read and ignore those memory errors, use [`virt::Reader::read`](https://docs.rs/kdmp-parser/latest/kdmp_parser/virt/struct.Reader.html#method.read). It won't tell you why it might have failed to read as much as you wanted, but it will tell you how many bytes it successfully read. Similarly, if you want it to read a fixed amount of bytes (and still ignore memory read errors), use [`virt::Reader::try_read_exact`](https://docs.rs/kdmp-parser/latest/kdmp_parser/virt/struct.Reader.html#method.try_read_exact).

If you care to know why a virtual translation failed, or why it wasn't able to read a certain page; use [`virt::Reader::read_exact`](https://docs.rs/kdmp-parser/latest/kdmp_parser/virt/struct.Reader.html#method.read_exact).

## Parser

The [parser](src/examples/parser.rs) application is a small utility to show-case how to use the library and demonstrate its features. You can use it to dump memory, etc.

![parser-usage](https://github.com/0vercl0k/kdmp-parser-rs/raw/main/pics/parser.gif)

Here are the options supported:

```text
A KISS, dependency free, Rust crate to parse Windows kernel crash-dumps created by Windows & its debugger.

Usage: parser.exe [OPTIONS] -- <DUMP_PATH>

Arguments:
  <DUMP_PATH>
          The dump path

Options:
      --dump-headers
          Dump the dump headers

  -c, --context-record
          Dump the context record

  -e, --exception-record
          Dump the exception record

  -m, --mem [<MEM>]
          Dump the first `len` bytes of every physical pages, unless an address is specified

      --virt
          The address specified is interpreted as a virtual address, not a physical address

      --len <LEN>
          The number of bytes to dump out

          [default: 128]

      --dtb <DTB>
          Directory table base address to use for virtual memory translations

  -r, --reader <READER>
          Reader mode

          Possible values:
          - mmap: The crash-dump is memory-mapped
          - file: The crash-dump is read as a file on disk

          [default: mmap]

      --modules
          Dump the list of kernel & user modules

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```

# Authors

* Axel '[@0vercl0k](https://twitter.com/0vercl0k)' Souchet

# Contributors

[ ![contributors-img](https://contrib.rocks/image?repo=0vercl0k/kdmp-parser-rs) ](https://github.com/0vercl0k/kdmp-parser-rs/graphs/contributors)
