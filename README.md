<div align='center'>
  <h1><code>kdmp-parser</code></h1>
  <p>
    <strong>A <a href="https://en.wikipedia.org/wiki/KISS_principle">KISS</a> Rust crate to parse Windows kernel crash-dumps created by Windows & its debugger.</strong>
  </p>
  <p>
    <img src="https://github.com/0vercl0k/kdmp-parser-rs/raw/main/pics/kdmp-parser.gif" />
    <a href="https://crates.io/crates/kdmp-parser"><img src="https://img.shields.io/crates/v/kdmp-parser.svg" /></a>
    <a href="https://docs.rs/kdmp-parser/"><img src="https://docs.rs/kdmp-parser/badge.svg"></a>
    <img src="https://github.com/0vercl0k/kdmp-parser-rs/workflows/Builds/badge.svg"/>
  </p>
</div>

This is a cross-platform crate that parses Windows **kernel** crash-dumps that Windows / WinDbg generates. It exposes read-only access to the physical memory pages as well as the register / exception context. It can also read virtual memory addresses by walking the [page tables](https://en.wikipedia.org/wiki/Page_table).

Compiled binaries are available in the [releases](https://github.com/0vercl0k/kdmp-parser-rs/releases) section.

## Parser
The [parser](src/examples/parser.rs) application is a small utility to show-case how to use the library and demonstrate its features. You can use it to dump memory, etc.

![parser-usage](https://github.com/0vercl0k/kdmp-parser-rs/raw/main/pics/parser.gif)

Here are the options supported:
```text
A KISS Rust crate to parse Windows kernel crash-dumps created by Windows & its debugger.

Usage: parser.exe [OPTIONS] <DUMP_PATH>

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

  -m, --mem[=<MEM>]
          Dump the first `len` bytes of every physical pages, unless an address is specified

      --virt
          The address specified is interpreted as a virtual address, not a physical address

      --len <LEN>
          The number of bytes to dump out

          [default: 16]

  -r, --reader <READER>
          Reader mode

          [default: mmap]

          Possible values:
          - mmap: The crash-dump is memory-mapped
          - file: The crash-dump is read as a file on disk

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
