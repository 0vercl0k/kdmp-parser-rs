// Axel '0vercl0k' Souchet - February 25 2024
#![allow(clippy::doc_markdown)]
#![doc = include_str!("../README.md")]
mod bits;
mod error;
mod gxa;
mod map;
mod parse;
mod phys;
mod pxe;
mod structs;
mod virt;
mod virt_utils;

pub use bits::Bits;
pub use error::{KdmpParserError, PageReadError, PxeKind, Result};
pub use gxa::{Gpa, Gva, Gxa};
pub use map::{MappedFileReader, Reader};
pub use parse::KernelDumpParser;
pub use pxe::{Pfn, Pxe, PxeFlags};
pub use structs::{Context, DumpType, Header64, PageKind};
