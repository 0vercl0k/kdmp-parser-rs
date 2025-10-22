// Axel '0vercl0k' Souchet - March 19 2024
//! This is the error type used across the codebase.
use std::error::Error;
use std::fmt::{self, Display};
use std::io;
use std::string::FromUtf16Error;

use crate::structs::{DUMP_HEADER64_EXPECTED_SIGNATURE, DUMP_HEADER64_EXPECTED_VALID_DUMP};
use crate::{Gpa, Gva};
pub type Result<R> = std::result::Result<R, KdmpParserError>;

/// Identifies which page table entry level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PxeKind {
    Pml4e,
    Pdpte,
    Pde,
    Pte,
}

/// Represent the fundamental reason a single page read can fail.
#[derive(Debug, Clone)]
pub enum PageReadError {
    /// Virtual address translation failed because a page table entry is not
    /// present (it exists in the dump but is marked as not present).
    NotPresent { gva: Gva, which_pxe: PxeKind },
    /// A physical page is missing from the dump.
    NotInDump {
        gva: Option<(Gva, Option<PxeKind>)>,
        gpa: Gpa,
    },
}

impl Error for PageReadError {}

/// Recoverable memory errors that can occur during memory reads.
///
/// There are several failure conditions that can happen while trying to read
/// virtual (or physical) memory out of a crash-dump that might not be obvious.
///
/// For example, consider reading two 4K pages from the virtual address
/// `0x1337_000`; it can fail because:
/// - The virtual address (the first 4K page) isn't present in the address space
///   at the `Pde` level: `MemoryReadError::PageRead(PageReadError::NotPresent {
///   gva: 0x1337_000, which_pxe: PxeKind::Pde })`
/// - The `Pde` that needs reading as part of the address translation (of the
///   first page) isn't part of the crash-dump:
///   `MemoryReadError::PageRead(PageReadError::NotInDump { gva:
///   Some((0x1337_000, PxeKind::Pde)), gpa: .. })`
/// - The physical page backing that virtual address isn't included in the
///   crash-dump: `MemoryReadError::PageRead(PageReadError::NotInDump { gva:
///   Some((0x1337_000, None)), gpa: .. })`
/// - Reading the second (and only the second) page failed because of any of the
///   previous reasons: `MemoryReadError::PartialRead { expected_amount: 8_192,
///   actual_amount: 4_096, reason: PageReadError::.. }`
///
/// Similarly, for physical memory reads starting at `0x1337_000`:
/// - A direct physical page isn't in the crash-dump:
///   `MemoryError::PageRead(PageReadError::NotInDump { gpa: 0x1337_000 })`
/// - Reading the second page failed: `MemoryError::PartialRead {
///   expected_amount: 8_192, actual_amount: 4_096, reason:
///   PageReadError::NotInDump { gva: None, gpa: 0x1338_000 } }`
///
/// We consider any of those errors 'recoverable' which means that we won't even
/// bubble those up to the callers with the regular APIs. Only the `strict`
/// versions will.
#[derive(Debug, Clone)]
pub enum MemoryReadError {
    /// A single page/read failed.
    PageRead(PageReadError),
    /// A read request was only partially fulfilled.
    PartialRead {
        expected_amount: usize,
        actual_amount: usize,
        reason: PageReadError,
    },
}

impl Display for PageReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PageReadError::NotPresent { gva, which_pxe } => {
                write!(f, "{gva} isn't present at the {which_pxe:?} level")
            }
            PageReadError::NotInDump { gva, gpa } => match gva {
                Some((gva, Some(which_pxe))) => write!(
                    f,
                    "{gpa} was needed while translating {gva} at the {which_pxe:?} level but is missing from the dump)"
                ),
                Some((gva, None)) => write!(f, "{gpa} backs {gva} but is missing from the dump)"),
                None => {
                    write!(f, "{gpa} is missing from the dump)")
                }
            },
        }
    }
}

impl Error for MemoryReadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            MemoryReadError::PageRead(e) => Some(e),
            MemoryReadError::PartialRead { reason, .. } => Some(reason),
        }
    }
}

impl Display for MemoryReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MemoryReadError::PageRead(_) => write!(f, "page read"),
            MemoryReadError::PartialRead {
                expected_amount,
                actual_amount,
                ..
            } => {
                write!(
                    f,
                    "partially read {actual_amount} off {expected_amount} wanted bytes"
                )
            }
        }
    }
}

#[derive(Debug)]
pub enum KdmpParserError {
    InvalidUnicodeString,
    Utf16(FromUtf16Error),
    Overflow(&'static str),
    Io(io::Error),
    InvalidData(&'static str),
    UnknownDumpType(u32),
    DuplicateGpa(Gpa),
    InvalidSignature(u32),
    InvalidValidDump(u32),
    PhysAddrOverflow(u32, u64),
    PageOffsetOverflow(u32, u64),
    BitmapPageOffsetOverflow(u64, usize),
    MemoryRead(MemoryReadError),
}

impl From<io::Error> for KdmpParserError {
    fn from(value: io::Error) -> Self {
        KdmpParserError::Io(value)
    }
}

impl From<FromUtf16Error> for KdmpParserError {
    fn from(value: FromUtf16Error) -> Self {
        KdmpParserError::Utf16(value)
    }
}

impl From<MemoryReadError> for KdmpParserError {
    fn from(value: MemoryReadError) -> Self {
        KdmpParserError::MemoryRead(value)
    }
}

impl From<PageReadError> for KdmpParserError {
    fn from(value: PageReadError) -> Self {
        Self::MemoryRead(MemoryReadError::PageRead(value))
    }
}

impl Display for KdmpParserError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KdmpParserError::InvalidUnicodeString => write!(f, "invalid UNICODE_STRING"),
            KdmpParserError::Utf16(_) => write!(f, "utf16"),
            KdmpParserError::Overflow(o) => write!(f, "overflow: {o}"),
            KdmpParserError::Io(_) => write!(f, "io"),
            KdmpParserError::InvalidData(i) => write!(f, "invalid data: {i}"),
            KdmpParserError::UnknownDumpType(u) => write!(f, "unsupported dump type {u:#x}"),
            KdmpParserError::DuplicateGpa(gpa) => {
                write!(f, "duplicate gpa found in physmem map for {gpa}")
            }
            KdmpParserError::InvalidSignature(sig) => write!(
                f,
                "header's signature looks wrong: {sig:#x} vs {DUMP_HEADER64_EXPECTED_SIGNATURE:#x}"
            ),
            KdmpParserError::InvalidValidDump(dump) => write!(
                f,
                "header's valid dump looks wrong: {dump:#x} vs {DUMP_HEADER64_EXPECTED_VALID_DUMP:#x}"
            ),
            KdmpParserError::PhysAddrOverflow(run, page) => {
                write!(f, "overflow for phys addr w/ run {run} page {page}")
            }
            KdmpParserError::PageOffsetOverflow(run, page) => {
                write!(f, "overflow for page offset w/ run {run} page {page}")
            }
            KdmpParserError::BitmapPageOffsetOverflow(bitmap_idx, bit_idx) => write!(
                f,
                "overflow for page offset w/ bitmap_idx {bitmap_idx} bit_idx {bit_idx}"
            ),
            KdmpParserError::MemoryRead(_) => write!(f, "memory read"),
        }
    }
}

impl Error for KdmpParserError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            KdmpParserError::Utf16(u) => Some(u),
            KdmpParserError::Io(e) => Some(e),
            KdmpParserError::MemoryRead(m) => Some(m),
            _ => None,
        }
    }
}
