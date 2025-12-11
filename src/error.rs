// Axel '0vercl0k' Souchet - March 19 2024
//! This is the error type used across the codebase.
use std::fmt::{self, Display};
use std::io;
use std::string::FromUtf16Error;

use crate::gxa::{Gpa, Gva};
use crate::structs::{DUMP_HEADER64_EXPECTED_SIGNATURE, DUMP_HEADER64_EXPECTED_VALID_DUMP};
pub type Result<R> = std::result::Result<R, Error>;

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

impl std::error::Error for PageReadError {}

/// Memory errors that can occur during memory reads.
///
/// There are several failure conditions that can happen while trying to read
/// virtual (or physical) memory out of a crash-dump that might not be obvious.
///
/// For example, consider reading two 4K pages from the virtual address
/// `0x1337_000`; it can fail because:
/// - The virtual address (the first 4K page) isn't present in the address space
///   at the [`PxeKind::Pde`] level: `PageReadError::NotPresent { gva:
///   0x1337_000, which_pxe: PxeKind::Pde })`
/// - The [`PxeKind::Pde`] that needs reading as part of the address translation
///   (of the first page) isn't part of the crash-dump: PageReadError::NotInDump
///   { gva: Some((0x1337_000, PxeKind::Pde)), gpa: .. })`
/// - The physical page backing that virtual address isn't included in the
///   crash-dump: `Error::PageRead(PageReadError::NotInDump { gva:
///   Some((0x1337_000, None)), gpa: .. })`
/// - Reading the second (and only the second) page failed because of any of the
///   previous reasons: `PartialRead { expected_amount: 8_192, actual_amount:
///   4_096, reason: PageReadError::.. }`
///
/// Similarly, for physical memory reads starting at `0x1337_000`:
/// - The physical page isn't in the crash-dump:
///   `MemoryError::PageRead(PageReadError::NotInDump { gpa: 0x1337_000 })`
/// - Reading the second page failed: `PartialRead { expected_amount: 8_192,
///   actual_amount: 4_096, reason: PageReadError::NotInDump { gva: None, gpa:
///   0x1338_000 } }`
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

#[derive(Debug)]
pub enum Error {
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
    PartialRead {
        expected_amount: usize,
        actual_amount: usize,
        reason: PageReadError,
    },
    PageRead(PageReadError),
}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<FromUtf16Error> for Error {
    fn from(value: FromUtf16Error) -> Self {
        Self::Utf16(value)
    }
}

impl From<PageReadError> for Error {
    fn from(value: PageReadError) -> Self {
        Self::PageRead(value)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUnicodeString => write!(f, "invalid UNICODE_STRING"),
            Self::Utf16(_) => write!(f, "utf16"),
            Self::Overflow(o) => write!(f, "overflow: {o}"),
            Self::Io(_) => write!(f, "io"),
            Self::InvalidData(i) => write!(f, "invalid data: {i}"),
            Self::UnknownDumpType(u) => write!(f, "unsupported dump type {u:#x}"),
            Self::DuplicateGpa(gpa) => {
                write!(f, "duplicate gpa found in physmem map for {gpa}")
            }
            Self::InvalidSignature(sig) => write!(
                f,
                "header's signature looks wrong: {sig:#x} vs {DUMP_HEADER64_EXPECTED_SIGNATURE:#x}"
            ),
            Self::InvalidValidDump(dump) => write!(
                f,
                "header's valid dump looks wrong: {dump:#x} vs {DUMP_HEADER64_EXPECTED_VALID_DUMP:#x}"
            ),
            Self::PhysAddrOverflow(run, page) => {
                write!(f, "overflow for phys addr w/ run {run} page {page}")
            }
            Self::PageOffsetOverflow(run, page) => {
                write!(f, "overflow for page offset w/ run {run} page {page}")
            }
            Self::BitmapPageOffsetOverflow(bitmap_idx, bit_idx) => write!(
                f,
                "overflow for page offset w/ bitmap_idx {bitmap_idx} bit_idx {bit_idx}"
            ),
            Self::PartialRead {
                expected_amount,
                actual_amount,
                reason,
            } => write!(
                f,
                "partially read {actual_amount} bytes out of {expected_amount} because of {reason}"
            ),
            Self::PageRead(p) => write!(f, "page read: {p}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Utf16(u) => Some(u),
            Self::Io(e) => Some(e),
            Self::PartialRead { reason, .. } => Some(reason),
            _ => None,
        }
    }
}
