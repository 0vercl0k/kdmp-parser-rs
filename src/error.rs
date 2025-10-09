// Axel '0vercl0k' Souchet - March 19 2024
//! This is the error type used across the codebase.
use std::error::Error;
use std::fmt::{self, Display};
use std::io;
use std::string::FromUtf16Error;

use crate::structs::{DUMP_HEADER64_EXPECTED_SIGNATURE, DUMP_HEADER64_EXPECTED_VALID_DUMP};
use crate::{Gpa, Gva};
pub type Result<R> = std::result::Result<R, KdmpParserError>;

#[derive(Debug)]
pub enum PxeNotPresent {
    Pml4e,
    Pdpte,
    Pde,
    Pte,
}

#[derive(Debug)]
pub enum AddrTranslationError {
    Virt(Gva, PxeNotPresent),
    Phys(Gpa),
}

impl Error for AddrTranslationError {}

impl Display for AddrTranslationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddrTranslationError::Virt(gva, not_pres) => {
                write!(f, "virt to phys translation of {gva}: {not_pres:?}")
            }
            AddrTranslationError::Phys(gpa) => write!(f, "phys to offset translation of {gpa}"),
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
    PartialPhysRead,
    PartialVirtRead,
    AddrTranslation(AddrTranslationError),
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

impl From<AddrTranslationError> for KdmpParserError {
    fn from(value: AddrTranslationError) -> Self {
        KdmpParserError::AddrTranslation(value)
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
            KdmpParserError::PartialPhysRead => write!(f, "partial physical memory read"),
            KdmpParserError::PartialVirtRead => write!(f, "partial virtual memory read"),
            KdmpParserError::AddrTranslation(_) => write!(f, "memory translation"),
        }
    }
}

impl Error for KdmpParserError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            KdmpParserError::Utf16(u) => Some(u),
            KdmpParserError::Io(e) => Some(e),
            KdmpParserError::AddrTranslation(a) => Some(a),
            _ => None,
        }
    }
}
