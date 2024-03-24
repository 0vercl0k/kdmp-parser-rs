// Axel '0vercl0k' Souchet - March 19 2024
//! This is the error type used across the codebase.
use std::{io, string};

use thiserror::Error;

use crate::structs::{HEADER64_EXPECTED_SIGNATURE, HEADER64_EXPECTED_VALID_DUMP};
use crate::{Gpa, Gva};
pub type Result<R> = std::result::Result<R, KdmpParserError>;

#[derive(Error, Debug)]
pub enum KdmpParserError {
    #[error("invalid UNICODE_STRING")]
    InvalidUnicodeString,
    #[error("utf16: {0}")]
    Utf16(#[from] string::FromUtf16Error),
    #[error("overflow: {0}")]
    Overflow(&'static str),
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("invalid data: {0}")]
    InvalidData(&'static str),
    #[error("unsupported dump type {0:#x}")]
    UnknownDumpType(u32),
    #[error("duplicate gpa found in physmem map for {0}")]
    DuplicateGpa(Gpa),
    #[error("header's signature looks wrong: {0:#x} vs {HEADER64_EXPECTED_SIGNATURE:#x}")]
    InvalidSignature(u32),
    #[error("header's valid dump looks wrong: {0:#x} vs {HEADER64_EXPECTED_VALID_DUMP:#x}")]
    InvalidValidDump(u32),
    #[error("overflow for phys addr w/ run {0} page {1}")]
    PhysAddrOverflow(u32, u64),
    #[error("overflow for page offset w/ run {0} page {1}")]
    PageOffsetOverflow(u32, u64),
    #[error("overflow for page offset w/ bitmap_idx {0} bit_idx {1}")]
    BitmapPageOffsetOverflow(u64, usize),
    #[error("partial physical memory read")]
    PartialPhysRead,
    #[error("partial virtual memory read")]
    PartialVirtRead,
    #[error("phys translation of {0}")]
    PhysTranslate(Gpa),
    #[error("virt to phys translation of {0}")]
    VirtTranslate(Gva),
}
