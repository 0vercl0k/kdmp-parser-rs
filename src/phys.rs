// Axel '0vercl0k' Souchet - Novvember 9 2025
use core::slice;
use std::cmp::min;
use std::io::SeekFrom;
use std::mem::MaybeUninit;

use crate::error::{Error, PageReadError, Result};
use crate::gxa::{Gpa, Gxa};
use crate::parse::KernelDumpParser;
use crate::structs::PageKind;

pub struct Reader<'parser> {
    parser: &'parser KernelDumpParser,
}

impl<'parser> Reader<'parser> {
    pub fn new(parser: &'parser KernelDumpParser) -> Self {
        Self { parser }
    }

    /// Translate a [`Gpa`] into a file offset of where the content of the page
    /// resides in.
    ///
    /// # Errors
    ///
    /// Returns an error if the `gpa` has no backing page or if an integer
    /// overflow is triggered while calculating where in the input file the
    /// backing page is at.
    pub fn translate(&self, gpa: Gpa) -> Result<SeekFrom> {
        let Some(base_offset) = self.parser.physmem.get(&gpa.page_align()) else {
            return Err(PageReadError::NotInDump { gva: None, gpa }.into());
        };

        base_offset
            .checked_add(gpa.offset())
            .map(SeekFrom::Start)
            .ok_or(Error::Overflow("w/ gpa offset"))
    }

    /// Read physical memory starting at `gpa` into a `buffer`.
    pub fn read_exact(&self, gpa: Gpa, buf: &mut [u8]) -> Result<()> {
        // Amount of bytes left to read.
        let mut amount_left = buf.len();
        // Total amount of bytes that we have successfully read.
        let mut total_read = 0;
        // The current gpa we are reading from.
        let mut addr = gpa;
        // Let's try to read as much as the user wants.
        while amount_left > 0 {
            // Translate the gpa into a file offset..
            let offset = match self.translate(addr) {
                Ok(o) => o,
                Err(Error::PageRead(PageReadError::NotInDump { gva: None, gpa })) => {
                    return Err(Error::PartialRead {
                        expected_amount: buf.len(),
                        actual_amount: total_read,
                        reason: PageReadError::NotInDump { gva: None, gpa },
                    });
                }
                Err(Error::PageRead(_)) => {
                    // We should never get there; `translate` can only fail with a `PageRead` error
                    // if and only if the gpa doesn't exist in the dump.
                    unreachable!();
                }
                Err(e) => return Err(e),
            };
            // ..and seek the reader there.
            self.parser.seek(offset)?;
            // We need to take care of reads that straddle different physical memory pages.
            // So let's figure out the maximum amount of bytes we can read off this page.
            // Either, we read it until its end, or we stop if the user wants us to read
            // less.
            let left_in_page = usize::try_from(PageKind::Normal.size() - gpa.offset()).unwrap();
            let amount_wanted = min(amount_left, left_in_page);
            // Figure out where we should read into.
            let slice = &mut buf[total_read..total_read + amount_wanted];
            // Read the physical memory!
            self.parser.read_exact(slice)?;
            // Update the total amount of read bytes and how much work we have left.
            total_read += amount_wanted;
            amount_left -= amount_wanted;
            // We have more work to do, so let's move to the next page.
            addr = addr.next_aligned_page();
        }

        // Yay, we read as much bytes as the user wanted!
        Ok(())
    }

    pub fn read(&self, gpa: Gpa, buf: &mut [u8]) -> Result<usize> {
        match self.read_exact(gpa, buf) {
            Ok(()) => Ok(buf.len()),
            Err(Error::PartialRead { actual_amount, .. }) => Ok(actual_amount),
            Err(e) => Err(e),
        }
    }

    /// Read a `T` from physical memory.
    pub fn read_struct<T>(&self, gpa: Gpa) -> Result<T> {
        let mut t: MaybeUninit<T> = MaybeUninit::uninit();
        let size_of_t = size_of_val(&t);
        let slice_over_t =
            unsafe { slice::from_raw_parts_mut(t.as_mut_ptr().cast::<u8>(), size_of_t) };

        self.read_exact(gpa, slice_over_t)?;

        Ok(unsafe { t.assume_init() })
    }
}
