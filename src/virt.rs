// Axel '0vercl0k' Souchet - November 9 2025
use core::slice;
use std::cmp::min;
use std::mem::MaybeUninit;

use crate::error::{Error, PageReadError, PxeKind, Result};
use crate::gxa::{Gpa, Gva, Gxa};
use crate::parse::KernelDumpParser;
use crate::phys;
use crate::pxe::{Pfn, Pxe};
use crate::structs::{PageKind, Pod};

/// The details related to a virtual to physical address translation.
///
/// If you are wondering why there is no 'readable' field, it is because
/// [`Reader::translate`] returns an error if one of the PXE is
/// marked as not present. In other words, if the translation succeeds, the page
/// is at least readable.
#[derive(Debug)]
pub struct Translation {
    /// The physical address backing the virtual address that was requested.
    pub pfn: Pfn,
    /// The byte offset in that physical page.
    pub offset: u64,
    /// The kind of physical page.
    pub page_kind: PageKind,
    /// Is the page writable?
    pub writable: bool,
    /// Is the page executable?
    pub executable: bool,
    /// Is the page user accessible?
    pub user_accessible: bool,
}

impl Translation {
    #[must_use]
    pub fn huge_page(pxes: &[Pxe; 2], gva: Gva) -> Self {
        Self::inner_new(pxes, gva)
    }

    #[must_use]
    pub fn large_page(pxes: &[Pxe; 3], gva: Gva) -> Self {
        Self::inner_new(pxes, gva)
    }

    #[must_use]
    pub fn new(pxes: &[Pxe; 4], gva: Gva) -> Self {
        Self::inner_new(pxes, gva)
    }

    /// Create a new instance from a slice of PXEs and the original GVA.
    fn inner_new(pxes: &[Pxe], gva: Gva) -> Self {
        let writable = pxes.iter().all(Pxe::writable);
        let executable = pxes.iter().all(Pxe::executable);
        let user_accessible = pxes.iter().all(Pxe::user_accessible);
        let pfn = pxes.last().map(|p| p.pfn).expect("at least one pxe");
        let page_kind = match pxes.len() {
            4 => PageKind::Normal,
            3 => PageKind::Large,
            2 => PageKind::Huge,
            _ => unreachable!("pxes len should be between 2 and 4"),
        };
        let offset = page_kind.page_offset(gva.u64());

        Self {
            pfn,
            offset,
            page_kind,
            writable,
            executable,
            user_accessible,
        }
    }

    #[must_use]
    pub fn gpa(&self) -> Gpa {
        self.pfn.gpa_with_offset(self.offset)
    }
}

pub fn ignore_non_fatal<T>(r: Result<T>) -> Result<Option<T>> {
    match r {
        Ok(o) => Ok(Some(o)),
        Err(Error::PageRead(_) | Error::PartialRead { .. }) => Ok(None),
        Err(e) => Err(e),
    }
}

pub struct Reader<'parser> {
    parser: &'parser KernelDumpParser,
    dtb: Gpa,
}

impl<'parser> Reader<'parser> {
    pub fn new(parser: &'parser KernelDumpParser) -> Self {
        Self::with_dtb(parser, Gpa::new(parser.headers().directory_table_base))
    }

    pub fn with_dtb(parser: &'parser KernelDumpParser, dtb: Gpa) -> Self {
        Self { parser, dtb }
    }

    /// Translate a [`Gva`] into a [`Gpa`] using a specific directory table base
    /// / set of page tables.
    #[expect(clippy::similar_names)]
    pub fn translate(&self, gva: Gva) -> Result<Translation> {
        let read_pxe = |gpa: Gpa, pxe: PxeKind| -> Result<Pxe> {
            let r = phys::Reader::new(self.parser);
            let Ok(pxe) = r.read_struct::<u64>(gpa).map(Pxe::from) else {
                // If the physical page isn't in the dump, enrich the error by adding the gva
                // that was getting translated as well as the pxe level we were at.
                return Err(PageReadError::NotInDump {
                    gva: Some((gva, Some(pxe))),
                    gpa,
                }
                .into());
            };

            Ok(pxe)
        };

        // Aligning in case PCID bits are set (bits 11:0)
        let pml4_base = self.dtb.page_align();
        let pml4e_gpa = Gpa::new(pml4_base.u64() + (gva.pml4e_idx() * 8));
        let pml4e = read_pxe(pml4e_gpa, PxeKind::Pml4e)?;
        if !pml4e.present() {
            return Err(PageReadError::NotPresent {
                gva,
                which_pxe: PxeKind::Pml4e,
            }
            .into());
        }

        let pdpt_base = pml4e.pfn.gpa();
        let pdpte_gpa = Gpa::new(pdpt_base.u64() + (gva.pdpe_idx() * 8));
        let pdpte = read_pxe(pdpte_gpa, PxeKind::Pdpte)?;
        if !pdpte.present() {
            return Err(PageReadError::NotPresent {
                gva,
                which_pxe: PxeKind::Pdpte,
            }
            .into());
        }

        // huge pages:
        // 7 (PS) - Page size; must be 1 (otherwise, this entry references a page
        // directory; see Table 4-1.
        let pd_base = pdpte.pfn.gpa();
        if pdpte.large_page() {
            return Ok(Translation::huge_page(&[pml4e, pdpte], gva));
        }

        let pde_gpa = Gpa::new(pd_base.u64() + (gva.pde_idx() * 8));
        let pde = read_pxe(pde_gpa, PxeKind::Pde)?;
        if !pde.present() {
            return Err(PageReadError::NotPresent {
                gva,
                which_pxe: PxeKind::Pde,
            }
            .into());
        }

        // large pages:
        // 7 (PS) - Page size; must be 1 (otherwise, this entry references a page
        // table; see Table 4-18.
        let pt_base = pde.pfn.gpa();
        if pde.large_page() {
            return Ok(Translation::large_page(&[pml4e, pdpte, pde], gva));
        }

        let pte_gpa = Gpa::new(pt_base.u64() + (gva.pte_idx() * 8));
        let pte = read_pxe(pte_gpa, PxeKind::Pte)?;
        if !pte.present() {
            // We'll allow reading from a transition PTE, so return an error only if it's
            // not one, otherwise we'll carry on.
            if !pte.transition() {
                return Err(PageReadError::NotPresent {
                    gva,
                    which_pxe: PxeKind::Pte,
                }
                .into());
            }
        }

        Ok(Translation::new(&[pml4e, pdpte, pde, pte], gva))
    }

    pub fn read(&self, gva: Gva, buf: &mut [u8]) -> Result<usize> {
        match self.read_exact(gva, buf) {
            Ok(()) => Ok(buf.len()),
            Err(Error::PartialRead { actual_amount, .. }) => Ok(actual_amount),
            Err(e) => Err(e),
        }
    }

    /// Read virtual memory starting at `gva` into a `buffer` using a specific
    /// directory table base / set of page tables, propagating all errors
    /// including memory errors.
    // why Option<usize>? if page not present or not in dump, None, otherwise usize
    pub fn read_exact(&self, gva: Gva, buf: &mut [u8]) -> Result<()> {
        // Amount of bytes left to read.
        let mut amount_left = buf.len();
        // Total amount of bytes that we have successfully read.
        let mut total_read = 0;
        // The current gva we are reading from.
        let mut addr = gva;
        // Let's try to read as much as the user wants.
        while amount_left > 0 {
            // Translate the gva into a gpa.
            let translation = match self.translate(addr) {
                Ok(t) => t,
                Err(Error::PageRead(reason)) => {
                    return Err(Error::PartialRead {
                        expected_amount: buf.len(),
                        actual_amount: total_read,
                        reason,
                    });
                }
                // ..otherwise this is an error.
                Err(e) => return Err(e),
            };

            // We need to take care of reads that straddle different virtual memory pages.
            // First, figure out the maximum amount of bytes we can read off this page.
            let left_in_page =
                usize::try_from(translation.page_kind.size() - translation.offset).unwrap();
            // Then, either we read it until its end, or we stop before if we can get by
            // with less.
            let amount_wanted = min(amount_left, left_in_page);
            // Figure out where we should read into.
            let slice = &mut buf[total_read..total_read + amount_wanted];

            // Read the physical memory!
            let gpa = translation.gpa();
            match phys::Reader::new(self.parser).read_exact(gpa, slice) {
                Ok(()) => {}
                Err(Error::PartialRead {
                    actual_amount,
                    reason: PageReadError::NotInDump { gva: None, gpa },
                    ..
                }) => {
                    // Augment `NotInDump` with the `gva` as `phys::Reader::read_exact` doesn't know
                    // anything about it.
                    let reason = PageReadError::NotInDump {
                        gva: Some((addr, None)),
                        gpa,
                    };

                    return Err(Error::PartialRead {
                        expected_amount: buf.len(),
                        actual_amount: total_read + actual_amount,
                        reason,
                    });
                }
                Err(Error::PartialRead { .. }) => {
                    // We should never get there; `phys::Reader::read_exact` can only return a
                    // `PartialRead` error if it cannot read the gpa because it
                    // isn't in the dump.
                    unreachable!();
                }
                Err(e) => return Err(e),
            }

            // Update the total amount of read bytes and how much work we have left.
            total_read += amount_wanted;
            amount_left -= amount_wanted;
            // We have more work to do, so let's move to the next page.
            addr = addr.next_aligned_page();
        }

        // Yay, we read as much bytes as the user wanted!
        Ok(())
    }

    /// Read a `T` from virtual memory. Returns `None` if a memory error occurs
    /// (page not present, page not in dump, etc.).
    pub fn read_struct<T: Pod>(&self, gva: Gva) -> Result<T> {
        let mut t: MaybeUninit<T> = MaybeUninit::uninit();
        let size_of_t = size_of_val(&t);
        let slice_over_t =
            unsafe { slice::from_raw_parts_mut(t.as_mut_ptr().cast::<u8>(), size_of_t) };

        self.read_exact(gva, slice_over_t)?;

        Ok(unsafe { t.assume_init() })
    }

    pub fn try_translate(&self, gva: Gva) -> Result<Option<Translation>> {
        ignore_non_fatal(self.translate(gva))
    }

    pub fn try_read_exact(&self, gva: Gva, buf: &mut [u8]) -> Result<Option<()>> {
        ignore_non_fatal(self.read_exact(gva, buf))
    }

    pub fn try_read_struct<T: Pod>(&self, gva: Gva) -> Result<Option<T>> {
        ignore_non_fatal(self.read_struct(gva))
    }
}
