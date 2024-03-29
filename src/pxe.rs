// Axel '0vercl0k' Souchet - June 5 2023
//! This defines [`Pxe`] / [`Pfn`] types that makes it easier to manipulate PFNs
//! and PXEs.
//!
//! # Examples
//!
//! ```
//! # use kdmp_parser::{Pxe, PxeFlags, Pfn};
//! let pxe = Pxe::new(
//!     Pfn::new(0x6d600),
//!     PxeFlags::UserAccessible | PxeFlags::Accessed | PxeFlags::Present
//! );
//! let encoded = u64::from(pxe);
//! let decoded = Pxe::from(encoded);
//! ```
use bitflags::bitflags;

use crate::Gpa;

bitflags! {
    /// The various bits and flags that a [`Pxe`] has.
    #[derive(Debug, Clone, Copy, Eq, Hash, PartialEq, Default, PartialOrd, Ord)]
    pub struct PxeFlags : u64 {
        const Present = 1 << 0;
        const Writable = 1 << 1;
        const UserAccessible = 1 << 2;
        const WriteThrough = 1 << 3;
        const CacheDisabled = 1 << 4;
        const Accessed = 1 << 5;
        const Dirty = 1 << 6;
        const LargePage = 1 << 7;
        const Transition = 1 << 11;
        const NoExecute = 1 << 63;
    }
}

/// Strong type for a Page Frame Number.
///
/// # Examples
///
/// ```
/// # use kdmp_parser::{Pfn, Gpa};
/// # fn main() {
/// let pfn = Pfn::new(0x1337);
/// assert_eq!(pfn.gpa(), Gpa::new(0x1337000));
/// # }
/// ```
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq, Default, PartialOrd, Ord)]
pub struct Pfn(u64);

impl Pfn {
    pub const fn new(pfn: u64) -> Self {
        Self(pfn)
    }

    pub const fn u64(&self) -> u64 {
        self.0
    }

    pub const fn gpa(&self) -> Gpa {
        Gpa::from_pfn(*self)
    }

    pub const fn gpa_with_offset(&self, offset: u64) -> Gpa {
        Gpa::from_pfn_with_offset(*self, offset)
    }
}

impl From<u64> for Pfn {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<Pfn> for u64 {
    fn from(value: Pfn) -> Self {
        value.u64()
    }
}

/// A [`Pxe`] is a set of flags ([`PxeFlags`]) and a Page Frame Number (PFN).
/// This representation takes more space than a regular `PXE` but it is more
/// convenient to split the flags / the pfn as [`bitflags!`] doesn't seem to
/// support bitfields.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq, Default, PartialOrd, Ord)]
pub struct Pxe {
    /// The PFN of the next table or the final page.
    pub pfn: Pfn,
    /// PXE flags.
    pub flags: PxeFlags,
}

impl Pxe {
    /// Create a [`Pxe`] from a `pfn` and a set of `flags`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use kdmp_parser::{Pxe, PxeFlags, Pfn};
    /// # fn main() {
    /// let pxe = Pxe::new(
    ///     Pfn::new(0x6d600),
    ///     PxeFlags::UserAccessible | PxeFlags::Accessed | PxeFlags::Present
    /// );
    /// assert_eq!(pxe.pfn.u64(), 0x6d600);
    /// # }
    /// ```
    pub fn new(pfn: Pfn, flags: PxeFlags) -> Self {
        Self { pfn, flags }
    }

    /// Is the bit Present/Valid turned on?
    ///
    /// # Examples
    ///
    /// ```
    /// # use kdmp_parser::{Pxe, PxeFlags, Pfn};
    /// # fn main() {
    /// let p = Pxe::new(
    ///     Pfn::new(0x6d600),
    ///     PxeFlags::Present
    /// );
    /// assert_eq!(p.present(), true);
    /// let np = Pxe::new(
    ///     Pfn::new(0x1337),
    ///     PxeFlags::UserAccessible
    /// );
    /// assert_eq!(np.present(), false);
    /// # }
    /// ```
    pub fn present(&self) -> bool {
        self.flags.contains(PxeFlags::Present)
    }

    /// Is it a large page?
    ///
    /// # Examples
    ///
    /// ```
    /// # use kdmp_parser::{Pxe, PxeFlags, Pfn};
    /// # fn main() {
    /// let p = Pxe::new(
    ///     Pfn::new(0x6d600),
    ///     PxeFlags::LargePage
    /// );
    /// assert_eq!(p.large_page(), true);
    /// let np = Pxe::new(
    ///     Pfn::new(0x1337),
    ///     PxeFlags::UserAccessible
    /// );
    /// assert_eq!(np.large_page(), false);
    /// # }
    /// ```
    pub fn large_page(&self) -> bool {
        self.flags.contains(PxeFlags::LargePage)
    }

    /// Is it a transition PTE?
    ///
    /// # Examples
    ///
    /// ```
    /// # use kdmp_parser::{Pxe, PxeFlags, Pfn};
    /// # fn main() {
    /// let p = Pxe::from(0x166B7880);
    /// let np = Pxe::from(0xA000000077AF867);
    /// assert_eq!(p.transition(), true);
    /// assert_eq!(np.transition(), false);
    /// # }
    /// ```
    pub fn transition(&self) -> bool {
        !self.present() && self.flags.contains(PxeFlags::Transition)
    }
}

/// Convert a [`u64`] into a [`Pxe`].
impl From<u64> for Pxe {
    /// Create a [`u64`] from a [`Pxe`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use kdmp_parser::{Pxe, PxeFlags, Pfn};
    /// # fn main() {
    /// let pxe = Pxe::from(0x6D_60_00_25);
    /// assert_eq!(pxe.pfn.u64(), 0x6d600);
    /// assert_eq!(pxe.flags, PxeFlags::UserAccessible | PxeFlags::Accessed | PxeFlags::Present);
    /// # }
    /// ```
    fn from(value: u64) -> Self {
        let pfn = Pfn::new((value >> 12) & 0xf_ffff_ffff);
        let flags = PxeFlags::from_bits(value & PxeFlags::all().bits()).expect("PxeFlags");

        Self::new(pfn, flags)
    }
}

/// Convert a [`Pxe`] into a [`u64`].
impl From<Pxe> for u64 {
    /// Create a [`u64`] from a [`Pxe`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use kdmp_parser::{Pxe, PxeFlags, Pfn};
    /// # fn main() {
    /// let pxe = Pxe::new(
    ///     Pfn::new(0x6d600),
    ///     PxeFlags::UserAccessible | PxeFlags::Accessed | PxeFlags::Present,
    /// );
    /// assert_eq!(u64::from(pxe), 0x6D_60_00_25);
    /// # }
    /// ```
    fn from(pxe: Pxe) -> Self {
        debug_assert!(pxe.pfn.u64() <= 0xf_ffff_ffffu64);

        pxe.flags.bits() | (pxe.pfn.u64() << 12u64)
    }
}
