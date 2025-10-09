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
use std::ops::Deref;

use crate::{Bits, Gpa};

/// The various bits and flags that a [`Pxe`] has.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq, Default, PartialOrd, Ord)]
pub struct PxeFlags(u64);

impl PxeFlags {
    #[must_use]
    pub fn new(bits: u64) -> Self {
        Self(bits)
    }

    #[must_use]
    pub fn present(&self) -> bool {
        self.0.bit(0) != 0
    }

    #[must_use]
    pub fn writable(&self) -> bool {
        self.0.bit(1) != 0
    }

    #[must_use]
    pub fn user_accessible(&self) -> bool {
        self.0.bit(2) != 0
    }

    #[must_use]
    pub fn write_through(&self) -> bool {
        self.0.bit(3) != 0
    }

    #[must_use]
    pub fn cache_disabled(&self) -> bool {
        self.0.bit(4) != 0
    }

    #[must_use]
    pub fn accessed(&self) -> bool {
        self.0.bit(5) != 0
    }

    #[must_use]
    pub fn dirty(&self) -> bool {
        self.0.bit(6) != 0
    }

    #[must_use]
    pub fn large_page(&self) -> bool {
        self.0.bit(7) != 0
    }

    #[must_use]
    pub fn transition(&self) -> bool {
        self.0.bit(11) != 0
    }

    #[must_use]
    pub fn no_execute(&self) -> bool {
        self.0.bit(63) != 0
    }
}

impl Deref for PxeFlags {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
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
    #[must_use]
    pub const fn new(pfn: u64) -> Self {
        Self(pfn)
    }

    #[must_use]
    pub const fn u64(&self) -> u64 {
        self.0
    }

    #[must_use]
    pub const fn gpa(&self) -> Gpa {
        Gpa::from_pfn(*self)
    }

    #[must_use]
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
    #[must_use]
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
    /// assert!(p.present());
    /// let np = Pxe::new(
    ///     Pfn::new(0x1337),
    ///     PxeFlags::UserAccessible
    /// );
    /// assert!(!np.present());
    /// # }
    /// ```
    #[must_use]
    pub fn present(&self) -> bool {
        self.flags.present()
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
    /// assert!(p.large_page());
    /// let np = Pxe::new(
    ///     Pfn::new(0x1337),
    ///     PxeFlags::UserAccessible
    /// );
    /// assert!(!np.large_page());
    /// # }
    /// ```
    #[must_use]
    pub fn large_page(&self) -> bool {
        self.flags.large_page()
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
    /// assert!(p.transition());
    /// assert!(!np.transition());
    /// # }
    /// ```
    #[must_use]
    pub fn transition(&self) -> bool {
        !self.present() && self.flags.transition()
    }

    /// Is the memory described by this [`Pxe`] writable?
    ///
    /// # Examples
    ///
    /// ```
    /// # use kdmp_parser::{Pxe, PxeFlags, Pfn};
    /// # fn main() {
    /// let w = Pxe::from(0x2709063);
    /// let ro = Pxe::from(0x8A00000002C001A1);
    /// assert!(w.writable());
    /// assert!(!ro.writable());
    /// # }
    /// ```
    #[must_use]
    pub fn writable(&self) -> bool {
        self.flags.writable()
    }

    /// Is the memory described by this [`Pxe`] executable?
    ///
    /// # Examples
    ///
    /// ```
    /// # use kdmp_parser::{Pxe, PxeFlags, Pfn};
    /// # fn main() {
    /// let x = Pxe::from(0x270a063);
    /// let nx = Pxe::from(0x8A00000002C001A1);
    /// assert!(x.executable());
    /// assert!(!nx.executable());
    /// # }
    /// ```
    #[must_use]
    pub fn executable(&self) -> bool {
        !self.flags.no_execute()
    }

    /// Is the memory described by this [`Pxe`] accessible by user-mode?
    ///
    /// # Examples
    ///
    /// ```
    /// # use kdmp_parser::{Pxe, PxeFlags, Pfn};
    /// # fn main() {
    /// let u = Pxe::from(0x8000000F34E5025);
    /// let s = Pxe::from(0x270A063);
    /// assert!(u.user_accessible());
    /// assert!(!s.user_accessible());
    /// # }
    /// ```
    #[must_use]
    pub fn user_accessible(&self) -> bool {
        self.flags.user_accessible()
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
        let flags = PxeFlags::new(value);

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

        *pxe.flags | (pxe.pfn.u64() << 12u64)
    }
}
