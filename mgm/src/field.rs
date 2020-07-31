//! Implementation of POLYVAL's finite field.
//!
//! From [RFC 8452 Section 3] which defines POLYVAL for use in AES-GCM_SIV:
//!
//! > "POLYVAL, like GHASH (the authenticator in AES-GCM; ...), operates in a
//! > binary field of size 2^128.  The field is defined by the irreducible
//! > polynomial x^128 + x^127 + x^126 + x^121 + 1."
//!
//! [RFC 8452 Section 3]: https://tools.ietf.org/html/rfc8452#section-3

#[cfg(all(
    target_feature = "pclmulqdq",
    target_feature = "sse2",
    target_feature = "sse4.1",
    any(target_arch = "x86", target_arch = "x86_64")
))]
mod pclmulqdq;
mod u32_soft;
mod u64_soft;

#[allow(unused_imports)]
use cfg_if::cfg_if;
use core::ops::{Add, Mul};

#[cfg(all(
    target_feature = "pclmulqdq",
    target_feature = "sse2",
    target_feature = "sse4.1",
    any(target_arch = "x86", target_arch = "x86_64")
))]
use self::pclmulqdq::M128i;

#[allow(unused_imports)]
use self::u32_soft::U32x4;

#[allow(unused_imports)]
use self::u64_soft::U64x2;

#[cfg(not(all(
    target_feature = "pclmulqdq",
    target_feature = "sse2",
    target_feature = "sse4.1",
    any(target_arch = "x86", target_arch = "x86_64")
)))]
cfg_if! {
    if #[cfg(target_pointer_width = "64")] {
        type M128i = U64x2;
    } else {
        type M128i = U32x4;
    }
}

/// POLYVAL field element bytestrings (16-bytes)
type Block = [u8; 16];

/// POLYVAL field element.
#[derive(Copy, Clone)]
#[repr(transparent)]
pub struct Element(M128i);

impl Element {
    /// Load a `FieldElement` from its bytestring representation.
    pub fn from_bytes(bytes: &super::Block) -> Self {
        let bytes: [u8; 16] = (*bytes).into();
        Element(bytes.into())
    }

    /// Serialize this `FieldElement` as a bytestring.
    pub fn to_bytes(self) -> Block {
        self.0.into()
    }
}

impl Default for Element {
    fn default() -> Self {
        Self::from_bytes(&super::Block::default())
    }
}

impl Add for Element {
    type Output = Self;

    /// Adds two POLYVAL field elements.
    ///
    /// From [RFC 8452 Section 3]:
    ///
    /// > "The sum of any two elements in the field is the result of XORing them."
    ///
    /// [RFC 8452 Section 3]: https://tools.ietf.org/html/rfc8452#section-3
    fn add(self, rhs: Self) -> Self {
        Element(self.0 + rhs.0)
    }
}

impl Mul for Element {
    type Output = Self;

    /// Computes POLYVAL multiplication over GF(2^128).
    ///
    /// From [RFC 8452 Section 3]:
    ///
    /// > "The product of any two elements is calculated using standard
    /// > (binary) polynomial multiplication followed by reduction modulo the
    /// > irreducible polynomial."
    ///
    /// [RFC 8452 Section 3]: https://tools.ietf.org/html/rfc8452#section-3
    fn mul(self, rhs: Self) -> Self {
        Element(self.0 * rhs.0)
    }
}
