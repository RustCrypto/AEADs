//! Carryless multiplication over GF(2^128) optimized using Shay Gueron's
//! techniques based on the PCLMULQDQ CPU intrinsic on `x86` and `x86_64`
//! target architectures.
//!
//! For more information on how these techniques work, see:
//! <https://blog.quarkslab.com/reversing-a-finite-field-multiplication-optimization.html>

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use crate::field::Block;
use core::ops::{Add, Mul};

/// Wrapper for `__m128i` - a 128-bit XMM register (SSE2)
#[repr(align(16))]
#[derive(Copy, Clone)]
pub struct M128i(__m128i);

impl From<Block> for M128i {
    // `_mm_loadu_si128` performs an unaligned load
    #[allow(clippy::cast_ptr_alignment)]
    fn from(bytes: Block) -> M128i {
        M128i(unsafe { _mm_loadu_si128(bytes.as_ptr() as *const __m128i) })
    }
}

impl From<M128i> for Block {
    // `_mm_storeu_si128` performs an unaligned store
    #[allow(clippy::cast_ptr_alignment)]
    fn from(xmm: M128i) -> Block {
        let mut result = Block::default();

        unsafe {
            _mm_storeu_si128(result.as_mut_ptr() as *mut __m128i, xmm.0);
        }

        result
    }
}

impl Add for M128i {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        M128i(unsafe { xor(self.0, rhs.0) })
    }
}

/// XOR is used to add two POLYVAL field elements
#[target_feature(enable = "sse2", enable = "sse4.1")]
unsafe fn xor(a: __m128i, b: __m128i) -> __m128i {
    _mm_xor_si128(a, b)
}

impl Mul for M128i {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        unsafe { M128i(clmul(self.0, rhs.0)) }
    }
}

/// Computes carryless POLYVAL multiplication over GF(2^128).
#[target_feature(enable = "pclmulqdq", enable = "sse2", enable = "sse4.1")]
unsafe fn clmul(lhs: __m128i, rhs: __m128i) -> __m128i {
    // pclmulqdq
    let t1 = _mm_clmulepi64_si128(lhs, rhs, 0x00);

    // pclmulqdq
    let t2 = _mm_clmulepi64_si128(lhs, rhs, 0x01);

    // pclmulqdq
    let t3 = _mm_clmulepi64_si128(lhs, rhs, 0x10);

    // pclmulqdq
    let t4 = _mm_clmulepi64_si128(lhs, rhs, 0x11);

    // pxor
    let t5 = _mm_xor_si128(t2, t3);

    // psrldq, pxor
    let t6 = _mm_xor_si128(t4, _mm_bsrli_si128(t5, 8));

    // pslldq, pxor
    let t7 = _mm_xor_si128(t1, _mm_bslli_si128(t5, 8));

    // reduce, pxor
    _mm_xor_si128(t6, reduce(t7))
}

/// Mask value used when performing Montgomery fast reduction.
/// This corresponds to POLYVAL's polynomial with the highest bit unset.
const MASK: u128 = 1 << 127 | 1 << 126 | 1 << 121 | 1;

/// Fast reduction modulo x^128 + x^127 + x^126 +x^121 + 1 (Gueron 2012)
/// Algorithm 4: "Montgomery reduction"
///
/// See: <https://crypto.stanford.edu/RealWorldCrypto/slides/gueron.pdf>
#[target_feature(enable = "pclmulqdq", enable = "sse2", enable = "sse4.1")]
unsafe fn reduce(x: __m128i) -> __m128i {
    // `_mm_loadu_si128` performs an unaligned load
    // (`u128` is not necessarily aligned to 16-bytes)
    #[allow(clippy::cast_ptr_alignment)]
    let mask = _mm_loadu_si128(&MASK as *const u128 as *const __m128i);

    // pclmulqdq
    let a = _mm_clmulepi64_si128(mask, x, 0x01);

    // pshufd, pxor
    let b = _mm_xor_si128(_mm_shuffle_epi32(x, 0x4e), a);

    // pclmulqdq
    let c = _mm_clmulepi64_si128(mask, b, 0x01);

    // pshufd, pxor
    _mm_xor_si128(_mm_shuffle_epi32(b, 0x4e), c)
}
