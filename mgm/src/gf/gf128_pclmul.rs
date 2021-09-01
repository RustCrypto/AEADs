//! Carryless multiplication over GF(2^128) based on the PCLMULQDQ CPU intrinsics
//! on `x86` and `x86_64` target architectures.
//!
//! More information can be found in the Intel whitepaper:
//! https://software.intel.com/sites/default/files/managed/72/cc/clmul-wp-rev-2.02-2014-04-20.pdf
use super::GfElement;
use aead::{consts::U16, generic_array::GenericArray};

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

type Block = GenericArray<u8, U16>;

const BS_MASK1: i64 = 0x0001_0203_0405_0607;
const BS_MASK2: i64 = 0x0809_0A0B_0C0D_0E0F;

macro_rules! xor {
    ($e1:expr, $e2:expr $(,)?) => {
        _mm_xor_si128($e1, $e2)
    };
    ($head:expr, $($tail:expr),* $(,)?) => {
        _mm_xor_si128($head, xor!($($tail ,)*))
    };
}

pub struct Element(__m128i);

impl GfElement for Element {
    type N = U16;

    #[inline(always)]
    fn new() -> Self {
        Self(unsafe { _mm_setzero_si128() })
    }

    #[allow(clippy::many_single_char_names)]
    fn mul_sum(&mut self, a: &Block, b: &Block) {
        unsafe {
            let bs_mask = _mm_set_epi64x(BS_MASK1, BS_MASK2);

            let a = _mm_loadu_si128(a.as_ptr() as *const _);
            let b = _mm_loadu_si128(b.as_ptr() as *const _);
            let a = _mm_shuffle_epi8(a, bs_mask);
            let b = _mm_shuffle_epi8(b, bs_mask);

            // Multiply using Karatsuba multiplication
            let a2 = xor!(a, _mm_shuffle_epi32(a, 0x0E));
            let b2 = xor!(b, _mm_shuffle_epi32(b, 0x0E));
            let c = _mm_clmulepi64_si128(a, b, 0x11);
            let d = _mm_clmulepi64_si128(a, b, 0x00);
            let e = _mm_clmulepi64_si128(a2, b2, 0x00);
            let t = xor!(c, d, e);
            let v0 = d;
            let v1 = xor!(_mm_shuffle_epi32(d, 0x0E), t);
            let v2 = xor!(c, _mm_shuffle_epi32(t, 0x0E));
            let v3 = _mm_shuffle_epi32(c, 0x0E);

            // reduce over polynominal f(w) = w^128 + w^7 + w^2 + w + 1
            let d = xor!(
                v2,
                _mm_srli_epi64(v3, 63),
                _mm_srli_epi64(v3, 62),
                _mm_srli_epi64(v3, 57)
            );
            let lo = xor!(
                v0,
                d,
                _mm_slli_epi64(d, 1),
                _mm_slli_epi64(d, 2),
                _mm_slli_epi64(d, 7),
            );
            let hi = xor!(
                v1,
                v3,
                _mm_slli_epi64(v3, 1),
                _mm_slli_epi64(v3, 2),
                _mm_slli_epi64(v3, 7),
                _mm_srli_epi64(d, 63),
                _mm_srli_epi64(d, 62),
                _mm_srli_epi64(d, 57),
            );
            let res = _mm_unpacklo_epi64(lo, hi);

            self.0 = xor!(self.0, res);
        }
    }

    #[inline(always)]
    fn into_bytes(self) -> Block {
        unsafe {
            let bs_mask = _mm_set_epi64x(BS_MASK1, BS_MASK2);
            core::mem::transmute(_mm_shuffle_epi8(self.0, bs_mask))
        }
    }
}
