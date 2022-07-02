//! Carryless multiplication over GF(2^64) based on the PCLMULQDQ CPU intrinsics
//! on `x86` and `x86_64` target architectures.

use super::GfElement;
use aead::{consts::U8, generic_array::GenericArray};

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

type Block = GenericArray<u8, U8>;

pub struct Element(u64);

impl GfElement for Element {
    type N = U8;

    #[inline(always)]
    fn new() -> Self {
        Self(0)
    }

    #[allow(clippy::many_single_char_names)]
    fn mul_sum(&mut self, a: &Block, b: &Block) {
        let a = u64::from_be_bytes(a[..].try_into().unwrap());
        let b = u64::from_be_bytes(b[..].try_into().unwrap());
        let [d, e]: [u64; 2] = unsafe {
            let a = _mm_set_epi64x(0, a as i64);
            let b = _mm_set_epi64x(0, b as i64);
            let c = _mm_clmulepi64_si128(a, b, 0x00);
            core::mem::transmute(c)
        };

        // reduce over polynominal f(w) = w^64 + w^4 + w^3 + w + 1
        let t = e ^ (e >> 63) ^ (e >> 61) ^ (e >> 60);
        self.0 ^= d ^ t ^ (t << 1) ^ (t << 3) ^ (t << 4);
    }

    #[inline(always)]
    fn into_bytes(self) -> Block {
        let mut block = Block::default();
        block.copy_from_slice(&self.0.to_be_bytes());
        block
    }
}
