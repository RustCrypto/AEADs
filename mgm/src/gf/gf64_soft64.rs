use super::{utils::bmul64, GfElement};
use aead::{consts::U8, generic_array::GenericArray};

pub struct Element(u64);

type Block = GenericArray<u8, U8>;

impl GfElement for Element {
    type N = U8;

    #[inline(always)]
    fn new() -> Self {
        Self(0)
    }

    #[allow(clippy::many_single_char_names)]
    fn mul_sum(&mut self, a: &Block, b: &Block) {
        let a = from_block(a);
        let b = from_block(b);
        let c = bmul64(a, b);

        let d = c as u64;
        let e = (c >> 64) as u64;

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

#[inline(always)]
fn from_block(block: &Block) -> u64 {
    u64::from_be_bytes(block[..].try_into().unwrap())
}
