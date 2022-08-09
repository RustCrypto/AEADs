use super::{utils::bmul64, GfElement};
use aead::{consts::U16, generic_array::GenericArray};

pub struct Element(u64, u64);

type Block = GenericArray<u8, U16>;

impl GfElement for Element {
    type N = U16;

    #[inline(always)]
    fn new() -> Self {
        Self(0, 0)
    }

    #[allow(clippy::many_single_char_names)]
    fn mul_sum(&mut self, a: &Block, b: &Block) {
        let [a1, a0] = from_block(a);
        let [b1, b0] = from_block(b);
        let a2 = a1 ^ a0;
        let b2 = b1 ^ b0;

        // Multiply using Karatsuba multiplication
        let c = bmul64(a1, b1);
        let d = bmul64(a0, b0);
        let e = bmul64(a2, b2);
        let t = c ^ d ^ e;
        let v0 = d as u64;
        let v1 = ((d >> 64) ^ t) as u64;
        let v2 = (c ^ (t >> 64)) as u64;
        let v3 = (c >> 64) as u64;

        // reduce over polynominal f(w) = w^128 + w^7 + w^2 + w + 1
        let d = v2 ^ (v3 >> 63) ^ (v3 >> 62) ^ (v3 >> 57);
        self.1 ^= v0 ^ d ^ (d << 1) ^ (d << 2) ^ (d << 7);
        self.0 ^= v1 ^ v3 ^ (v3 << 1) ^ (v3 << 2) ^ (v3 << 7) ^ (d >> 63) ^ (d >> 62) ^ (d >> 57);
    }

    #[inline(always)]
    fn into_bytes(self) -> Block {
        let mut block = Block::default();
        block[..8].copy_from_slice(&self.0.to_be_bytes());
        block[8..].copy_from_slice(&self.1.to_be_bytes());
        block
    }
}

#[inline(always)]
fn from_block(block: &Block) -> [u64; 2] {
    let (a, b) = block.split_at(8);
    [
        u64::from_be_bytes(a.try_into().unwrap()),
        u64::from_be_bytes(b.try_into().unwrap()),
    ]
}
