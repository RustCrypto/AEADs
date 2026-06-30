use aead::{array::Array, consts::U16};
use core::ops::{Add, Mul};

use super::{GfElement, utils::bmul64};

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Element(u64, u64);

type Block = Array<u8, U16>;

impl GfElement for Element {
    type N = U16;

    #[inline(always)]
    fn new() -> Self {
        Self(0, 0)
    }

    #[inline(always)]
    fn into_bytes(self) -> Block {
        let mut block = Block::default();
        block[8..].copy_from_slice(&self.0.to_le_bytes());
        block[..8].copy_from_slice(&self.1.to_le_bytes());
        block
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

        // reduce over polynomial f(w) = w^128 + w^7 + w^2 + w + 1
        let d = v2 ^ (v3 >> 63) ^ (v3 >> 62) ^ (v3 >> 57);
        self.1 ^= v0 ^ d ^ (d << 1) ^ (d << 2) ^ (d << 7);
        self.0 ^= v1 ^ v3 ^ (v3 << 1) ^ (v3 << 2) ^ (v3 << 7) ^ (d >> 63) ^ (d >> 62) ^ (d >> 57);
    }
}

impl From<u128> for Element {
    fn from(x: u128) -> Self {
        Self((x >> 64) as u64, x as u64)
    }
}

impl From<Block> for Element {
    fn from(block: Block) -> Self {
        let [a, b] = from_block(&block);
        Self(a, b)
    }
}

impl From<Element> for Block {
    fn from(element: Element) -> Self {
        element.into_bytes()
    }
}

impl From<&Block> for Element {
    fn from(block: &Block) -> Self {
        let [a, b] = from_block(block);
        Self(a, b)
    }
}

#[inline(always)]
fn from_block(block: &Block) -> [u64; 2] {
    let (a, b) = block.split_at(8);
    [
        u64::from_le_bytes(b.try_into().unwrap()),
        u64::from_le_bytes(a.try_into().unwrap()),
    ]
}

impl Add for Element {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self(self.0 ^ rhs.0, self.1 ^ rhs.1)
    }
}

impl Mul for Element {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        let mut res = Self::new();
        res.mul_sum(&self.into_bytes(), &rhs.into_bytes());
        res
    }
}
