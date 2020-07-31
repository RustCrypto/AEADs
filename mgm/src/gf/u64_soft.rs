use crate::Block;
use core::num::Wrapping;

pub(crate) struct Element(u64, u64);

impl Element {
    pub(crate) fn new() -> Self {
        Self(0, 0)
    }

    #[allow(clippy::cast_ptr_alignment)]
    #[allow(clippy::many_single_char_names)]
    pub(crate) fn mul_sum(&mut self, a: &Block, b: &Block) {
        let [a1, a0] = from_block(a);
        let [b1, b0] = from_block(b);
        let a2 = a1 ^ a0;
        let b2 = b1 ^ b0;

        let c = bmul64(a1, b1);
        let d = bmul64(a0, b0);
        let e = bmul64(a2, b2);
        let t = c ^ d ^ e;
        let v0 = d as u64;
        let v1 = ((d >> 64) ^ t) as u64;
        let v2 = (c ^ (t >> 64)) as u64;
        let v3 = (c >> 64) as u64;

        let d = v2 ^ (v3 >> 63) ^ (v3 >> 62) ^ (v3 >> 57);
        self.1 ^= v0 ^ d ^ (d << 1) ^ (d << 2) ^ (d << 7);
        self.0 ^= v1 ^ v3 ^ (v3 << 1) ^ (v3 << 2) ^ (v3 << 7) ^ (d >> 63) ^ (d >> 62) ^ (d >> 57);
    }

    pub(crate) fn into_bytes(self) -> Block {
        let mut block = Block::default();
        block[..8].copy_from_slice(&self.0.to_be_bytes());
        block[8..].copy_from_slice(&self.1.to_be_bytes());
        block
    }
}

/// Multiplication in GF(2)[X], truncated to the low 64-bits, with “holes”
/// (sequences of zeroes) to avoid carry spilling.
///
/// When carries do occur, they wind up in a "hole" and are subsequently masked
/// out of the result.
fn bmul64(x: u64, y: u64) -> u128 {
    let x0 = Wrapping((x & 0x1111_1111_1111_1111) as u128);
    let x1 = Wrapping((x & 0x2222_2222_2222_2222) as u128);
    let x2 = Wrapping((x & 0x4444_4444_4444_4444) as u128);
    let x3 = Wrapping((x & 0x8888_8888_8888_8888) as u128);
    let y0 = Wrapping((y & 0x1111_1111_1111_1111) as u128);
    let y1 = Wrapping((y & 0x2222_2222_2222_2222) as u128);
    let y2 = Wrapping((y & 0x4444_4444_4444_4444) as u128);
    let y3 = Wrapping((y & 0x8888_8888_8888_8888) as u128);

    let mut z0 = ((x0 * y0) ^ (x1 * y3) ^ (x2 * y2) ^ (x3 * y1)).0;
    let mut z1 = ((x0 * y1) ^ (x1 * y0) ^ (x2 * y3) ^ (x3 * y2)).0;
    let mut z2 = ((x0 * y2) ^ (x1 * y1) ^ (x2 * y0) ^ (x3 * y3)).0;
    let mut z3 = ((x0 * y3) ^ (x1 * y2) ^ (x2 * y1) ^ (x3 * y0)).0;

    z0 &= 0x1111_1111_1111_1111_1111_1111_1111_1111;
    z1 &= 0x2222_2222_2222_2222_2222_2222_2222_2222;
    z2 &= 0x4444_4444_4444_4444_4444_4444_4444_4444;
    z3 &= 0x8888_8888_8888_8888_8888_8888_8888_8888;

    z0 | z1 | z2 | z3
}

fn from_block(block: &Block) -> [u64; 2] {
    use core::convert::TryInto;
    [
        u64::from_be_bytes(block[..8].try_into().unwrap()),
        u64::from_be_bytes(block[8..].try_into().unwrap()),
    ]
}
