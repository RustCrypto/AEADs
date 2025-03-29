#![allow(unused)]
use core::num::Wrapping;

/// Multiplication in GF(2)[X], truncated to the low 64-bits, with “holes”
/// (sequences of zeroes) to avoid carry spilling.
///
/// When carries do occur, they wind up in a "hole" and are subsequently masked
/// out of the result.
pub(super) fn bmul64(x: u64, y: u64) -> u128 {
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
