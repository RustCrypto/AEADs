#![allow(dead_code)]

use core::slice::from_raw_parts_mut;

use aead::generic_array::{ArrayLength, GenericArray};
use aes::Block;

#[inline]
pub(crate) fn inplace_xor<T, U>(a: &mut GenericArray<T, U>, b: &GenericArray<T, U>)
where
    U: ArrayLength<T>,
    T: core::ops::BitXor<Output = T> + Copy,
{
    for (aa, bb) in a.as_mut_slice().iter_mut().zip(b.as_slice()) {
        *aa = *aa ^ *bb;
    }
}

/// Doubles a block, in GF(2^128).
///
/// Adapted from https://github.com/RustCrypto/universal-hashes/blob/9b0ac5d1/polyval/src/mulx.rs#L5-L18
#[inline]
pub(crate) fn double(block: &Block) -> Block {
    let mut v = u128::from_be_bytes((*block).into());
    let v_hi = v >> 127;

    // If v_hi = 0, return (v << 1)
    // If v_hi = 1, return (v << 1) xor (0b0...010000111)
    v <<= 1;
    v ^= v_hi ^ (v_hi << 1) ^ (v_hi << 2) ^ (v_hi << 7);
    v.to_be_bytes().into()
}

/// Counts the number of non-trailing zeros in the binary representation.
///
/// Defined in https://www.rfc-editor.org/rfc/rfc7253.html#section-2
#[inline]
pub(crate) fn ntz(n: usize) -> usize {
    n.trailing_zeros().try_into().unwrap()
}

const BLOCK_SIZE: usize = 16;

/// Adapted from https://doc.rust-lang.org/std/primitive.slice.html#method.split_at_mut_unchecked
///
/// SAFETY: Assumes that `two_blocks` is exactly two blocks.
#[inline]
#[allow(unsafe_code)]
pub(crate) unsafe fn split_into_two_blocks(two_blocks: &mut [u8]) -> [&mut Block; 2] {
    let ptr = two_blocks.as_mut_ptr();

    unsafe {
        [
            from_raw_parts_mut(ptr, BLOCK_SIZE).into(),
            from_raw_parts_mut(ptr.add(BLOCK_SIZE), BLOCK_SIZE).into(),
        ]
    }
}

/// Adapted from https://doc.rust-lang.org/std/primitive.slice.html#method.split_at_mut_unchecked
///
/// SAFETY: Assumes that `four_blocks` is exactly four blocks.
#[inline]
#[allow(unsafe_code)]
pub(crate) unsafe fn split_into_four_blocks(four_blocks: &mut [u8]) -> [&mut Block; 4] {
    let ptr = four_blocks.as_mut_ptr();

    unsafe {
        [
            from_raw_parts_mut(ptr, BLOCK_SIZE).into(),
            from_raw_parts_mut(ptr.add(BLOCK_SIZE), BLOCK_SIZE).into(),
            from_raw_parts_mut(ptr.add(2 * BLOCK_SIZE), BLOCK_SIZE).into(),
            from_raw_parts_mut(ptr.add(3 * BLOCK_SIZE), BLOCK_SIZE).into(),
        ]
    }
}
