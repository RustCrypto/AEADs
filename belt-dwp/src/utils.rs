/// Helper function for transforming BelT keys and blocks from a byte array
/// to an array of `u32`s.
///
/// # Panics
/// If length of `src` is not equal to `4 * N`.
#[inline(always)]
pub(crate) fn to_u32<const N: usize>(src: &[u8]) -> [u32; N] {
    assert_eq!(src.len(), 4 * N);
    core::array::from_fn(|i| u32::from_le_bytes(src[i * 4..(i + 1) * 4].try_into().unwrap()))
}

/// Helper function for transforming BelT keys and blocks from a array of `u32`s
/// to a byte array.
///
/// # Panics
/// If length of `src` is not equal to `4 * N`.
#[inline(always)]
pub(crate) fn from_u32<const N: usize>(src: &[u32]) -> [u8; N] {
    assert_eq!(N, 4 * src.len());
    core::array::from_fn(|i| src[i / 4].to_le_bytes()[i % 4])
}
