/// Helper function for transforming BelT keys and blocks from a byte array
/// to an array of `u32`s.
///
/// # Panics
/// If length of `src` is not equal to `4 * N`.
// #[inline(always)]
pub(crate) fn to_u32<const N: usize>(src: &[u8]) -> [u32; N] {
    assert_eq!(src.len(), 4 * N);
    let mut res = [0u32; N];
    res.iter_mut()
        .zip(src.chunks_exact(4))
        .for_each(|(dst, src)| *dst = u32::from_le_bytes(src.try_into().unwrap()));
    res
}

/// Helper function for transforming BelT keys and blocks from a array of `u32`s
/// to a byte array.
///
/// # Panics
/// If length of `src` is not equal to `4 * N`.
// #[inline(always)]
pub(crate) fn from_u32<const N: usize>(src: &[u32]) -> [u8; N] {
    assert_eq!(N, 4 * src.len());
    let mut res = [0u8; N];
    src.iter()
        .zip(res.chunks_exact_mut(4))
        .for_each(|(src, dst)| dst.copy_from_slice(&src.to_le_bytes()));
    res
}
