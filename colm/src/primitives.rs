use super::arch::*;

/// Byte swap necessary, because of little-endian encoding in x86_64 registers.
#[inline]
pub(crate) fn byte_swap(x: __m128i) -> __m128i {
    unsafe {
        let bswap_mask = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
        _mm_shuffle_epi8(x, bswap_mask)
    }
}

/// Polynomial multiplication with 2 in the Galois field G^128
#[inline]
pub(crate) fn gf128_mul2(x: &__m128i) -> __m128i {
    unsafe {
        let redpoly = _mm_set_epi64x(0, 0x87); // Set our irreducible polynomial by which to reduce polynomial multiplication over GF(2)

        //let mut mask = _mm_cmpgt_epi32(zero, x); // Set mask
        let mut mask = _mm_srai_epi32(*x, 31); // Set mask for branchless conditional
        mask = _mm_shuffle_epi32(mask, 0xff);

        let x2 = _mm_or_si128(
            // Bitwise OR between
            _mm_slli_epi64(*x, 1), // x shifted left by 1 (equals multiplication by 2)
            _mm_srli_epi64(_mm_slli_si128::<8>(*x), 63), // and x shifted left by 8 and shifted right by 63.
        );
        // Return bitwise XOR of x2 with the bitwise AND between the irreducible polynomial and mask
        // Rules out the reducing polynomial if mask is 0
        _mm_xor_si128(x2, _mm_and_si128(redpoly, mask))
    }
}

/// Polynomial multiplication with 3 in the Galois field G^128
#[inline]
pub(crate) fn gf128_mul3(x: &__m128i) -> __m128i {
    unsafe { _mm_xor_si128(gf128_mul2(x), *x) }
}

/// Polynomial multiplication with 7 in the Galois field G^128
#[inline]
pub(crate) fn gf128_mul7(x: &__m128i) -> __m128i {
    unsafe {
        let x2 = gf128_mul2(x);
        let x4 = gf128_mul2(&x2);

        _mm_xor_si128(x4, _mm_xor_si128(x2, *x))
    }
}

/// Inplace implementation of COLM's rho function.
#[inline]
pub(crate) fn rho(block: &mut __m128i, w: &mut __m128i) {
    unsafe {
        let new_w = _mm_xor_si128(gf128_mul2(w), *block);
        *block = _mm_xor_si128(new_w, *w);
        *w = new_w;
    }
}

/// Inplace implementation of COLM's inverse rho function.
#[inline]
pub(crate) fn rho_inv(block: &mut __m128i, w: &mut __m128i) {
    unsafe {
        let new_w = gf128_mul2(w);
        *w = _mm_xor_si128(*w, *block);
        *block = _mm_xor_si128(new_w, *w);
    }
}
