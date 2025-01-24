use super::{mask, poly_step, Array, Hasher, Hs1Params};
#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

impl<P: Hs1Params> Hasher<P> {
    #[inline(always)]
    #[cfg(target_feature = "sse2")]
    pub(super) unsafe fn update_block_sse2(&mut self) -> &mut Self {
        assert!(usize::from(self.bytes) <= self.block_u8().len());

        #[inline(always)]
        unsafe fn nh_step(x: &[u32; 4], y: &[u32; 4]) -> __m128i {
            let x = x.as_ptr().cast::<__m128i>().read_unaligned();
            let y = y.as_ptr().cast::<__m128i>().read_unaligned();
            let xy = _mm_add_epi32(x, y);

            let a_b = _mm_shuffle_epi32::<0b00_01_00_00>(xy);
            let c_d = _mm_shuffle_epi32::<0b00_11_00_10>(xy);
            _mm_mul_epu32(a_b, c_d)
        }

        let m_ints = &self.block;

        let block16_count = usize::from(((self.bytes + 15) / 16).max(1));

        let mut nh: Array<__m128i, P::T> = Array::from_fn(|_| _mm_setzero_si128());
        for (i0, m_ints_i) in m_ints.chunks_exact(4).enumerate().take(block16_count) {
            for (nh_i, k_n_i_i) in nh.iter_mut().zip(self.k.nh.chunks_exact(4).skip(i0)) {
                let k_n_i_i = k_n_i_i.try_into().expect("exactly 4 elements");
                let m_ints_i = m_ints_i.try_into().expect("exactly 4 elements");
                let s = nh_step(k_n_i_i, m_ints_i);
                *nh_i = _mm_add_epi64(*nh_i, s);
            }
        }

        nh.iter()
            .map(|nh_i| {
                let &[ac, bd] = &*(nh_i as *const _ as *const [u64; 2]);
                ac.wrapping_add(bd)
            })
            .map(|nh_i| (nh_i.wrapping_add(u64::from(self.bytes) & mask(4))) & mask(60))
            .zip(self.k.poly.iter())
            .zip(self.h.iter_mut())
            .for_each(|((a_i, &k_p_i), h_i)| *h_i = poly_step(*h_i, a_i, k_p_i));

        self.bytes = 0;

        self
    }
}
