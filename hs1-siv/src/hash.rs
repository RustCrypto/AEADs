use super::{
    mask, Array, ArraySize, False, Gr, Hs1HashKey, Hs1Params, PhantomData, Quot, True, B16, U4,
};
use aead::array::typenum::Unsigned;
use core::mem;

#[derive(Clone)]
pub struct Hasher<P: Hs1Params> {
    k: Hs1HashKey<P>,
    h: Array<u64, P::T>,
    block: Array<u32, Quot<B16<P>, U4>>,
    bytes: u8,
    _marker: PhantomData<P>,
}

pub(crate) mod sealed {
    pub trait Hs1HashFinal {
        type Output: Copy;
        type Asu: Copy + AsMut<[u64]> + Default;

        fn compute(h: u64, k_a: &Self::Asu) -> Self::Output;
    }
}

impl sealed::Hs1HashFinal for False {
    type Output = [u8; 8];
    type Asu = [u64; 0];

    fn compute(h: u64, []: &Self::Asu) -> Self::Output {
        h.to_le_bytes()
    }
}

impl sealed::Hs1HashFinal for True {
    type Output = [u8; 4];
    type Asu = [u64; 3];

    fn compute(h: u64, &[k_a0, k_a1, k_a2]: &Self::Asu) -> Self::Output {
        let (h1, h2) = (h & 0xffff_ffff, h >> 32);
        let res = k_a0
            .wrapping_add(k_a1.wrapping_mul(h1))
            .wrapping_add(k_a2.wrapping_mul(h2));
        let [_, _, _, _, res @ ..] = res.to_le_bytes();
        res
    }
}

type Hs1Hash<P> = Gr<<P as Hs1Params>::T, U4>;
pub type Output<P> = <Hs1Hash<P> as sealed::Hs1HashFinal>::Output;
pub type Asu<P> = <Hs1Hash<P> as sealed::Hs1HashFinal>::Asu;

impl<P: Hs1Params> Hasher<P> {
    pub fn new(k: &Hs1HashKey<P>) -> Self {
        Self {
            k: k.clone(),
            h: array_from_iter(core::iter::repeat(1)),
            block: Array::default(),
            bytes: 0,
            _marker: PhantomData,
        }
    }

    fn update_block(&mut self) -> &mut Self {
        assert!(usize::from(self.bytes) <= self.block_u8().len());

        #[inline(always)]
        fn nh(v1: &[u32], v2: &[u32]) -> u64 {
            debug_assert_eq!(v1.len(), v2.len());
            debug_assert_eq!(v1.len() % 4, 0);
            // I originally used a fancy, compact iterator chain here but the optimizer is shit
            // (and honestly, this is pretty compact too)
            let mut s = 0u64;
            for (x, y) in v1.chunks_exact(4).zip(v2.chunks_exact(4)) {
                let d = u64::from(x[3].wrapping_add(y[3]));
                let c = u64::from(x[2].wrapping_add(y[2]));
                let b = u64::from(x[1].wrapping_add(y[1]));
                let a = u64::from(x[0].wrapping_add(y[0]));
                s = s.wrapping_add(a * c).wrapping_add(b * d);
            }
            s
        }

        let m_ints = &self.block;

        let block16_count = usize::from(((self.bytes + 15) / 16).max(1));

        self.k
            .nh
            .windows(B16::<P>::to_usize() / 4)
            .step_by(4)
            .map(|k_n_i| nh(&k_n_i[..block16_count * 4], &m_ints[..block16_count * 4]))
            .map(|nh_i| (nh_i + (u64::from(self.bytes) & mask(4))) & mask(60))
            .zip(self.k.poly.iter())
            .zip(self.h.iter_mut())
            .for_each(|((a_i, &k_p_i), h_i)| *h_i = poly_step(*h_i, a_i, k_p_i));

        self.bytes = 0;

        self
    }

    pub fn update<'a>(&'a mut self, bytes: &[u8]) -> &'a mut Self {
        assert!(usize::from(self.bytes) < self.block_u8().len());
        let start = usize::from(self.bytes);
        let fill = bytes.len().min(self.block_u8().len() - start);
        let end = start + fill;
        let (now, rest) = bytes.split_at(fill);
        self.block_u8()[start..end].copy_from_slice(now);
        self.bytes = end as u8;
        if end < self.block_u8().len() {
            return self;
        }
        self.update_block();

        let mut it = rest.chunks_exact(self.block_u8().len());
        for blk in &mut it {
            self.block_u8().copy_from_slice(blk);
            self.bytes = B16::<P>::to_u8();
            self.update_block();
        }

        let rest = it.remainder();
        self.block_u8()[..rest.len()].copy_from_slice(rest);
        self.bytes = rest.len() as u8;
        self
    }

    pub(crate) fn pad_to(&mut self, bits: u8) -> &mut Self {
        debug_assert!(1 << bits <= B16::<P>::to_u8());
        let m = mask(bits) as u8;
        let fill = (m + 1).wrapping_sub(self.bytes) & m;
        self.update(&[0; 256][..usize::from(fill)])
    }

    // TODO &mut self helps avoid needing to clone(), but might be unintuitive
    pub fn finalize(&mut self) -> Array<Output<P>, P::T> {
        // TODO we need to handle empty data properly
        // However, see the note in crate::test::test_vectors::hash_me_empty
        use sealed::Hs1HashFinal;
        if self.bytes != 0 {
            self.update_block();
        }
        let mut out = Array::<Output<P>, P::T>::default();
        for ((out_i, h_i), k_a_i) in out.iter_mut().zip(&self.h).zip(&self.k.asu) {
            let h_i = poly_finalize(*h_i);
            *out_i = Hs1Hash::<P>::compute(h_i, k_a_i);
        }
        out
    }

    fn block_u8(&mut self) -> &mut Array<u8, B16<P>> {
        const {
            assert!(
                mem::size_of::<Array<u32, Quot<B16<P>, U4>>>()
                    == mem::size_of::<Array<u8, B16<P>>>()
            )
        }
        // SAFETY:
        // - the alignment is correct
        // - the lengths are equal
        // - there is no padding
        // - there are no invalid bit patterns
        unsafe { mem::transmute(&mut self.block) }
    }
}

#[inline(always)]
const fn poly_step(a: u64, b: u64, k: u64) -> u64 {
    let tmp = a as u128 * k as u128;
    (tmp as u64 & mask(61))
        .wrapping_add((tmp >> 61) as u64)
        .wrapping_add(b)
}

#[inline(always)]
const fn poly_finalize(a: u64) -> u64 {
    let a = (a & mask(61)).wrapping_add(a >> 61);
    let c = (a != mask(61)) as u64 * u64::MAX;
    a & c
}

#[inline(always)]
fn array_from_iter<I, L>(it: I) -> Array<I::Item, L>
where
    I: IntoIterator,
    L: ArraySize,
    I::Item: Default,
{
    let mut v = Array::<I::Item, L>::default();
    v.iter_mut().zip(it).for_each(|(w, r)| *w = r);
    v
}

#[cfg(test)]
mod test {
    #[test]
    fn poly_finalize_mod_2_61() {
        assert_eq!(super::poly_finalize(0), 0);
        assert_eq!(super::poly_finalize((1 << 61) - 2), (1 << 61) - 2);
        assert_eq!(super::poly_finalize((1 << 61) - 1), 0);
        assert_eq!(super::poly_finalize(1 << 61), 1);
    }
}
