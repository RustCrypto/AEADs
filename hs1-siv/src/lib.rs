#![no_std]
#![doc = include_str!("../README.md")]
#![warn(missing_docs, rust_2018_idioms)]

mod hash;

pub use aead;

use aead::{
    array::{
        typenum::{Gr, IsGreater, Prod, Quot, Sub1, Sum, Unsigned},
        Array, ArraySize,
    },
    consts::{False, True, B1, U0, U12, U16, U2, U32, U4, U6, U8},
    AeadCore, AeadInPlace, KeyInit, KeySizeUser,
};
use chacha20::{
    cipher::{StreamCipher, StreamCipherSeek},
    ChaCha12, ChaCha20, ChaCha8, KeyIvInit,
};
use core::{
    marker::PhantomData,
    mem,
    ops::{Add, Div, Mul, Sub},
};
use hash::Hasher;

/// Implementation of HS1-SIV.
///
/// While HS1-SIV takes a key between 1 and 32 bytes,
/// this structure instead stores the derived key,
/// which is substantially larger:
///
/// - `Hs1SivLo`: 128 bytes.
/// - `Hs1SivMe`: 176 bytes.
/// - `Hs1SivHi`: 368 bytes.
#[derive(Clone)]
pub struct Hs1Siv<P>
where
    P: Hs1Params,
{
    key: Hs1Key<P>,
    _marker: PhantomData<P>,
}

/// | `B` | `T` | `C`        | `L` |
/// |-----|-----|------------|-----|
/// |   4 |   2 | `ChaCha8`  |   8 |
///
/// | Key search  | SIV collision                   |
/// |-------------|---------------------------------|
/// | `n/(2^256)` | `(n^2)/(2^56)  + (n^2)/(2^64) ` |
pub type Hs1SivLo = Hs1Siv<params::Hs1SivLo>;

/// | `B` | `T` | `C`        | `L` |
/// |-----|-----|------------|-----|
/// |   4 |   4 | `ChaCha12` |  16 |
///
/// | Key search  | SIV collision                   |
/// |-------------|---------------------------------|
/// | `n/(2^256)` | `(n^2)/(2^112) + (n^2)/(2^128)` |
pub type Hs1SivMe = Hs1Siv<params::Hs1SivMe>;

/// | `B` | `T` | `C`        | `L` |
/// |-----|-----|------------|-----|
/// |   4 |   6 | `ChaCha20` |  32 |
///
/// | Key search  | SIV collision                   |
/// |-------------|---------------------------------|
/// | `n/(2^256)` | `(n^2)/(2^168) + (n^2)/(2^256)` |
pub type Hs1SivHi = Hs1Siv<params::Hs1SivHi>;

impl<P> AeadCore for Hs1Siv<P>
where
    P: Hs1Params,
{
    type TagSize = P::L;
    type NonceSize = U12;
    type CiphertextOverhead = U0;
}

impl<P> AeadInPlace for Hs1Siv<P>
where
    P: Hs1Params,
{
    fn encrypt_in_place_detached(
        &self,
        nonce: &aead::Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> aead::Result<aead::Tag<Self>> {
        hs1_siv_encrypt::<P>(&self.key, nonce, associated_data, buffer)
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &aead::Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &aead::Tag<Self>,
    ) -> aead::Result<()> {
        hs1_siv_decrypt::<P>(&self.key, nonce, associated_data, buffer, tag)
    }
}

impl<P> KeySizeUser for Hs1Siv<P>
where
    P: Hs1Params,
{
    type KeySize = U32;
}

impl<P> KeyInit for Hs1Siv<P>
where
    P: Hs1Params,
{
    fn new(key: &aead::Key<Self>) -> Self {
        assert!((1..=32).contains(&key.len()));
        let key = hs1_subkeygen::<P>(key);
        Self {
            key,
            _marker: PhantomData,
        }
    }
}

/// Definitions of standard parameters for use with HS1-SIV.
///
/// Prefer using the type aliases at the root of the crate instead.
pub mod params {
    use super::*;

    /// | `B` | `T` | `C`        | `L` |
    /// |-----|-----|------------|-----|
    /// |   4 |   2 | `ChaCha8`  |   8 |
    ///
    /// | Key search  | SIV collision                   |
    /// |-------------|---------------------------------|
    /// | `n/(2^256)` | `(n^2)/(2^56)  + (n^2)/(2^64) ` |
    #[derive(Clone, Copy)]
    pub struct Hs1SivLo;

    /// | `B` | `T` | `C`        | `L` |
    /// |-----|-----|------------|-----|
    /// |   4 |   4 | `ChaCha12` |  16 |
    ///
    /// | Key search  | SIV collision                   |
    /// |-------------|---------------------------------|
    /// | `n/(2^256)` | `(n^2)/(2^112) + (n^2)/(2^128)` |
    #[derive(Clone, Copy)]
    pub struct Hs1SivMe;

    /// | `B` | `T` | `C`        | `L` |
    /// |-----|-----|------------|-----|
    /// |   4 |   6 | `ChaCha20` |  32 |
    ///
    /// | Key search  | SIV collision                   |
    /// |-------------|---------------------------------|
    /// | `n/(2^256)` | `(n^2)/(2^168) + (n^2)/(2^256)` |
    #[derive(Clone, Copy)]
    pub struct Hs1SivHi;

    impl Hs1Params for Hs1SivLo {
        type B = U4;
        type T = U2;
        type C = ChaCha8;
        type L = U8;
    }

    impl Hs1Params for Hs1SivMe {
        type B = U4;
        type T = U4;
        type C = ChaCha12;
        type L = U16;
    }

    impl Hs1Params for Hs1SivHi {
        type B = U4;
        type T = U6;
        type C = ChaCha20;
        type L = U32;
    }
}

#[derive(Clone)]
#[repr(C, align(16))]
struct Hs1Key<P: Hs1Params> {
    chacha: Array<u8, U32>,
    hash: Hs1HashKey<P>,
}

#[derive(Clone)]
#[repr(C, align(16))]
struct Hs1HashKey<P: Hs1Params> {
    nh: Array<u32, NhLen<P>>,
    poly: Array<u64, P::T>,
    asu: Array<hash::Asu<P>, P::T>,
}

impl<P: Hs1Params> Hs1Key<P> {
    fn as_bytes_mut(&mut self) -> &mut [u8] {
        // Ensure that all fields have a size which is a multiple of 16.
        // This trivializes the safety proof, since padding is impossible if the check passes.
        const {
            const fn chk<T, L: ArraySize>() {
                assert!(mem::size_of::<Array<T, L>>() % 16 == 0);
            }
            chk::<u8, U32>();
            chk::<u32, NhLen<P>>();
            chk::<u64, P::T>();
            chk::<hash::Asu<P>, P::T>();
        }
        // SAFETY:
        // - There are no padding bytes
        // - There are no invalid bit patterns
        unsafe {
            let len = mem::size_of_val(self);
            let ptr = self as *mut Self as *mut u8;
            core::slice::from_raw_parts_mut(ptr, len)
        }
    }
}

type B16<P> = Prod<<P as Hs1Params>::B, U16>;
type NhLen<P> = Sum<Quot<B16<P>, U4>, Prod<Sub1<<P as Hs1Params>::T>, U4>>;

/// HS1 parameters.
// hey, as long as it works!
pub trait Hs1Params: Copy + Sync + Send
where
    Self::B: Mul<U16> + 'static,
    B16<Self>: ArraySize,
    Self::T: ArraySize,
    Self::L: ArraySize,
    Quot<B16<Self>, U4>: ArraySize,
    // Hs1Key
    Self::T: Sub<B1>,
    Sub1<Self::T>: Mul<U4>,
    B16<Self>: Div<U4>,
    Quot<B16<Self>, U4>: Add<Prod<Sub1<Self::T>, U4>>,
    NhLen<Self>: ArraySize,
    // hs1_hash
    Self::T: IsGreater<U4>,
    Gr<Self::T, U4>: hash::sealed::Hs1HashFinal,
    hash::Output<Self>: Default + AsRef<[u8]>,
{
    /// Block size, in terms of 16 bytes.
    type B;
    /// "collision level" (higher is more secure).
    type T;
    /// ChaCha implementation.
    type C: KeyIvInit<KeySize = U32, IvSize = U12>
        + StreamCipher
        + StreamCipherSeek
        + sealed::ChaChaImpl;
    /// Tag length in bytes.
    type L;
}

mod sealed {
    // Necessary for subkeygen
    pub trait ChaChaImpl {
        const ROUNDS: u8;
    }
}

impl sealed::ChaChaImpl for ChaCha8 {
    const ROUNDS: u8 = 8;
}
impl sealed::ChaChaImpl for ChaCha12 {
    const ROUNDS: u8 = 12;
}
impl sealed::ChaChaImpl for ChaCha20 {
    const ROUNDS: u8 = 20;
}

/// # Note
///
/// `m.len()` may not exceed `2**38`.
fn hs1_siv_encrypt<P: Hs1Params>(
    k: &Hs1Key<P>,
    n: &Array<u8, U12>,
    a: &[u8],
    m: &mut [u8],
) -> Result<Array<u8, P::L>, aead::Error> {
    if m.len() as u128 > 1 << 38 {
        return Err(aead::Error);
    }
    let t = hs1_tag::<P>(k, a, n, &*m);
    hs1::<P>(k, &[&*t], n, 64, m);
    Ok(t)
}

fn hs1_siv_decrypt<P: Hs1Params>(
    k: &Hs1Key<P>,
    n: &Array<u8, U12>,
    a: &[u8],
    m: &mut [u8],
    t: &Array<u8, P::L>,
) -> Result<(), aead::Error> {
    if m.len() as u128 > 1 << 38 {
        return Err(aead::Error);
    }
    hs1::<P>(k, &[t], n, 64, m);
    let t2 = hs1_tag::<P>(k, a, n, m);
    let diff = t.iter().zip(t2.iter()).fold(0, |s, (x, y)| s | (x ^ y));
    (diff == 0).then_some(()).ok_or_else(|| {
        // Apparently keeping the plaintext is CVE-worthy (CVE-2023-42811)
        // No way in hell I'm running the cipher again - just zero out the buffer
        m.fill(0);
        aead::Error
    })
}

fn hs1_tag<P: Hs1Params>(k: &Hs1Key<P>, a: &[u8], n: &Array<u8, U12>, m: &[u8]) -> Array<u8, P::L> {
    let a_m_len = &mut [0; 16];
    a_m_len[..8].copy_from_slice(&(a.len() as u64).to_le_bytes());
    a_m_len[8..].copy_from_slice(&(m.len() as u64).to_le_bytes());
    let m2 = &[a, m, a_m_len];
    let mut t = Array::<u8, P::L>::default();
    hs1::<P>(k, m2, n, 0, &mut t);
    t
}

#[inline(always)]
fn hs1<P: Hs1Params>(k: &Hs1Key<P>, m: &[&[u8]], n: &Array<u8, U12>, y_offset: u32, y: &mut [u8]) {
    let mut key = k.chacha;

    let mut hasher = Hasher::<P>::new(&k.hash);
    for (i, b) in m.iter().enumerate() {
        if i > 0 {
            hasher.pad_to(4);
        }
        hasher.update(b);
    }
    let input = hasher.finalize();

    key.iter_mut()
        .zip(input.iter().flat_map(|x| x.as_ref()))
        .for_each(|(w, r)| *w ^= *r);
    let mut cipher = P::C::new(&key, n);
    cipher.seek(y_offset);
    cipher.apply_keystream(y)
}

fn hs1_subkeygen<P: Hs1Params>(k: &[u8]) -> Hs1Key<P> {
    assert!((1..=32).contains(&k.len()));

    let k2 = &mut Array::<u8, U32>::default();
    k2.iter_mut()
        .zip(k.iter().cycle())
        .for_each(|(w, r)| *w = *r);

    let n = &mut Array::<u8, U12>::default();
    debug_assert!(k.len() < 256);
    debug_assert!(P::L::U64 < 256);
    debug_assert!(P::T::U64 < 256);
    debug_assert!(B16::<P>::U64 < 256);
    n[0] = k.len() as u8;
    n[2] = P::L::to_u8();
    n[4] = <P::C as sealed::ChaChaImpl>::ROUNDS;
    n[5] = P::T::to_u8();
    n[6] = B16::<P>::to_u8();

    let mut k = Hs1Key {
        chacha: Array::default(),
        hash: Hs1HashKey {
            nh: Array::default(),
            poly: Array::default(),
            asu: Array::default(),
        },
    };

    <P::C as KeyIvInit>::new(k2, n).apply_keystream(k.as_bytes_mut());
    k.hash.poly.iter_mut().for_each(|p| *p &= mask(60));

    k
}

#[inline(always)]
const fn mask(bits: u8) -> u64 {
    (1u64 << bits).wrapping_sub(1)
}

#[cfg(test)]
mod test {
    use super::*;
    use aead::{Aead, KeyInit};

    const MSG: &[u8] = b"Hello to the entire wide, round, global globe!";
    const KEY: &[u8; 32] = b"Short keys? Use long for testing";
    const NONCE: &[u8; 12] = b"Quack quack!";

    fn hs1siv<P: Hs1Params>() {
        let hs1 = Hs1Siv::<P>::new(KEY.into());
        let cph = hs1.encrypt(NONCE.into(), MSG).unwrap();
        let msg = hs1.decrypt(NONCE.into(), &*cph).unwrap();
        assert_eq!(&msg, MSG);
    }

    #[test]
    fn hs1siv_me() {
        hs1siv::<params::Hs1SivMe>();
    }

    #[test]
    fn hs1siv_lo() {
        hs1siv::<params::Hs1SivLo>();
    }

    #[test]
    fn hs1siv_hi() {
        hs1siv::<params::Hs1SivHi>();
    }

    /// Custom generated vectors using (reference implementation)[0].
    ///
    /// [0]: https://bench.cr.yp.to/supercop.html
    mod test_vectors {
        use super::*;

        #[test]
        fn subkeygen_me() {
            let k = hs1_subkeygen::<params::Hs1SivMe>(KEY);
            assert_eq!(
                k.chacha,
                [
                    0x02, 0xea, 0xb5, 0x34, 0x85, 0x3e, 0xf7, 0xf4, 0x81, 0x3f, 0x87, 0xd8, 0xd2,
                    0x63, 0x1e, 0x05, 0xf9, 0x68, 0x91, 0xd0, 0x8a, 0x03, 0x34, 0xfc, 0x64, 0xbe,
                    0x6b, 0x3a, 0x89, 0xfe, 0x20, 0x8d,
                ]
            );
            assert_eq!(
                k.hash.nh,
                [
                    0x74e7102f, 0x374603b7, 0xf470c90c, 0x8c829c82, 0x07d6f293, 0xf9e7e569,
                    0xcd590406, 0xe6bdc9ad, 0xa2687cda, 0xfc1a8b80, 0x501efbee, 0x0df51d32,
                    0x7fd3f594, 0xc3d1520b, 0x1b83db2f, 0x0791c054, 0x66583c46, 0xcb096241,
                    0x7afc8085, 0x4b37d47a, 0x540287e0, 0xe1ace58b, 0x4f125f3b, 0xb69b5935,
                    0x6cb2cf06, 0xbf86407b, 0x18a6a2e5, 0xe1eaa248,
                ]
            );
            assert_eq!(
                k.hash.poly,
                [
                    0x09aad6627602f656,
                    0x07f2089068131f87,
                    0x0a982e724caf2722,
                    0x004f2d42b1092d0a,
                ]
            );
            assert_eq!(k.hash.asu, [[]; 4]);
        }

        #[test]
        fn subkeygen_lo() {
            let k = hs1_subkeygen::<params::Hs1SivLo>(KEY);
            assert_eq!(
                k.chacha,
                [
                    0xab, 0x1b, 0x65, 0x62, 0xe5, 0x4c, 0x79, 0x27, 0x30, 0xa3, 0x4c, 0xa6, 0x7e,
                    0x79, 0x0f, 0xb9, 0xa9, 0x85, 0x62, 0xb2, 0x17, 0x2e, 0x47, 0x99, 0xe3, 0x7a,
                    0x0c, 0x63, 0x77, 0xc4, 0x85, 0xca,
                ]
            );
            assert_eq!(
                k.hash.nh,
                [
                    0xd743ff76, 0x64b9e928, 0x0effa5ae, 0xf850ec1d, 0xda1249a9, 0x29afefcf,
                    0x18bb4916, 0x35d0b524, 0x2036f9c4, 0x0ae224a6, 0x98f18f97, 0x3aad32e2,
                    0x85256859, 0x30e4ad2e, 0x63b08461, 0x13c97c7d, 0xe4d45609, 0x0ca44ba2,
                    0x6c4b356e, 0x9b960e6b,
                ]
            );
            assert_eq!(k.hash.poly, [0x0ef85bac983cb194, 0x0a584b5179c75231]);
            assert_eq!(k.hash.asu, [[]; 2]);
        }

        #[test]
        fn hash_me() {
            let k = hs1_subkeygen::<params::Hs1SivMe>(KEY);
            let h = Hasher::new(&k.hash).update(MSG).finalize();
            assert_eq!(
                h,
                [
                    0x1808a23d991ae22c,
                    0x08f96bf01b438f3b,
                    0x194ee1ffd24b84a0,
                    0x0b25578352a73e9d,
                ]
                .map(u64::to_le_bytes)
            );
        }

        #[test]
        fn hash_me_64() {
            const MSG64: &[u8; 64] =
                b"Hello to the entire wide, round, global globe!!! okookokokokokok";
            let k = hs1_subkeygen::<params::Hs1SivMe>(KEY);
            let h = Hasher::new(&k.hash).update(MSG64).finalize();
            assert_eq!(
                h,
                [
                    0x0f128a7f7b601324,
                    0x0dc82e748a2a1395,
                    0x106966138221d2ba,
                    0x09f86f41d6677d4d,
                ]
                .map(u64::to_le_bytes)
            );
        }

        #[test]
        fn hash_lo() {
            let k = hs1_subkeygen::<params::Hs1SivLo>(KEY);
            let h = Hasher::new(&k.hash).update(MSG).finalize();
            assert_eq!(
                h,
                [0x1afa0c19eba9a66b, 0x15ceb31a087f2657,].map(u64::to_le_bytes)
            );
        }

        #[test]
        fn hash_hi() {
            let k = hs1_subkeygen::<params::Hs1SivHi>(KEY);
            let h = Hasher::new(&k.hash).update(MSG).finalize();
            assert_eq!(
                h,
                [0xcf452c22, 0x452317a2, 0x7fa1f1d6, 0x100d9702, 0xcf1defb0, 0x4c73da69,]
                    .map(u32::to_le_bytes)
            );
        }

        // TODO I'm 99% sure this is wrong according to the paper,
        // but it shouldn't be an issue as long as we don't expose the hasher
        // to the public...
        #[test]
        fn hash_me_empty() {
            let k = hs1_subkeygen::<params::Hs1SivMe>(KEY);
            let h = Hasher::new(&k.hash).finalize();
            assert_eq!(
                h,
                [
                    0x0000000000000001,
                    0x0000000000000001,
                    0x0000000000000001,
                    0x0000000000000001,
                ]
                .map(u64::to_le_bytes)
            );
        }

        #[test]
        fn hs1siv_me() {
            let hs1 = Hs1SivMe::new(KEY.into());
            let cph = hs1.encrypt(NONCE.into(), MSG).unwrap();
            assert_eq!(
                &cph,
                &[
                    0x1b, 0x26, 0x40, 0x4d, 0xe3, 0x46, 0xb3, 0x65, 0x07, 0xa7, 0x93, 0xf3, 0x6e,
                    0xab, 0xb5, 0xcb, 0x1a, 0x99, 0x7c, 0xbf, 0xdf, 0x6c, 0xed, 0x15, 0xd9, 0xd0,
                    0x26, 0x37, 0xf7, 0xcc, 0xd4, 0xb1, 0x20, 0xee, 0x02, 0x52, 0x3c, 0xee, 0xcc,
                    0x41, 0x04, 0xbf, 0x42, 0xa9, 0xfc, 0x2e, 0x45, 0x06, 0x67, 0xa6, 0xfe, 0x07,
                    0x2f, 0x00, 0x81, 0x72, 0x52, 0xa8, 0xb0, 0xb1, 0x2e, 0xd6,
                ]
            );
        }

        #[test]
        fn hs1siv_lo() {
            let hs1 = Hs1SivLo::new(KEY.into());
            let cph = hs1.encrypt(NONCE.into(), MSG).unwrap();
            assert_eq!(
                &cph,
                &[
                    0xa8, 0xac, 0xcd, 0x91, 0x09, 0x39, 0xac, 0x6a, 0x13, 0x81, 0xa3, 0xa4, 0xbe,
                    0xa1, 0xc9, 0x97, 0xa7, 0xda, 0xe6, 0x5e, 0x73, 0xd6, 0x0f, 0x2e, 0x87, 0xcf,
                    0xe7, 0x20, 0xaf, 0x0d, 0x94, 0x45, 0xaa, 0x9b, 0x91, 0xf2, 0x11, 0x33, 0x48,
                    0xc5, 0x7d, 0x0f, 0xd8, 0xda, 0xd7, 0x9a, 0x3d, 0xcf, 0x63, 0xea, 0xda, 0x32,
                    0x7c, 0xa6,
                ]
            );
        }

        #[test]
        fn hs1siv_hi() {
            let hs1 = Hs1SivHi::new(KEY.into());
            let cph = hs1.encrypt(NONCE.into(), MSG).unwrap();
            assert_eq!(
                &cph,
                &[
                    0xbc, 0x5d, 0xbb, 0x49, 0x52, 0x97, 0xb8, 0xb0, 0xab, 0x3a, 0x0b, 0x69, 0xb0,
                    0x60, 0xd2, 0x75, 0xd1, 0x4e, 0x14, 0x73, 0x8f, 0xe3, 0xb6, 0x14, 0xb0, 0x06,
                    0x01, 0x96, 0x4f, 0x90, 0x6e, 0x6a, 0x67, 0x71, 0xd0, 0x71, 0xf0, 0x4b, 0xc9,
                    0xf8, 0x14, 0x54, 0x30, 0xe3, 0x33, 0xb0, 0x09, 0x97, 0x47, 0xf4, 0x8c, 0xd0,
                    0x60, 0xae, 0x68, 0x40, 0xcb, 0x58, 0x64, 0x6b, 0xf9, 0x66, 0x5f, 0x58, 0xfa,
                    0xdf, 0xd0, 0x50, 0xa7, 0x00, 0x43, 0x55, 0x5e, 0x63, 0xe9, 0x89, 0x31, 0x29,
                ]
            );
        }
    }
}
