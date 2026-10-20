#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]

pub use aead::{self, AeadCore, AeadInOut, Error, Key, KeyInit, KeySizeUser};

use aead::{TagPosition, array::ArraySize, consts::U16, inout::InOutBuf};
use bash_f::{STATE_WORDS, bash_f};
use core::{fmt, marker::PhantomData};
use ctutils::CtEq;

mod variants;
pub use variants::*;

/// Length of the state 𝑆 ∈ {0,1}^1536 in octets.
const STATE_BYTES: usize = 8 * STATE_WORDS;

/// 6-bit data type codes, Table 3 of STB 34.101.77-2020.
const DATA: u8 = 0b000010;
const TEXT: u8 = 0b000011;
const OUT: u8 = 0b000100;

/// `bash-prg-ae` authenticated encryption (STB 34.101.77-2020, 8.13) with
/// security level ℓ = `8 * Size` bits and capacity 𝑑 = `D`.
///
/// The key 𝐾 and the tag 𝑇 are both ℓ bits long. The announcement 𝐴 (nonce)
/// is `NonceSize` octets long, a multiple of 4 not greater than 60.
pub struct BashPrgAe<Size: ArraySize, const D: usize, NonceSize: ArraySize = U16> {
    key: Key<Self>,
    _pd: PhantomData<(Size, NonceSize)>,
}

impl<Size: ArraySize, const D: usize, NonceSize: ArraySize> BashPrgAe<Size, D, NonceSize> {
    /// Security level ℓ in bits.
    const LEVEL: usize = 8 * Size::USIZE;

    /// 8.13.1: 𝐴 ∈ {0,1}^32* and |𝐴| ≤ 480.
    const CHECK_NONCE: () = assert!(
        NonceSize::USIZE % 4 == 0 && NonceSize::USIZE <= 60,
        "nonce length must be a multiple of 4 octets not greater than 60"
    );
}

impl<Size: ArraySize, const D: usize, NonceSize: ArraySize> KeySizeUser
    for BashPrgAe<Size, D, NonceSize>
{
    type KeySize = Size;
}

impl<Size: ArraySize, const D: usize, NonceSize: ArraySize> KeyInit
    for BashPrgAe<Size, D, NonceSize>
{
    #[inline]
    fn new(key: &Key<Self>) -> Self {
        let () = Self::CHECK_NONCE;
        Self {
            key: key.clone(),
            _pd: PhantomData,
        }
    }
}

impl<Size: ArraySize, const D: usize, NonceSize: ArraySize> AeadCore
    for BashPrgAe<Size, D, NonceSize>
{
    type NonceSize = NonceSize;
    type TagSize = Size;
    const TAG_POSITION: TagPosition = TagPosition::Postfix;
}

// Note 1 of 8.13: if 𝐼 = ⊥, step 2.1 may be skipped; if 𝑋 = ⊥, step 2.2 may
// be simplified to 𝑌 ← ⊥. This changes the tag; the test vectors of the
// STB 34.101.77 test methodology (BASH.PRG.AE*.2, *.3) require both.
impl<Size: ArraySize, const D: usize, NonceSize: ArraySize> AeadInOut
    for BashPrgAe<Size, D, NonceSize>
{
    fn encrypt_inout_detached(
        &self,
        nonce: &aead::Nonce<Self>,
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
    ) -> Result<aead::Tag<Self>, Error> {
        // 1. α.start[ℓ, 𝑑](𝐴, 𝐾)
        let mut a = Automaton::start(Self::LEVEL, D, nonce, &self.key);

        // 2.1. α.absorb(𝐼)
        if !associated_data.is_empty() {
            a.absorb(associated_data);
        }

        // 2.2. 𝑌 ← α.encrypt(𝑋)
        if !buffer.is_empty() {
            a.encrypt(buffer.into_out_with_copied_in());
        }

        // 2.3. 𝑇 ← α.squeeze(ℓ)
        let mut tag = aead::Tag::<Self>::default();
        a.squeeze(&mut tag);

        // 2.4. Return (𝑌, 𝑇)
        Ok(tag)
    }

    fn decrypt_inout_detached(
        &self,
        nonce: &aead::Nonce<Self>,
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
        tag: &aead::Tag<Self>,
    ) -> Result<(), Error> {
        // 1. α.start[ℓ, 𝑑](𝐴, 𝐾)
        let mut a = Automaton::start(Self::LEVEL, D, nonce, &self.key);

        // 2.1. α.absorb(𝐼)
        if !associated_data.is_empty() {
            a.absorb(associated_data);
        }
        let mut saved = a.clone();

        // 2.2. 𝑋 ← α.decrypt(𝑌)
        let buf = buffer.into_out_with_copied_in();
        if !buf.is_empty() {
            a.decrypt(buf);
        }

        // 2.3. If 𝑇 ≠ α.squeeze(ℓ), return ⊥
        let mut tag_exact = aead::Tag::<Self>::default();
        a.squeeze(&mut tag_exact);
        if tag_exact.ct_eq(tag).into() {
            // 2.4. Return 𝑋
            Ok(())
        } else {
            // 8.13.2: 𝑋 is a variable until the tag is checked and must be
            // cleared if the tag is wrong. Restore 𝑌 in its place.
            saved.encrypt(buf);
            Err(Error)
        }
    }
}

impl<Size: ArraySize, const D: usize, NonceSize: ArraySize> Clone
    for BashPrgAe<Size, D, NonceSize>
{
    fn clone(&self) -> Self {
        Self::new(&self.key)
    }
}

impl<Size: ArraySize, const D: usize, NonceSize: ArraySize> fmt::Debug
    for BashPrgAe<Size, D, NonceSize>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BashPrgAe{}{D} {{ ... }}", Self::LEVEL)
    }
}

impl<Size: ArraySize, const D: usize, NonceSize: ArraySize> Drop for BashPrgAe<Size, D, NonceSize> {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        zeroize::Zeroize::zeroize(self.key.as_mut_slice());
    }
}

#[cfg(feature = "zeroize")]
impl<Size: ArraySize, const D: usize, NonceSize: ArraySize> zeroize::ZeroizeOnDrop
    for BashPrgAe<Size, D, NonceSize>
{
}

/// Programmable automaton α (STB 34.101.77-2020, 8.1–8.9) in key mode.
///
/// Lengths are in octets, while the standard counts them in bits.
#[derive(Clone)]
struct Automaton {
    /// State 𝑆: buffer 𝑆[..𝑟) followed by memory 𝑆[𝑟..).
    s: [u8; STATE_BYTES],
    /// Current offset in the buffer, 𝑝𝑜𝑠 ∈ {0, 1, …, 𝑟 − 1}.
    pos: usize,
    /// Buffer length 𝑟.
    rate: usize,
}

impl Automaton {
    /// Command `start[ℓ, d](A, K)`, 8.3.
    ///
    /// Announcement and key lengths are fixed by the variant types and always
    /// satisfy 𝐴, 𝐾 ∈ {0,1}^32*, |𝐴|, |𝐾| ≤ 480 and |𝐾| ≥ ℓ.
    fn start(l: usize, d: usize, ann: &[u8], key: &[u8]) -> Self {
        // 1. If 𝐾 ≠ ⊥, then 𝑟 ← 1536 − ℓ − 𝑑ℓ/2
        let rate = STATE_BYTES - (l + d * l / 2) / 8;

        // 3. 𝑝𝑜𝑠 ← 8 + |𝐴| + |𝐾|
        let pos = 1 + ann.len() + key.len();

        // 4. 𝑆[..𝑝𝑜𝑠) ← ⟨|𝐴|/2 + |𝐾|/32⟩_8 ‖ 𝐴 ‖ 𝐾
        // 5. 𝑆[𝑝𝑜𝑠..1472) ← 0^{1472−𝑝𝑜𝑠}
        let mut s = [0u8; STATE_BYTES];
        s[0] = u8::try_from(ann.len() * 4 + key.len() / 4).expect("lengths are at most 60");
        s[1..][..ann.len()].copy_from_slice(ann);
        s[1 + ann.len()..][..key.len()].copy_from_slice(key);

        // 6. 𝑆[1472..) ← ⟨ℓ/4 + 𝑑⟩_64
        s[STATE_BYTES - 8] = u8::try_from(l / 4 + d).expect("l <= 256, d <= 2");

        // 7. Save (ℓ, 𝑑, 𝑟, 𝑝𝑜𝑠) along with 𝑆
        Self { s, pos, rate }
    }

    /// Command `commit(t)`, 8.4.
    fn commit(&mut self, t: u8) {
        // 1. 𝑆[𝑝𝑜𝑠..𝑝𝑜𝑠+8) ← 𝑆[𝑝𝑜𝑠..𝑝𝑜𝑠+8) ⊕ (𝑡 ‖ 01)
        self.s[self.pos] ^= (t << 2) | 0b01;

        // 2. 𝑆[𝑟] ← 𝑆[𝑟] ⊕ 1 (bit 𝑆[𝑟] is the high bit of octet 𝑟/8)
        self.s[self.rate] ^= 0x80;

        // 3. 𝑆 ← bash-f(𝑆)
        self.permute();

        // 4. 𝑝𝑜𝑠 ← 0
        self.pos = 0;
    }

    /// Loop shared by `absorb`, `squeeze`, `encrypt` and `decrypt`:
    ///
    /// 1. (𝑋₁, 𝑋₂, …, 𝑋ₙ) = Split(𝑋, 𝑟)
    /// 2. For 𝑖 = 1, 2, …, 𝑛:
    ///    1. 𝑝𝑜𝑠 ← |𝑋ᵢ|
    ///    2. process 𝑆[..𝑝𝑜𝑠) and 𝑋ᵢ with `f`
    ///    3. if 𝑝𝑜𝑠 = 𝑟, then 𝑆 ← bash-f(𝑆) and 𝑝𝑜𝑠 ← 0
    ///
    /// The data may be split across calls, so the blocks are taken from 𝑝𝑜𝑠
    /// on. `f` gets the state chunk and the offset of the block in the data.
    fn duplex(&mut self, len: usize, mut f: impl FnMut(&mut [u8], usize)) {
        let mut off = 0;
        while off < len {
            let n = (self.rate - self.pos).min(len - off);
            f(&mut self.s[self.pos..][..n], off);
            off += n;
            self.pos += n;
            if self.pos == self.rate {
                self.permute();
                self.pos = 0;
            }
        }
    }

    /// Command `absorb(X)`, 8.6.
    fn absorb(&mut self, x: &[u8]) {
        // 1. commit(DATA)
        self.commit(DATA);

        // 2-3. 𝑆[..𝑝𝑜𝑠) ← 𝑆[..𝑝𝑜𝑠) ⊕ 𝑋ᵢ
        self.duplex(x.len(), |s, off| {
            s.iter_mut().zip(&x[off..]).for_each(|(s, x)| *s ^= x);
        });
    }

    /// Command `squeeze(n)`, 8.7, with 𝑛 = 8 * `y.len()`.
    fn squeeze(&mut self, y: &mut [u8]) {
        // 1. commit(OUT)
        self.commit(OUT);

        // 2-5. 𝑌 ← 𝑌 ‖ 𝑆[..𝑝𝑜𝑠)
        self.duplex(y.len(), |s, off| y[off..][..s.len()].copy_from_slice(s));
    }

    /// Command `encrypt(X)`, 8.8, in place.
    fn encrypt(&mut self, buf: &mut [u8]) {
        // 1. commit(TEXT)
        self.commit(TEXT);

        // 2-4. 𝑆[..𝑝𝑜𝑠) ← 𝑆[..𝑝𝑜𝑠) ⊕ 𝑋ᵢ, 𝑌 ← 𝑌 ‖ 𝑆[..𝑝𝑜𝑠)
        self.duplex(buf.len(), |s, off| {
            for (s, b) in s.iter_mut().zip(&mut buf[off..]) {
                *s ^= *b;
                *b = *s;
            }
        });
    }

    /// Command `decrypt(Y)`, 8.9, in place.
    fn decrypt(&mut self, buf: &mut [u8]) {
        // 1. commit(TEXT)
        self.commit(TEXT);

        // 2-4. 𝑋 ← 𝑋 ‖ (𝑆[..𝑝𝑜𝑠) ⊕ 𝑌ᵢ), 𝑆[..𝑝𝑜𝑠) ← 𝑌ᵢ
        self.duplex(buf.len(), |s, off| {
            for (s, b) in s.iter_mut().zip(&mut buf[off..]) {
                let y = *b;
                *b ^= *s;
                *s = y;
            }
        });
    }

    /// 𝑆 ← bash-f(𝑆), 6.2. Octets of 𝑆 map to 64-bit words little-endian.
    fn permute(&mut self) {
        let mut words = [0u64; STATE_WORDS];
        for (w, chunk) in words.iter_mut().zip(self.s.chunks_exact(8)) {
            *w = u64::from_le_bytes(chunk.try_into().expect("8-byte chunk"));
        }
        bash_f(&mut words);
        for (chunk, w) in self.s.chunks_exact_mut(8).zip(&words) {
            chunk.copy_from_slice(&w.to_le_bytes());
        }
        #[cfg(feature = "zeroize")]
        zeroize::Zeroize::zeroize(&mut words);
    }
}

impl Drop for Automaton {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        zeroize::Zeroize::zeroize(&mut self.s);
    }
}
