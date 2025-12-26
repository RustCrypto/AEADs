#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

//! # Usage
//!
//! Simple usage (allocating, no associated data):
//!
#![cfg_attr(feature = "getrandom", doc = "```")]
#![cfg_attr(not(feature = "getrandom"), doc = "```ignore")]
//! # fn main() -> Result<(), Box<dyn core::error::Error>> {
//! // NOTE: requires the `getrandom` feature is enabled
//!
//! use aes::Aes256;
//! use ccm::{
//!     aead::{Aead, AeadCore, Generate, Key, KeyInit, Nonce},
//!     consts::{U10, U13},
//!     Ccm,
//! };
//!
//! // AES-256-CCM type with tag and nonce size equal to 10 and 13 bytes respectively
//! pub type Aes256Ccm = Ccm<Aes256, U10, U13>;
//!
//! let key = Key::<Aes256Ccm>::generate();
//! let cipher = Aes256Ccm::new(&key);
//!
//! let nonce = Nonce::<Aes256Ccm>::generate(); // MUST be unique per message
//! let ciphertext = cipher.encrypt(&nonce, b"plaintext message".as_ref())?;
//!
//! let plaintext = cipher.decrypt(&nonce, ciphertext.as_ref())?;
//! assert_eq!(&plaintext, b"plaintext message");
//! # Ok(())
//! # }
//! ```
//!
//! ## In-place Usage (eliminates `alloc` requirement)
//!
//! This crate has an optional `alloc` feature which can be disabled in e.g.
//! microcontroller environments that don't have a heap.
//!
//! The [`AeadInOut::encrypt_in_place`] and [`AeadInOut::decrypt_in_place`]
//! methods accept any type that impls the [`aead::Buffer`] trait which
//! contains the plaintext for encryption or ciphertext for decryption.
//!
//! Enabling the `arrayvec` feature of this crate will provide an impl of
//! [`aead::Buffer`] for `arrayvec::ArrayVec` (re-exported from the [`aead`] crate as
//! [`aead::arrayvec::ArrayVec`]), and enabling the `bytes` feature of this crate will
//! provide an impl of [`aead::Buffer`] for `bytes::BytesMut` (re-exported from the
//! [`aead`] crate as [`aead::bytes::BytesMut`]).
//!
//! It can then be passed as the `buffer` parameter to the in-place encrypt
//! and decrypt methods:
//!
#![cfg_attr(all(feature = "getrandom", feature = "arrayvec"), doc = "```")]
#![cfg_attr(
    not(all(feature = "getrandom", feature = "arrayvec")),
    doc = "```ignore"
)]
//! # fn main() -> Result<(), Box<dyn core::error::Error>> {
//! use aes::Aes256;
//! use ccm::{
//!     aead::{AeadCore, AeadInOut, Generate, Key, KeyInit, Nonce, arrayvec::ArrayVec},
//!     consts::{U10, U13},
//!     Ccm,
//! };
//!
//! // AES-256-CCM type with tag and nonce size equal to 10 and 13 bytes respectively
//! pub type Aes256Ccm = Ccm<Aes256, U10, U13>;
//!
//! let key = Key::<Aes256Ccm>::generate();
//! let cipher = Aes256Ccm::new(&key);
//!
//! let nonce = Nonce::<Aes256Ccm>::generate(); // MUST be unique per message
//! let mut buffer: ArrayVec<u8, 128> = ArrayVec::new(); // Note: buffer needs 16-bytes overhead for auth tag
//! buffer.try_extend_from_slice(b"plaintext message").unwrap();
//!
//! // Encrypt `buffer` in-place, replacing the plaintext contents with ciphertext
//! cipher.encrypt_in_place(&nonce, b"", &mut buffer)?;
//!
//! // `buffer` now contains the message ciphertext
//! assert_ne!(buffer.as_ref(), b"plaintext message");
//!
//! // Decrypt `buffer` in-place, replacing its ciphertext context with the original plaintext
//! cipher.decrypt_in_place(&nonce, b"", &mut buffer)?;
//! assert_eq!(buffer.as_ref(), b"plaintext message");
//! # Ok(())
//! # }

pub use aead::{self, AeadCore, AeadInOut, Error, Key, KeyInit, KeySizeUser, consts};

use aead::{
    TagPosition,
    array::{Array, ArraySize, typenum::Unsigned},
    consts::U16,
    inout::InOutBuf,
};
use cipher::{
    Block, BlockCipherEncrypt, BlockSizeUser, InnerIvInit, StreamCipher, StreamCipherSeek,
};
use core::marker::PhantomData;
use ctr::{Ctr32BE, Ctr64BE, CtrCore};
use subtle::ConstantTimeEq;

mod private;

/// CCM nonces
pub type Nonce<NonceSize> = Array<u8, NonceSize>;

/// CCM tags
pub type Tag<TagSize> = Array<u8, TagSize>;

/// Trait implemented for valid tag sizes, i.e.
/// [`U4`][consts::U4], [`U6`][consts::U6], [`U8`][consts::U8],
/// [`U10`][consts::U10], [`U12`][consts::U12], [`U14`][consts::U14], and
/// [`U16`][consts::U16].
pub trait TagSize: private::SealedTag {}

impl<T: private::SealedTag> TagSize for T {}

/// Trait implemented for valid nonce sizes, i.e.
/// [`U7`][consts::U7], [`U8`][consts::U8], [`U9`][consts::U9],
/// [`U10`][consts::U10], [`U11`][consts::U11], [`U12`][consts::U12], and
/// [`U13`][consts::U13].
pub trait NonceSize: private::SealedNonce {}

impl<T: private::SealedNonce> NonceSize for T {}

/// CCM instance generic over an underlying block cipher.
///
/// Type parameters:
/// - `C`: block cipher.
/// - `M`: size of MAC tag in bytes, valid values:
///   [`U4`][consts::U4], [`U6`][consts::U6], [`U8`][consts::U8],
///   [`U10`][consts::U10], [`U12`][consts::U12], [`U14`][consts::U14],
///   [`U16`][consts::U16].
/// - `N`: size of nonce, valid values:
///   [`U7`][consts::U7], [`U8`][consts::U8], [`U9`][consts::U9],
///   [`U10`][consts::U10], [`U11`][consts::U11], [`U12`][consts::U12],
///   [`U13`][consts::U13].
#[derive(Clone)]
pub struct Ccm<C, M, N>
where
    C: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt,
    M: ArraySize + TagSize,
    N: ArraySize + NonceSize,
{
    cipher: C,
    _pd: PhantomData<(M, N)>,
}

impl<C, M, N> Ccm<C, M, N>
where
    C: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt,
    M: ArraySize + TagSize,
    N: ArraySize + NonceSize,
{
    fn extend_nonce(nonce: &Nonce<N>) -> Block<C> {
        let mut ext_nonce = Block::<C>::default();
        ext_nonce[0] = N::get_l() - 1;
        ext_nonce[1..][..nonce.len()].copy_from_slice(nonce);
        ext_nonce
    }

    fn calc_mac(
        &self,
        nonce: &Nonce<N>,
        adata: &[u8],
        buffer: &[u8],
    ) -> Result<Tag<C::BlockSize>, Error> {
        let is_ad = !adata.is_empty();
        let l = N::get_l();
        let flags = 64 * (is_ad as u8) + 8 * M::get_m_tick() + (l - 1);

        if buffer.len() > N::get_max_len() {
            return Err(Error);
        }

        let mut b0 = Block::<C>::default();
        b0[0] = flags;
        let n = 1 + N::to_usize();
        b0[1..n].copy_from_slice(nonce);

        let cb = b0.len() - n;
        // the max len check makes certain that we discard only
        // zero bytes from `b`
        if cb > 4 {
            let b = (buffer.len() as u64).to_be_bytes();
            b0[n..].copy_from_slice(&b[b.len() - cb..]);
        } else {
            let b = (buffer.len() as u32).to_be_bytes();
            b0[n..].copy_from_slice(&b[b.len() - cb..]);
        }

        let mut mac = CbcMac::from_cipher(&self.cipher);
        mac.block_update(&b0);

        if !adata.is_empty() {
            let alen = adata.len();
            let (n, mut b) = fill_aad_header(alen);
            if b.len() - n >= alen {
                b[n..][..alen].copy_from_slice(adata);
                mac.block_update(&b);
            } else {
                let (l, r) = adata.split_at(b.len() - n);
                b[n..].copy_from_slice(l);
                mac.block_update(&b);
                mac.update(r);
            }
        }

        mac.update(buffer);

        Ok(mac.finalize())
    }
}

impl<C, M, N> From<C> for Ccm<C, M, N>
where
    C: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt,
    M: ArraySize + TagSize,
    N: ArraySize + NonceSize,
{
    fn from(cipher: C) -> Self {
        Self {
            cipher,
            _pd: PhantomData,
        }
    }
}

impl<C, M, N> KeySizeUser for Ccm<C, M, N>
where
    C: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt + KeyInit,
    M: ArraySize + TagSize,
    N: ArraySize + NonceSize,
{
    type KeySize = C::KeySize;
}

impl<C, M, N> KeyInit for Ccm<C, M, N>
where
    C: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt + KeyInit,
    M: ArraySize + TagSize,
    N: ArraySize + NonceSize,
{
    fn new(key: &Key<Self>) -> Self {
        Self::from(C::new(key))
    }
}

impl<C, M, N> AeadCore for Ccm<C, M, N>
where
    C: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt,
    M: ArraySize + TagSize,
    N: ArraySize + NonceSize,
{
    type NonceSize = N;
    type TagSize = M;
    const TAG_POSITION: TagPosition = TagPosition::Postfix;
}

impl<C, M, N> AeadInOut for Ccm<C, M, N>
where
    C: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt,
    M: ArraySize + TagSize,
    N: ArraySize + NonceSize,
{
    fn encrypt_inout_detached(
        &self,
        nonce: &Nonce<N>,
        adata: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
    ) -> Result<Tag<Self::TagSize>, Error> {
        let mut full_tag = self.calc_mac(nonce, adata, buffer.get_in())?;

        let ext_nonce = Self::extend_nonce(nonce);
        // number of bytes left for counter (max 8)
        let cb = C::BlockSize::USIZE - N::USIZE - 1;

        if cb > 4 {
            let mut ctr = Ctr64BE::from_core(CtrCore::inner_iv_init(&self.cipher, &ext_nonce));
            ctr.apply_keystream(&mut full_tag);
            ctr.apply_keystream_inout(buffer);
        } else {
            let mut ctr = Ctr32BE::from_core(CtrCore::inner_iv_init(&self.cipher, &ext_nonce));
            ctr.apply_keystream(&mut full_tag);
            ctr.apply_keystream_inout(buffer);
        }

        Ok(Tag::try_from(&full_tag[..M::to_usize()]).expect("tag size mismatch"))
    }

    fn decrypt_inout_detached(
        &self,
        nonce: &Nonce<N>,
        adata: &[u8],
        mut buffer: InOutBuf<'_, '_, u8>,
        tag: &Tag<Self::TagSize>,
    ) -> Result<(), Error> {
        let ext_nonce = Self::extend_nonce(nonce);
        // number of bytes left for counter (max 8)
        let cb = C::BlockSize::USIZE - N::USIZE - 1;

        if cb > 4 {
            let mut ctr = Ctr64BE::from_core(CtrCore::inner_iv_init(&self.cipher, &ext_nonce));
            ctr.seek(C::BlockSize::USIZE);
            ctr.apply_keystream_inout(buffer.reborrow());
        } else {
            let mut ctr = Ctr32BE::from_core(CtrCore::inner_iv_init(&self.cipher, &ext_nonce));
            ctr.seek(C::BlockSize::USIZE);
            ctr.apply_keystream_inout(buffer.reborrow());
        }

        let mut full_tag = self.calc_mac(nonce, adata, buffer.get_out())?;

        if cb > 4 {
            let mut ctr = Ctr64BE::from_core(CtrCore::inner_iv_init(&self.cipher, &ext_nonce));
            ctr.apply_keystream(&mut full_tag);
        } else {
            let mut ctr = Ctr32BE::from_core(CtrCore::inner_iv_init(&self.cipher, &ext_nonce));
            ctr.apply_keystream(&mut full_tag);
        }

        if full_tag[..tag.len()].ct_eq(tag).into() {
            Ok(())
        } else {
            buffer.get_out().fill(0);
            Err(Error)
        }
    }
}

struct CbcMac<'a, C: BlockCipherEncrypt> {
    cipher: &'a C,
    state: Block<C>,
}

impl<'a, C> CbcMac<'a, C>
where
    C: BlockCipherEncrypt,
{
    fn from_cipher(cipher: &'a C) -> Self {
        Self {
            cipher,
            state: Default::default(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        let (blocks, rem) = Block::<C>::slice_as_chunks(data);

        for block in blocks {
            self.block_update(block);
        }

        if !rem.is_empty() {
            let mut bn = Block::<C>::default();
            bn[..rem.len()].copy_from_slice(rem);
            self.block_update(&bn);
        }
    }

    fn block_update(&mut self, block: &Block<C>) {
        self.state
            .iter_mut()
            .zip(block.iter())
            .for_each(|(a, b)| *a ^= b);
        self.cipher.encrypt_block(&mut self.state);
    }

    fn finalize(self) -> Block<C> {
        self.state
    }
}

fn fill_aad_header(adata_len: usize) -> (usize, Array<u8, U16>) {
    debug_assert_ne!(adata_len, 0);

    let mut b = Array::<u8, U16>::default();
    let n = if adata_len < 0xFF00 {
        b[..2].copy_from_slice(&(adata_len as u16).to_be_bytes());
        2
    } else if adata_len <= u32::MAX as usize {
        b[0] = 0xFF;
        b[1] = 0xFE;
        b[2..6].copy_from_slice(&(adata_len as u32).to_be_bytes());
        6
    } else {
        b[0] = 0xFF;
        b[1] = 0xFF;
        b[2..10].copy_from_slice(&(adata_len as u64).to_be_bytes());
        10
    };
    (n, b)
}

#[cfg(test)]
mod tests {
    #[test]
    fn fill_aad_header_test() {
        use super::fill_aad_header;
        use hex_literal::hex;

        let (n, b) = fill_aad_header(0x0123);
        assert_eq!(n, 2);
        assert_eq!(b[..], hex!("01230000000000000000000000000000")[..]);

        let (n, b) = fill_aad_header(0xFF00);
        assert_eq!(n, 6);
        assert_eq!(b[..], hex!("FFFE0000FF0000000000000000000000")[..]);

        let (n, b) = fill_aad_header(0x01234567);
        assert_eq!(n, 6);
        assert_eq!(b[..], hex!("FFFE0123456700000000000000000000")[..]);

        #[cfg(target_pointer_width = "64")]
        {
            let (n, b) = fill_aad_header(0x0123456789ABCDEF);
            assert_eq!(n, 10);
            assert_eq!(b[..], hex!("FFFF0123456789ABCDEF000000000000")[..]);
        }
    }
}
