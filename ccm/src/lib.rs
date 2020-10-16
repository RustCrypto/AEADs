//! Counter with CBC-MAC ([CCM]): [Authenticated Encryption and Associated Data (AEAD)][1]
//! algorithm generic over block ciphers with block size equal to 128 bits as specified in
//! [RFC 3610].
//!
//! # Usage
//!
//! Simple usage (allocating, no associated data):
//!
//! ```
//! use ccm::{Ccm, consts::{U10, U13}};
//! use ccm::aead::{Aead, NewAead, generic_array::GenericArray};
//! use aes::Aes256;
//!
//! // AES-CCM type with tag and nonce size equal to 10 and 13 bytes respectively
//! type AesCcm = Ccm<Aes256, U10, U13>;
//!
//! let key = GenericArray::from_slice(b"an example very very secret key.");
//! let cipher = AesCcm::new(key);
//!
//! let nonce = GenericArray::from_slice(b"unique nonce."); // 13-bytes; unique per message
//!
//! let ciphertext = cipher.encrypt(nonce, b"plaintext message".as_ref())
//!     .expect("encryption failure!"); // NOTE: handle this error to avoid panics!
//!
//! let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
//!     .expect("decryption failure!"); // NOTE: handle this error to avoid panics!
//!
//! assert_eq!(&plaintext, b"plaintext message");
//! ```
//! This crate implements traits from the [`aead`] crate and is capable to perfrom
//! encryption and decryption in-place wihout relying on `alloc`.
//!
//! [RFC 3610]: https://tools.ietf.org/html/rfc3610
//! [CCM]: https://en.wikipedia.org/wiki/CCM_mode
//! [aead]: https://docs.rs/aead
//! [1]: https://en.wikipedia.org/wiki/Authenticated_encryption
#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]
pub use aead;
pub use aead::consts;

use aead::{
    consts::{U0, U16},
    generic_array::{typenum::Unsigned, ArrayLength},
    AeadInPlace, Error, Key, NewAead, Nonce, Tag,
};
use cipher::block::{Block, BlockCipher, NewBlockCipher};
use core::marker::PhantomData;
use subtle::ConstantTimeEq;

mod traits;

use traits::{NonceSize, TagSize};

/// CCM instance generic over an underlying block cipher.
///
/// Type parameters:
/// - `C`: block cipher.
/// - `M`: size of MAC tag, valid values:
/// `U4`, `U6`, `U8`, `U10`, `U12`, `U14`, `U16`.
/// - `N`: size of nonce, valid values:
/// `U7`, `U8`, `U9`, `U10`, `U11`, `U12`, `U13`.
pub struct Ccm<C, M, N>
where
    C: BlockCipher<BlockSize = U16>,
    C::ParBlocks: ArrayLength<Block<C>>,
    M: ArrayLength<u8> + TagSize,
    N: ArrayLength<u8> + NonceSize,
{
    cipher: C,
    _tag_size: PhantomData<M>,
    _nonce_size: PhantomData<N>,
}

impl<C, M, N> Ccm<C, M, N>
where
    C: BlockCipher<BlockSize = U16>,
    C::ParBlocks: ArrayLength<Block<C>>,
    M: ArrayLength<u8> + TagSize,
    N: ArrayLength<u8> + NonceSize,
{
    fn from_cipher(cipher: C) -> Self {
        Self {
            cipher,
            _tag_size: Default::default(),
            _nonce_size: Default::default(),
        }
    }

    fn gen_enc_block(block: &mut Block<C>, nonce: &Nonce<N>, i: usize) {
        block[0] = N::get_l() - 1;
        let n = 1 + N::to_usize();
        block[1..n].copy_from_slice(nonce);
        let b = &mut block[n..];
        let arr = i.to_be_bytes();
        b.copy_from_slice(&arr[arr.len() - b.len()..])
    }

    fn calc_mac(
        &self,
        nonce: &Nonce<N>,
        adata: &[u8],
        buffer: &[u8],
    ) -> Result<Tag<C::BlockSize>, Error> {
        let bs = C::BlockSize::to_usize();
        let is_ad = !adata.is_empty();
        let l = N::get_l();
        let flags = 64 * (is_ad as u8) + 8 * M::get_m_tick() + (l - 1);

        if buffer.len() > N::get_max_len() {
            return Err(Error);
        }
        let l_arr = buffer.len().to_be_bytes();

        let mut b0 = Block::<C>::default();
        b0[0] = flags;
        let n = 1 + N::to_usize();
        b0[1..n].copy_from_slice(&nonce);
        let q = l_arr.len() - l as usize;
        b0[n..].copy_from_slice(&l_arr[q..]);

        let la = adata.len();
        let la_arr = la.to_be_bytes();
        let b1 = if la == 0 {
            None
        } else if la < (1 << 16) - (1 << 8) {
            let mut b = Block::<C>::default();
            b[..2].copy_from_slice(&la_arr[la_arr.len() - 2..]);
            Some((b, 2))
        } else if la <= core::u32::MAX as usize {
            let mut b = Block::<C>::default();
            b[0] = 0xFF;
            b[1] = 0xFE;
            b[2..6].copy_from_slice(&la_arr[la_arr.len() - 4..]);
            Some((b, 6))
        } else {
            let mut b = Block::<C>::default();
            b[0] = 0xFF;
            b[1] = 0xFF;
            b[2..10].copy_from_slice(&la_arr[la_arr.len() - 8..]);
            Some((b, 10))
        };

        let mut mac = CbcMac::from_cipher(&self.cipher);
        mac.update(&b0);

        if let Some((mut b1, n)) = b1 {
            if b1.len() - n >= adata.len() {
                b1[n..n + adata.len()].copy_from_slice(adata);
                mac.update(&b1);
            } else {
                let (l, r) = adata.split_at(b1.len() - n);
                b1[n..].copy_from_slice(l);
                mac.update(&b1);

                let mut chunks = r.chunks_exact(bs);
                for chunk in &mut chunks {
                    mac.update(Block::<C>::from_slice(chunk));
                }
                let rem = chunks.remainder();
                if !rem.is_empty() {
                    let mut bn = Block::<C>::default();
                    bn[..rem.len()].copy_from_slice(rem);
                    mac.update(&bn)
                }
            }
        }

        let mut chunks = buffer.chunks_exact(bs);
        for chunk in &mut chunks {
            mac.update(Block::<C>::from_slice(chunk));
        }
        let rem = chunks.remainder();
        if !rem.is_empty() {
            let mut bn = Block::<C>::default();
            bn[..rem.len()].copy_from_slice(rem);
            mac.update(&bn);
        }

        Ok(mac.finalize())
    }
}

impl<C, M, N> NewAead for Ccm<C, M, N>
where
    C: BlockCipher<BlockSize = U16> + NewBlockCipher,
    C::ParBlocks: ArrayLength<Block<C>>,
    M: ArrayLength<u8> + TagSize,
    N: ArrayLength<u8> + NonceSize,
{
    type KeySize = C::KeySize;

    fn new(key: &Key<Self>) -> Self {
        Self::from_cipher(C::new(key))
    }
}

impl<C, M, N> AeadInPlace for Ccm<C, M, N>
where
    C: BlockCipher<BlockSize = U16>,
    C::ParBlocks: ArrayLength<Block<C>>,
    M: ArrayLength<u8> + TagSize,
    N: ArrayLength<u8> + NonceSize,
{
    type NonceSize = N;
    type TagSize = M;
    type CiphertextOverhead = U0;

    fn encrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self::NonceSize>,
        adata: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag<Self::TagSize>, Error> {
        let bs = C::BlockSize::to_usize();

        let mut full_tag = self.calc_mac(nonce, adata, buffer)?;

        let mut s = Default::default();
        Self::gen_enc_block(&mut s, nonce, 0);
        self.cipher.encrypt_block(&mut s);
        xor(&mut full_tag, &s);

        let mut iter = buffer.chunks_exact_mut(bs);
        let mut i = 1;
        for chunk in &mut iter {
            Self::gen_enc_block(&mut s, nonce, i);
            self.cipher.encrypt_block(&mut s);
            xor(chunk, &s);
            i += 1;
        }
        Self::gen_enc_block(&mut s, nonce, i);
        self.cipher.encrypt_block(&mut s);
        let rem = iter.into_remainder();
        xor(rem, &s[..rem.len()]);

        let tag = Tag::<M>::clone_from_slice(&full_tag[..M::to_usize()]);
        Ok(tag)
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self::NonceSize>,
        adata: &[u8],
        buffer: &mut [u8],
        tag: &Tag<Self::TagSize>,
    ) -> Result<(), Error> {
        let bs = C::BlockSize::to_usize();

        let mut s = Default::default();
        Self::gen_enc_block(&mut s, nonce, 0);
        self.cipher.encrypt_block(&mut s);

        let s0 = s;

        let mut iter = buffer.chunks_exact_mut(bs);
        let mut i = 1;
        for chunk in &mut iter {
            Self::gen_enc_block(&mut s, nonce, i);
            self.cipher.encrypt_block(&mut s);
            xor(chunk, &s);
            i += 1;
        }
        Self::gen_enc_block(&mut s, nonce, i);
        self.cipher.encrypt_block(&mut s);
        let rem = iter.into_remainder();
        xor(rem, &s[..rem.len()]);

        let mut full_tag = self.calc_mac(nonce, adata, buffer)?;
        xor(&mut full_tag, &s0);
        let n = tag.len();
        if full_tag[..n].ct_eq(tag).unwrap_u8() == 0 {
            buffer.iter_mut().for_each(|v| *v = 0);
            return Err(Error);
        }

        Ok(())
    }
}

struct CbcMac<'a, C: BlockCipher> {
    cipher: &'a C,
    state: Block<C>,
}

impl<'a, C: BlockCipher> CbcMac<'a, C> {
    fn from_cipher(cipher: &'a C) -> Self {
        Self {
            cipher,
            state: Default::default(),
        }
    }

    fn update(&mut self, block: &Block<C>) {
        xor(&mut self.state, block);
        self.cipher.encrypt_block(&mut self.state);
    }

    fn finalize(self) -> Block<C> {
        self.state
    }
}

#[inline]
fn xor(v1: &mut [u8], v2: &[u8]) {
    for (a, b) in v1.iter_mut().zip(v2.iter()) {
        *a ^= b;
    }
}
