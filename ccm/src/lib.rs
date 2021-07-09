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
    generic_array::{typenum::Unsigned, ArrayLength, GenericArray},
    AeadCore, AeadInPlace, Error, Key, NewAead,
};
use cipher::{Block, BlockCipher, BlockEncrypt, NewBlockCipher, FromBlockCipher, StreamCipher};
use core::marker::PhantomData;
use subtle::ConstantTimeEq;

mod traits;

pub use traits::{NonceSize, TagSize};

/// CCM nonces
pub type Nonce<NonceSize> = GenericArray<u8, NonceSize>;

/// CCM tags
pub type Tag<TagSize> = GenericArray<u8, TagSize>;

/// CCM instance generic over an underlying block cipher.
///
/// Type parameters:
/// - `C`: block cipher.
/// - `M`: size of MAC tag in bytes, valid values:
/// [`U4`], [`U6`], [`U8`], [`U10`], [`U12`], [`U14`], [`U12`].
/// - `N`: size of nonce, valid values:
/// [`U7`], [`U8`], [`U9`], [`U10`], [`U11`], [`U12`], [`U13`].
pub struct Ccm<C, M, N>
where
    C: BlockCipher<BlockSize = U16> + BlockEncrypt,
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
    C: BlockCipher<BlockSize = U16> + BlockEncrypt,
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
        be_copy(&mut b0[n..], buffer.len());

        let mut mac = CbcMac::from_cipher(&self.cipher);
        mac.block_update(&b0);

        if !adata.is_empty() {
            let alen = adata.len();
            let (n, mut b) = fill_aad_header(alen);
            if b.len() - n >= alen {
                b[n..n + alen].copy_from_slice(adata);
                mac.block_update(&b);
            } else {
                let (l, r) = adata.split_at(b.len() - n);
                b[n..].copy_from_slice(l);
                mac.block_update(&b);
                mac.update(&r);
            }
        }

        mac.update(buffer);

        Ok(mac.finalize())
    }
}

impl<C, M, N> NewAead for Ccm<C, M, N>
where
    C: BlockCipher<BlockSize = U16> + BlockEncrypt + NewBlockCipher,
    C::ParBlocks: ArrayLength<Block<C>>,
    M: ArrayLength<u8> + TagSize,
    N: ArrayLength<u8> + NonceSize,
{
    type KeySize = C::KeySize;

    fn new(key: &Key<Self>) -> Self {
        Self::from_cipher(C::new(key))
    }
}

impl<C, M, N> AeadCore for Ccm<C, M, N>
where
    C: BlockCipher<BlockSize = U16> + BlockEncrypt,
    C::ParBlocks: ArrayLength<Block<C>>,
    M: ArrayLength<u8> + TagSize,
    N: ArrayLength<u8> + NonceSize,
{
    type NonceSize = N;
    type TagSize = M;
    type CiphertextOverhead = U0;
}

impl<C, M, N> AeadInPlace for Ccm<C, M, N>
where
    C: BlockCipher<BlockSize = U16> + BlockEncrypt,
    C::ParBlocks: ArrayLength<Block<C>>,
    M: ArrayLength<u8> + TagSize,
    N: ArrayLength<u8> + NonceSize,
{
    fn encrypt_in_place_detached(
        &self,
        nonce: &Nonce<N>,
        adata: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag<Self::TagSize>, Error> {
        let mut full_tag = self.calc_mac(nonce, adata, buffer)?;

        let ext_nonce = Self::extend_nonce(nonce);
        let d = C::BlockSize::USIZE - N::USIZE - 1;
        if d > 8 {
            let mut ctr = ctr::Ctr128BE::from_block_cipher(&self.cipher, &ext_nonce);
            ctr.apply_keystream(&mut full_tag);
            ctr.apply_keystream(buffer);
        } else if d > 4 {
            let mut ctr = ctr::Ctr64BE::from_block_cipher(&self.cipher, &ext_nonce);
            ctr.apply_keystream(&mut full_tag);
            ctr.apply_keystream(buffer);
        } else {
            let mut ctr = ctr::Ctr32BE::from_block_cipher(&self.cipher, &ext_nonce);
            ctr.apply_keystream(&mut full_tag);
            ctr.apply_keystream(buffer);
        }

        Ok(Tag::clone_from_slice(&full_tag[..M::to_usize()]))
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &Nonce<N>,
        adata: &[u8],
        buffer: &mut [u8],
        tag: &Tag<Self::TagSize>,
    ) -> Result<(), Error> {
        let ext_nonce = Self::extend_nonce(nonce);
        let d = C::BlockSize::USIZE - N::USIZE - 1;

        if d > 8 {
            let mut ctr = ctr::Ctr128BE::from_block_cipher(&self.cipher, &ext_nonce);
            ctr.seek_block(1);
            ctr.apply_keystream(buffer);
        } else if d > 4 {
            let mut ctr = ctr::Ctr64BE::from_block_cipher(&self.cipher, &ext_nonce);
            ctr.seek_block(1);
            ctr.apply_keystream(buffer);
        } else {
            let mut ctr = ctr::Ctr32BE::from_block_cipher(&self.cipher, &ext_nonce);
            ctr.seek_block(1);
            ctr.apply_keystream(buffer);
        }

        let mut full_tag = self.calc_mac(nonce, adata, buffer)?;

        if d > 8 {
            ctr::Ctr128BE::from_block_cipher(&self.cipher, &ext_nonce)
                .apply_keystream(&mut full_tag);
        } else if d > 4 {
            ctr::Ctr64BE::from_block_cipher(&self.cipher, &ext_nonce)
                .apply_keystream(&mut full_tag);
        } else {
            ctr::Ctr32BE::from_block_cipher(&self.cipher, &ext_nonce)
                .apply_keystream(&mut full_tag);
        }

        if full_tag[..tag.len()].ct_eq(tag).unwrap_u8() == 0 {
            buffer.iter_mut().for_each(|v| *v = 0);
            return Err(Error);
        }

        Ok(())
    }
}

struct CbcMac<'a, C: BlockCipher + BlockEncrypt> {
    cipher: &'a C,
    state: Block<C>,
}

impl<'a, C> CbcMac<'a, C>
where
    C: BlockCipher + BlockEncrypt,
{
    fn from_cipher(cipher: &'a C) -> Self {
        Self {
            cipher,
            state: Default::default(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        let mut chunks = data.chunks_exact(C::BlockSize::USIZE);
        for chunk in &mut chunks {
            self.block_update(Block::<C>::from_slice(chunk));
        }
        let rem = chunks.remainder();
        if !rem.is_empty() {
            let mut bn = Block::<C>::default();
            bn[..rem.len()].copy_from_slice(rem);
            self.block_update(&bn);
        }
    }

    fn block_update(&mut self, block: &Block<C>) {
        xor(&mut self.state, block);
        self.cipher.encrypt_block(&mut self.state);
    }

    fn finalize(self) -> Block<C> {
        self.state
    }
}

fn fill_aad_header(adata_len: usize) -> (usize, GenericArray<u8, U16>) {
    debug_assert_ne!(adata_len, 0);

    let mut b = GenericArray::<u8, U16>::default();
    let n = if adata_len < 0xFF00 {
        b[..2].copy_from_slice(&(adata_len as u16).to_be_bytes());
        2
    } else if adata_len <= core::u32::MAX as usize {
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

fn be_copy(buf: &mut [u8], n: usize) {
    let narr = n.to_le_bytes();
    let iter = buf.iter_mut().rev().zip(narr.iter());
    for (a, b) in iter {
        *a = *b;
    }
}

fn xor(v1: &mut [u8], v2: &[u8]) {
    for (a, b) in v1.iter_mut().zip(v2.iter()) {
        *a ^= b;
    }
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
