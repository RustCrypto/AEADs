//! Generic implementation of [Multilinear Galous Mode][1] [AEAD] construction.
//!
//! # Example
//! ```
//! # #[cfg(feature = "alloc")]
//! # {
//! use mgm::Mgm;
//! use kuznyechik::Kuznyechik;
//! use mgm::aead::{Aead, NewAead, generic_array::GenericArray};
//!
//! let key = GenericArray::from_slice(b"very secret key very secret key ");
//! let cipher = Mgm::<Kuznyechik>::new(key);
//!
//! // 127-bit nonce value, since API has to accept 128 bits, first nonce bit
//! // MUST be equal to zero, otherwise encryption and decryption will fail
//! let nonce = GenericArray::from_slice(b"unique nonce val");
//!
//! // NOTE: handle errors to avoid panics!
//! let ciphertext = cipher.encrypt(nonce, b"plaintext message".as_ref())
//!     .expect("encryption failure!");
//! let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
//!     .expect("decryption failure!");
//!
//! assert_eq!(&plaintext, b"plaintext message");
//! # }
//! ```
//!
//! [1]: https://eprint.iacr.org/2019/123.pdf
//! [AEAD]: https://en.wikipedia.org/wiki/Authenticated_encryption
#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![warn(missing_docs, rust_2018_idioms)]
use aead::{
    consts::U0,
    generic_array::{typenum::Unsigned, GenericArray},
    AeadCore, AeadInPlace, Error, Key, NewAead,
};
use cipher::{BlockCipher, BlockEncrypt, NewBlockCipher, ParBlocks};
use subtle::ConstantTimeEq;

pub use aead;

mod gf;
mod sealed;

use gf::GfElement;
use sealed::{Counter, Sealed};

/// MGM nonces
pub type Nonce<NonceSize> = GenericArray<u8, NonceSize>;

/// MGM tags
pub type Tag<TagSize> = GenericArray<u8, TagSize>;

type Block<C> = GenericArray<u8, <C as BlockCipher>::BlockSize>;
type Element<C> = <<C as BlockCipher>::BlockSize as Sealed>::Element;

/// Trait implemented for block cipher sizes usable with MGM.
pub trait MgmBlockSize: sealed::Sealed {}

impl<T: Sealed> MgmBlockSize for T {}

/// Multilinear Galous Mode cipher
#[derive(Clone, Debug)]
pub struct Mgm<C>
where
    C: BlockEncrypt,
    C::BlockSize: MgmBlockSize,
{
    cipher: C,
}

impl<C> Mgm<C>
where
    C: BlockEncrypt,
    C::BlockSize: MgmBlockSize,
{
    fn apply_ks_block(&self, ctr: &mut Counter<C>, buf: &mut [u8]) {
        let mut block = C::BlockSize::ctr2block(ctr);
        self.cipher.encrypt_block(&mut block);
        for i in 0..core::cmp::min(block.len(), buf.len()) {
            buf[i] ^= block[i];
        }
        C::BlockSize::incr_r(ctr);
    }

    fn update_tag(&self, tag: &mut Element<C>, tag_ctr: &mut Counter<C>, block: &Block<C>) {
        let mut h = C::BlockSize::ctr2block(tag_ctr);
        self.cipher.encrypt_block(&mut h);
        tag.mul_sum(&h, block);
        C::BlockSize::incr_l(tag_ctr);
    }

    fn apply_par_ks_blocks(&self, ctr: &mut Counter<C>, par_blocks: &mut [u8]) {
        let pb = C::ParBlocks::USIZE;
        let bs = C::BlockSize::USIZE;
        assert_eq!(par_blocks.len(), pb * bs);

        let mut par_ks = ParBlocks::<C>::default();
        for ks in par_ks.iter_mut() {
            *ks = C::BlockSize::ctr2block(ctr);
            C::BlockSize::incr_r(ctr);
        }
        self.cipher.encrypt_par_blocks(&mut par_ks);

        let iter = par_blocks.chunks_exact_mut(bs);
        for (ks, block) in par_ks.iter().zip(iter) {
            for i in 0..bs {
                block[i] ^= ks[i];
            }
        }
    }

    fn update_par_tag(&self, tag: &mut Element<C>, tag_ctr: &mut Counter<C>, par_blocks: &[u8]) {
        let pb = C::ParBlocks::USIZE;
        let bs = C::BlockSize::USIZE;
        assert_eq!(par_blocks.len(), pb * bs);

        let mut par_h = ParBlocks::<C>::default();
        for h in par_h.iter_mut() {
            *h = C::BlockSize::ctr2block(tag_ctr);
            C::BlockSize::incr_l(tag_ctr);
        }
        self.cipher.encrypt_par_blocks(&mut par_h);
        let iter = par_blocks.chunks_exact(bs).map(GenericArray::from_slice);
        for (h, block) in par_h.iter().zip(iter) {
            tag.mul_sum(h, block);
        }
    }
}

impl<C> From<C> for Mgm<C>
where
    C: BlockEncrypt,
    C::BlockSize: MgmBlockSize,
{
    fn from(cipher: C) -> Self {
        Self { cipher }
    }
}

impl<C> NewAead for Mgm<C>
where
    C: BlockEncrypt + NewBlockCipher,
    C::BlockSize: MgmBlockSize,
{
    type KeySize = C::KeySize;

    fn new(key: &Key<Self>) -> Self {
        Self::from(C::new(key))
    }
}

impl<C> AeadCore for Mgm<C>
where
    C: BlockEncrypt,
    C::BlockSize: MgmBlockSize,
{
    type NonceSize = C::BlockSize;
    type TagSize = C::BlockSize;
    type CiphertextOverhead = U0;
}

impl<C> AeadInPlace for Mgm<C>
where
    C: BlockEncrypt,
    C::BlockSize: MgmBlockSize,
{
    fn encrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self::NonceSize>,
        mut adata: &[u8],
        mut buffer: &mut [u8],
    ) -> Result<Tag<Self::TagSize>, Error> {
        // first nonce bit must be equal to zero
        if nonce[0] >> 7 != 0 {
            return Err(Error);
        }

        let adata_len = adata.len();
        let msg_len = buffer.len();

        let mut tag_ctr = nonce.clone();
        tag_ctr[0] |= 0b1000_0000;
        self.cipher.encrypt_block(&mut tag_ctr);
        let mut tag_ctr = C::BlockSize::block2ctr(&tag_ctr);

        let mut tag = <C::BlockSize as Sealed>::Element::new();

        let pb = C::ParBlocks::USIZE;
        let bs = C::BlockSize::USIZE;

        // process adata
        if pb > 1 {
            let mut iter = adata.chunks_exact(pb * bs);
            for chunk in &mut iter {
                self.update_par_tag(&mut tag, &mut tag_ctr, chunk);
            }
            adata = iter.remainder();
        };

        let mut iter = adata.chunks_exact(bs);
        for block in (&mut iter).map(Block::<C>::from_slice) {
            self.update_tag(&mut tag, &mut tag_ctr, block);
        }
        let rem = iter.remainder();
        if !rem.is_empty() {
            let mut block: Block<C> = Default::default();
            block[..rem.len()].copy_from_slice(rem);
            self.update_tag(&mut tag, &mut tag_ctr, &block);
        }

        let mut enc_ctr = nonce.clone();
        enc_ctr[0] &= 0b0111_1111;
        self.cipher.encrypt_block(&mut enc_ctr);
        let mut enc_ctr = C::BlockSize::block2ctr(&enc_ctr);

        // process plaintext
        if pb > 1 {
            let mut iter = buffer.chunks_exact_mut(pb * bs);
            for chunk in &mut iter {
                self.apply_par_ks_blocks(&mut enc_ctr, chunk);
                self.update_par_tag(&mut tag, &mut tag_ctr, chunk);
            }
            buffer = iter.into_remainder();
        }

        let mut iter = buffer.chunks_exact_mut(bs);
        for block in (&mut iter).map(Block::<C>::from_mut_slice) {
            self.apply_ks_block(&mut enc_ctr, block);
            self.update_tag(&mut tag, &mut tag_ctr, block);
        }
        let rem = iter.into_remainder();
        if !rem.is_empty() {
            self.apply_ks_block(&mut enc_ctr, rem);

            let mut block = Block::<C>::default();
            let n = rem.len();
            block[..n].copy_from_slice(rem);
            self.update_tag(&mut tag, &mut tag_ctr, &block);
        }

        let block = C::BlockSize::lengths2block(adata_len, msg_len)?;
        self.update_tag(&mut tag, &mut tag_ctr, &block);

        let mut tag = tag.into_bytes();
        self.cipher.encrypt_block(&mut tag);

        Ok(tag)
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self::NonceSize>,
        mut adata: &[u8],
        mut buffer: &mut [u8],
        expected_tag: &Tag<Self::TagSize>,
    ) -> Result<(), Error> {
        // first nonce bit must be equal to zero
        if nonce[0] >> 7 != 0 {
            return Err(Error);
        }

        let adata_len = adata.len();
        let msg_len = buffer.len();

        let mut tag_ctr = nonce.clone();
        tag_ctr[0] |= 0b1000_0000;
        self.cipher.encrypt_block(&mut tag_ctr);

        let mut tag_ctr = C::BlockSize::block2ctr(&tag_ctr);
        let mut tag = <C::BlockSize as Sealed>::Element::new();

        let pb = C::ParBlocks::USIZE;
        let bs = C::BlockSize::USIZE;

        // calculate tag
        // process adata
        if pb > 1 {
            let mut iter = adata.chunks_exact(pb * bs);
            for chunk in &mut iter {
                self.update_par_tag(&mut tag, &mut tag_ctr, chunk);
            }
            adata = iter.remainder();
        };

        let mut iter = adata.chunks_exact(bs);
        for block in (&mut iter).map(Block::<C>::from_slice) {
            self.update_tag(&mut tag, &mut tag_ctr, block);
        }
        let rem = iter.remainder();
        if !rem.is_empty() {
            let mut block: Block<C> = Default::default();
            block[..rem.len()].copy_from_slice(rem);
            self.update_tag(&mut tag, &mut tag_ctr, &block);
        }

        // process ciphertext
        let buf = if pb > 1 {
            let mut iter = buffer.chunks_exact(pb * bs);
            for chunk in &mut iter {
                self.update_par_tag(&mut tag, &mut tag_ctr, chunk);
            }
            iter.remainder()
        } else {
            &buffer
        };

        let mut iter = buf.chunks_exact(bs);
        for block in (&mut iter).map(Block::<C>::from_slice) {
            self.update_tag(&mut tag, &mut tag_ctr, block);
        }
        let rem = iter.remainder();
        if !rem.is_empty() {
            let n = rem.len();

            let mut block = Block::<C>::default();
            block[..n].copy_from_slice(rem);

            self.update_tag(&mut tag, &mut tag_ctr, &block);
        }

        let block = C::BlockSize::lengths2block(adata_len, msg_len)?;
        self.update_tag(&mut tag, &mut tag_ctr, &block);

        let mut tag = tag.into_bytes();
        self.cipher.encrypt_block(&mut tag);

        if expected_tag.ct_eq(&tag).unwrap_u8() == 0 {
            return Err(Error);
        }

        // decrypt ciphertext
        let mut dec_ctr = nonce.clone();
        dec_ctr[0] &= 0b0111_1111;
        self.cipher.encrypt_block(&mut dec_ctr);
        let mut dec_ctr = C::BlockSize::block2ctr(&dec_ctr);

        if pb > 1 {
            let mut iter = buffer.chunks_exact_mut(pb * bs);
            for chunk in &mut iter {
                self.apply_par_ks_blocks(&mut dec_ctr, chunk);
            }
            buffer = iter.into_remainder();
        }

        let mut iter = buffer.chunks_exact_mut(bs);
        for block in (&mut iter).map(Block::<C>::from_mut_slice) {
            self.apply_ks_block(&mut dec_ctr, block);
        }
        let rem = iter.into_remainder();
        if !rem.is_empty() {
            self.apply_ks_block(&mut dec_ctr, rem);
        }

        Ok(())
    }
}
