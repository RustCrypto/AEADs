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
use cipher::{BlockCipher, BlockEncrypt, NewBlockCipher};
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
    fn get_h(&self, counter: &Counter<C>) -> Block<C> {
        let mut block = C::BlockSize::ctr2block(counter);
        self.cipher.encrypt_block(&mut block);
        block
    }

    fn encrypt_counter(&self, counter: &Counter<C>) -> Block<C> {
        let mut block = C::BlockSize::ctr2block(counter);
        self.cipher.encrypt_block(&mut block);
        block
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
        adata: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag<Self::TagSize>, Error> {
        // first nonce bit must be equal to zero
        if nonce[0] >> 7 != 0 {
            return Err(Error);
        }
        let final_block = C::BlockSize::lengths2block(adata.len(), buffer.len())?;

        let mut enc_ctr = nonce.clone();
        let mut tag_ctr = nonce.clone();
        enc_ctr[0] &= 0b0111_1111;
        tag_ctr[0] |= 0b1000_0000;

        self.cipher.encrypt_block(&mut enc_ctr);
        self.cipher.encrypt_block(&mut tag_ctr);

        let mut enc_ctr = C::BlockSize::block2ctr(&enc_ctr);
        let mut tag_ctr = C::BlockSize::block2ctr(&tag_ctr);

        let mut tag = <C::BlockSize as Sealed>::Element::new();

        // process adata
        let mut iter = adata.chunks_exact(C::BlockSize::USIZE);
        for chunk in (&mut iter).map(Block::<C>::from_slice) {
            tag.mul_sum(&self.get_h(&tag_ctr), chunk);
            C::BlockSize::incr_l(&mut tag_ctr);
        }
        let rem = iter.remainder();
        if !rem.is_empty() {
            let mut chunk: Block<C> = Default::default();
            chunk[..rem.len()].copy_from_slice(rem);
            tag.mul_sum(&self.get_h(&tag_ctr), &chunk);
            C::BlockSize::incr_l(&mut tag_ctr);
        }

        // process plaintext
        let mut iter = buffer.chunks_exact_mut(C::BlockSize::USIZE);
        for chunk in (&mut iter).map(Block::<C>::from_mut_slice) {
            xor(chunk, &self.encrypt_counter(&enc_ctr));
            tag.mul_sum(&self.get_h(&tag_ctr), chunk);
            C::BlockSize::incr_r(&mut enc_ctr);
            C::BlockSize::incr_l(&mut tag_ctr);
        }
        let rem = iter.into_remainder();
        if !rem.is_empty() {
            let n = rem.len();
            let e = self.encrypt_counter(&enc_ctr);
            xor(rem, &e[..n]);

            let mut ct = Block::<C>::default();
            ct[..n].copy_from_slice(rem);

            tag.mul_sum(&self.get_h(&tag_ctr), &ct);
            C::BlockSize::incr_l(&mut tag_ctr);
        }

        tag.mul_sum(&self.get_h(&tag_ctr), &final_block);

        let mut tag = tag.into_bytes();
        self.cipher.encrypt_block(&mut tag);

        Ok(tag)
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self::NonceSize>,
        adata: &[u8],
        buffer: &mut [u8],
        expected_tag: &Tag<Self::TagSize>,
    ) -> Result<(), Error> {
        // first nonce bit must be equal to zero
        if nonce[0] >> 7 != 0 {
            return Err(Error);
        }

        let mut enc_ctr = nonce.clone();
        let mut tag_ctr = nonce.clone();
        enc_ctr[0] &= 0b0111_1111;
        tag_ctr[0] |= 0b1000_0000;

        self.cipher.encrypt_block(&mut enc_ctr);
        self.cipher.encrypt_block(&mut tag_ctr);

        let mut tag_ctr = C::BlockSize::block2ctr(&tag_ctr);
        let mut tag = <C::BlockSize as Sealed>::Element::new();

        // process adata
        let mut iter = adata.chunks_exact(C::BlockSize::USIZE);
        for chunk in (&mut iter).map(Block::<C>::from_slice) {
            tag.mul_sum(&self.get_h(&tag_ctr), chunk);
            C::BlockSize::incr_l(&mut tag_ctr);
        }
        let rem = iter.remainder();
        if !rem.is_empty() {
            let mut chunk: Block<C> = Default::default();
            chunk[..rem.len()].copy_from_slice(rem);
            tag.mul_sum(&self.get_h(&tag_ctr), &chunk);
            C::BlockSize::incr_l(&mut tag_ctr);
        }

        let mut iter = buffer.chunks_exact_mut(C::BlockSize::USIZE);
        for chunk in (&mut iter).map(Block::<C>::from_mut_slice) {
            tag.mul_sum(&self.get_h(&tag_ctr), chunk);
            C::BlockSize::incr_l(&mut tag_ctr);
        }
        let rem = iter.into_remainder();
        if !rem.is_empty() {
            let n = rem.len();

            let mut ct = Block::<C>::default();
            ct[..n].copy_from_slice(rem);

            tag.mul_sum(&self.get_h(&tag_ctr), &ct);
            C::BlockSize::incr_l(&mut tag_ctr);
        }

        let final_block = C::BlockSize::lengths2block(adata.len(), buffer.len())?;
        tag.mul_sum(&self.get_h(&tag_ctr), &final_block);

        let mut tag = tag.into_bytes();
        self.cipher.encrypt_block(&mut tag);

        if expected_tag.ct_eq(&tag).unwrap_u8() == 0 {
            return Err(Error);
        }

        // decrypt ciphertext
        let mut dec_counter = C::BlockSize::block2ctr(&enc_ctr);
        let mut iter = buffer.chunks_exact_mut(C::BlockSize::USIZE);
        for chunk in (&mut iter).map(Block::<C>::from_mut_slice) {
            xor(chunk, &self.encrypt_counter(&dec_counter));
            C::BlockSize::incr_r(&mut dec_counter);
            C::BlockSize::incr_l(&mut tag_ctr);
        }
        let rem = iter.into_remainder();
        if !rem.is_empty() {
            let n = rem.len();
            let e = self.encrypt_counter(&dec_counter);
            xor(rem, &e[..n]);
        }

        Ok(())
    }
}

fn xor(buf: &mut [u8], val: &[u8]) {
    debug_assert_eq!(buf.len(), val.len());
    for (a, b) in buf.iter_mut().zip(val.iter()) {
        *a ^= *b;
    }
}
