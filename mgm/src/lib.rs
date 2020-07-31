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
//! let key = GenericArray::from_slice(b"an example very very secret key.");
//! let cipher = Mgm::<Kuznyechik>::new(key);;
//!
//! // 127-bit nonce value, since API has to accept 128 bits, first nonce bit
//! // MUST be equal to zero, otherwise encryption and decryption will fail
//! let nonce = GenericArray::from_slice(b"unique nonce val");
//!
//! // NOTE: handle this error to avoid panics!
//! let ciphertext = cipher.encrypt(nonce, b"plaintext message".as_ref())
//!     .expect("encryption failure!");
//!
//! // NOTE: handle this error to avoid panics!
//! let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
//!     .expect("decryption failure!");
//!
//! assert_eq!(&plaintext, b"plaintext message");
//! # }
//! ```
//!
//! [1]: https://eprint.iacr.org/2019/123.pdf
//! [AEAD]: https://en.wikipedia.org/wiki/Authenticated_encryption
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
#![warn(missing_docs, rust_2018_idioms)]
//#![no_std]
use aead::consts::{U0, U16};
use aead::generic_array::{typenum::Unsigned, ArrayLength, GenericArray};
use aead::{AeadInPlace, Error, Key, NewAead, Nonce, Tag};
use block_cipher::{BlockCipher, NewBlockCipher};
use core::convert::TryInto;
use core::num::Wrapping;

pub use aead;

mod gf;

type Block = GenericArray<u8, U16>;
type Counter = [Wrapping<u64>; 2];

const ONE: Wrapping<u64> = Wrapping(1);

/// Multilinear Galous Mode cipher instance
pub struct Mgm<C>
where
    C: BlockCipher<BlockSize = U16> + NewBlockCipher,
    C::ParBlocks: ArrayLength<Block>,
{
    cipher: C,
}

impl<C> Mgm<C>
where
    C: BlockCipher<BlockSize = U16> + NewBlockCipher,
    C::ParBlocks: ArrayLength<Block>,
{
    fn from_cipher(cipher: C) -> Self {
        Self { cipher }
    }

    fn get_h(&self, counter: &Counter) -> Block {
        let mut block = to_bytes(counter);
        self.cipher.encrypt_block(&mut block);
        block
    }

    fn encrypt_counter(&self, counter: &Counter) -> Block {
        let mut block = to_bytes(counter);
        self.cipher.encrypt_block(&mut block);
        block
    }
}

impl<C> NewAead for Mgm<C>
where
    C: BlockCipher<BlockSize = U16> + NewBlockCipher,
    C::ParBlocks: ArrayLength<Block>,
{
    type KeySize = C::KeySize;

    fn new(key: &Key<Self>) -> Self {
        Self::from_cipher(C::new(key))
    }
}

impl<C> AeadInPlace for Mgm<C>
where
    C: BlockCipher<BlockSize = U16> + NewBlockCipher,
    C::ParBlocks: ArrayLength<Block>,
{
    type NonceSize = C::BlockSize;
    type TagSize = C::BlockSize;
    type CiphertextOverhead = U0;

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

        let mut enc_counter = *nonce;
        let mut tag_counter = *nonce;
        enc_counter[0] &= 0b0111_1111;
        tag_counter[0] |= 0b1000_0000;

        self.cipher.encrypt_block(&mut enc_counter);
        self.cipher.encrypt_block(&mut tag_counter);

        let mut enc_counter = to_u64_pair(&enc_counter);
        let mut tag_counter = to_u64_pair(&tag_counter);

        let mut tag = gf::Element::new();

        // process adata
        let mut iter = adata.chunks_exact(C::BlockSize::USIZE);
        for chunk in (&mut iter).map(Block::from_slice) {
            tag.mul_sum(&self.get_h(&tag_counter), chunk);
            tag_counter[0] += ONE;
        }
        let rem = iter.remainder();
        if !rem.is_empty() {
            let mut chunk: Block = Default::default();
            chunk[..rem.len()].copy_from_slice(rem);
            tag.mul_sum(&self.get_h(&tag_counter), &chunk);
            tag_counter[0] += ONE;
        }

        // process plaintext
        let mut iter = buffer.chunks_exact_mut(C::BlockSize::USIZE);
        for chunk in (&mut iter).map(Block::from_mut_slice) {
            xor(chunk, &self.encrypt_counter(&enc_counter));
            tag.mul_sum(&self.get_h(&tag_counter), chunk);
            enc_counter[1] += ONE;
            tag_counter[0] += ONE;
        }
        let rem = iter.into_remainder();
        if !rem.is_empty() {
            let n = rem.len();
            let e = self.encrypt_counter(&enc_counter);
            xor(rem, &e[..n]);

            let mut ct = Block::default();
            ct[..n].copy_from_slice(rem);

            tag.mul_sum(&self.get_h(&tag_counter), &ct);
            tag_counter[0] += ONE;
        }

        let adata_len = Wrapping(8 * (adata.len() as u64));
        let msg_len = Wrapping(8 * (buffer.len() as u64));
        let final_block = to_bytes(&[adata_len, msg_len]);
        tag.mul_sum(&self.get_h(&tag_counter), &final_block);

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

        let mut enc_counter = *nonce;
        let mut tag_counter = *nonce;
        enc_counter[0] &= 0b0111_1111;
        tag_counter[0] |= 0b1000_0000;

        self.cipher.encrypt_block(&mut enc_counter);
        self.cipher.encrypt_block(&mut tag_counter);

        let mut dec_counter = to_u64_pair(&enc_counter);
        let mut tag_counter = to_u64_pair(&tag_counter);

        let mut tag = gf::Element::new();

        // process adata
        let mut iter = adata.chunks_exact(C::BlockSize::USIZE);
        for chunk in (&mut iter).map(Block::from_slice) {
            tag.mul_sum(&self.get_h(&tag_counter), chunk);
            tag_counter[0] += ONE;
        }
        let rem = iter.remainder();
        if !rem.is_empty() {
            let mut chunk: Block = Default::default();
            chunk[..rem.len()].copy_from_slice(rem);
            tag.mul_sum(&self.get_h(&tag_counter), &chunk);
            tag_counter[0] += ONE;
        }

        // process ciphertext
        let mut iter = buffer.chunks_exact_mut(C::BlockSize::USIZE);
        for chunk in (&mut iter).map(Block::from_mut_slice) {
            tag.mul_sum(&self.get_h(&tag_counter), chunk);
            xor(chunk, &self.encrypt_counter(&dec_counter));
            dec_counter[1] += ONE;
            tag_counter[0] += ONE;
        }
        let rem = iter.into_remainder();
        if !rem.is_empty() {
            let n = rem.len();
            let e = self.encrypt_counter(&dec_counter);

            let mut ct = Block::default();
            ct[..n].copy_from_slice(rem);

            tag.mul_sum(&self.get_h(&tag_counter), &ct);
            xor(rem, &e[..n]);
            tag_counter[0] += ONE;
        }

        let adata_len = Wrapping(8 * (adata.len() as u64));
        let msg_len = Wrapping(8 * (buffer.len() as u64));
        let final_block = to_bytes(&[adata_len, msg_len]);
        tag.mul_sum(&self.get_h(&tag_counter), &final_block);

        let mut tag = tag.into_bytes();
        self.cipher.encrypt_block(&mut tag);

        use subtle::ConstantTimeEq;
        if expected_tag.ct_eq(&tag).unwrap_u8() == 1 {
            Ok(())
        } else {
            Err(Error)
        }
    }
}

fn xor(buf: &mut [u8], val: &[u8]) {
    debug_assert_eq!(buf.len(), val.len());
    for (a, b) in buf.iter_mut().zip(val.iter()) {
        *a ^= *b;
    }
}

fn to_u64_pair(v: &Block) -> Counter {
    [
        Wrapping(u64::from_be_bytes(v[..8].try_into().unwrap())),
        Wrapping(u64::from_be_bytes(v[8..].try_into().unwrap())),
    ]
}

fn to_bytes(v: &Counter) -> Block {
    let a = v[0].0.to_be_bytes();
    let b = v[1].0.to_be_bytes();
    let mut block = Block::default();
    block[..8].copy_from_slice(&a);
    block[8..].copy_from_slice(&b);
    block
}
