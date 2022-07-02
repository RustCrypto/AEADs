//! The [COLM][1] [Authenticated Encryption and Associated Data (AEAD)][2] cipher.
//!
//! COLM has been selected as the second choice for defense-in-depth
//! scenario during the [CAESAR competition][3].
//!
//! ## Security notes
//!
//! Although encryption and decryption passes the test vector, there is no guarantee
//! of constant-time operation.
//!
//! **USE AT YOUR OWN RISK.**
//!
//! # Usage
//! ```
//! use colm::{Colm0Aes128, Nonce}; // If you don't know what block cipher to use with COLM choose the pre-defined type with AES
//! use colm::aead::{Aead, NewAead};
//!
//! let key = b"just another key";
//! let cipher = Colm0Aes128::new(key.into());
//!
//! let nonce = Nonce::from_slice(b"thenonce"); // 64-bit nonce for COLM
//!
//! let ciphertext = cipher.encrypt(nonce, b"plaintext message".as_ref())
//!     .expect("encryption failure!"); // NOTE: handle this error to avoid panics!
//!
//! let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
//!     .expect("decryption failure!"); // NOTE: handle this error to avoic panics!
//!
//! assert_eq!(&plaintext, b"plaintext message");
//! ```
//!
//! ## Usage with AAD
//! COLM can authenticate additional data that is not encrypted alongside with the ciphertext.
//! ```
//! use colm::{Colm0Aes128, Nonce}; // If you don't know what block cipher to use with COLM choose the pre-defined type with AES
//! use colm::aead::{Aead, NewAead, Payload};
//!
//! let key = b"just another key";
//! let cipher = Colm0Aes128::new(key.into());
//!
//! let nonce = Nonce::from_slice(b"thenonce"); // 64-bit nonce for COLM
//!
//! let payload = Payload {
//!     msg: &b"this will be encrypted".as_ref(),
//!     aad: &b"this will NOT be encrypted, but will be authenticated".as_ref(),
//! };
//!
//! let ciphertext = cipher.encrypt(nonce, payload)
//!     .expect("encryption failure!"); // NOTE: handle this error to avoid panics!
//!
//! let payload = Payload {
//!     msg: &ciphertext,
//!     aad: &b"this will NOT be encrypted, but will be authenticated".as_ref(),
//! };
//!
//! let plaintext = cipher.decrypt(nonce, payload)
//!     .expect("decryption failure!"); // NOTE: handle this error to avoid panics!
//!
//! assert_eq!(&plaintext, b"this will be encrypted");
//! ```
//!
//! ## In-place Usage (eliminates `alloc` requirement)
//!
//! This crate has an optional `alloc` feature which can be disabled in e.g.
//! microcontroller environments that don't have a heap.
//!
//! The [`AeadInPlace::encrypt_in_place`] and [`AeadInPlace::decrypt_in_place`]
//! methods accept any type that impls the [`aead::Buffer`] trait which
//! contains the plaintext for encryption or ciphertext for decryption.
//!
//! Note that if you enable the `heapless` feature of this crate,
//! you will receive an impl of [`aead::Buffer`] for `heapless::Vec`
//! (re-exported from the [`aead`] crate as [`aead::heapless::Vec`]),
//! which can then be passed as the `buffer` parameter to the in-place encrypt
//! and decrypt methods:
//!
//! ```
//! # #[cfg(feature = "heapless")]
//! # {
//! use colm::{Colm0Aes128, Nonce}; // If you don't know what block cipher to use with COLM choose the pre-defined type with AES
//! use deoxys::aead::{AeadInPlace, NewAead};
//! use deoxys::aead::heapless::Vec;
//!
//! let key = b"just another key";
//! let cipher = Colm0Aes128::new(key,into());
//!
//! let nonce = Nonce::from_slice(b"thenonce"); // 64-bits for COLM
//!
//! let mut buffer: Vec<u8, 128> = Vec::new(); // Buffer needs 16-bytes overhead for tag
//! buffer.extend_from_slice(b"plaintext message");
//!
//! // Encrypt `buffer` in-place, replacing the plaintext contents with ciphertext
//! cipher.encrypt_in_place(nonce, b"", &mut buffer).expect("encryption failure!");
//!
//! // `buffer` now contains the message ciphertext
//! assert_ne!(&buffer, b"plaintext message");
//!
//! // Decrypt `buffer` in-place, replacing its ciphertext context with the original plaintext
//! cipher.decrypt_in_place(nonce, b"", &mut buffer).expect("decryption failure!");
//! assert_eq!(&buffer, b"plaintext message");
//! # }
//! ```
//!
//! [1]: https://competitions.cr.yp.to/round3/colmv1.pdf
//! [2]: https://en.wikipedia.org/wiki/Authenticated_encryption
//! [3]: https://competitions.cr.yp.to/caesar-submissions.html

#![feature(portable_simd)]
#![no_std]
#![warn(missing_docs, rust_2018_idioms)]

mod primitives;

#[cfg(target_arch = "x86")]
use core::arch::x86 as arch;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64 as arch;

use arch::{
    __m128i, _mm_loadu_si128, _mm_set_epi64x, _mm_setzero_si128, _mm_storeu_si128, _mm_xor_si128,
};

pub use aead::{self, AeadCore, AeadInPlace, Error, NewAead};
pub use cipher::Key;

use cipher::{
    consts::{U0, U16, U8},
    generic_array::{ArrayLength, GenericArray},
    BlockCipher, BlockDecrypt, BlockEncrypt, BlockSizeUser, KeyInit, KeySizeUser,
};

use core::marker::PhantomData;
use core::simd::u8x16;

use primitives::*;

#[cfg(feature = "aes")]
pub use aes;

#[cfg(feature = "aes")]
use aes::Aes128;

/// COLM nonces
pub type Nonce<NonceSize> = GenericArray<u8, NonceSize>;

/// COLM tags
pub type Tag = GenericArray<u8, U16>;

/// COLM0 with AES128 as underlying block cipher
#[cfg(feature = "aes")]
pub type Colm0Aes128 = Colm0<Aes128, U8>;

/// Struct representing COLM0 generic over the underlying block cipher
#[derive(Clone)]
pub struct Colm0<B, NonceSize> {
    cipher: B,
    nonce_size: PhantomData<NonceSize>,
}

impl<B, NonceSize> KeySizeUser for Colm0<B, NonceSize>
where
    B: KeyInit,
{
    type KeySize = B::KeySize;
}

impl<B, NonceSize> NewAead for Colm0<B, NonceSize>
where
    B: BlockSizeUser<BlockSize = U16> + BlockEncrypt + BlockDecrypt + KeyInit,
{
    type KeySize = B::KeySize;

    fn new(key: &Key<Self>) -> Self {
        B::new(key).into()
    }
}

impl<B, NonceSize> From<B> for Colm0<B, NonceSize>
where
    B: BlockSizeUser<BlockSize = U16> + BlockEncrypt + BlockDecrypt,
{
    fn from(cipher: B) -> Self {
        Self {
            cipher,
            nonce_size: PhantomData,
        }
    }
}

impl<B, NonceSize> AeadCore for Colm0<B, NonceSize>
where
    NonceSize: ArrayLength<u8>,
{
    type NonceSize = NonceSize;
    type TagSize = U16;
    type CiphertextOverhead = U0;
}

impl<B, NonceSize> AeadInPlace for Colm0<B, NonceSize>
where
    B: BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt + BlockDecrypt,
    NonceSize: ArrayLength<u8>,
{
    fn encrypt_in_place_detached(
        &self,
        nonce: &Nonce<NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag, Error> {
        unsafe {
            let mut buf = [0u8; 16];
            let mut tag = [0u8; 16];

            let (mut w, mut block, mut lup, mut ldown, mut inb): (
                __m128i,
                __m128i,
                __m128i,
                __m128i,
                __m128i,
            );
            let mut checksum = _mm_setzero_si128();
            let mut ll = _mm_setzero_si128();

            let mut tag_start = 0;
            let mut block_start = 0;
            let mut block_end = 16;
            let mut remaining = buffer.len();

            ll = self.bc_encrypt(ll);
            lup = ll;
            ldown = gf128_mul3(&gf128_mul3(&ll));

            // mac AD + nonce
            w = self.mac(associated_data, nonce, &ll);

            // Encryption of complete blocks
            while remaining > 16 {
                lup = gf128_mul2(&lup);
                ldown = gf128_mul2(&ldown);

                // Load current complete block
                inb = _mm_loadu_si128(buffer[block_start..block_end].as_ptr() as *const __m128i);
                inb = byte_swap(inb);
                // XOR between current checksum and current complete block
                checksum = _mm_xor_si128(checksum, inb);

                // Start of actual COLM encryption procedure
                block = _mm_xor_si128(inb, lup);
                block = self.bc_encrypt(block);

                rho(&mut block, &mut w);

                block = self.bc_encrypt(block);
                block = _mm_xor_si128(block, ldown);

                // Store now encrypted current block back into output buffer
                _mm_storeu_si128(
                    buffer[block_start..block_end].as_ptr() as *mut __m128i,
                    byte_swap(block),
                );

                block_start += 16;
                block_end += 16;
                remaining -= 16;
            }

            // Need to compute tag_start in case last block is partial
            tag_start = (tag_start + remaining) % 16;

            // Copy remaining bytes from input buffer to buf
            buf[..remaining].copy_from_slice(&buffer[block_start..]);

            lup = gf128_mul7(&lup);
            ldown = gf128_mul7(&ldown);

            // Prepare padding in case last block is incomplete
            if remaining < 16 {
                buf[remaining] = 0x80;
                lup = gf128_mul7(&lup);
                ldown = gf128_mul7(&ldown);
            }

            // Load current (maybe partial) block into inb
            inb = _mm_loadu_si128(buf.as_ptr() as *const __m128i);
            inb = byte_swap(inb);
            // XOR between current checksum and current (maybe partial) block
            checksum = _mm_xor_si128(checksum, inb);

            block = _mm_xor_si128(checksum, lup);
            block = self.bc_encrypt(block);

            rho(&mut block, &mut w);

            block = self.bc_encrypt(block);
            block = _mm_xor_si128(block, ldown);

            // If no plaintext is given only return tag
            if remaining == 0 {
                _mm_storeu_si128(tag.as_ptr() as *mut __m128i, byte_swap(block));
                return Ok(tag.into());
            }

            _mm_storeu_si128(
                buffer[block_start..].as_ptr() as *mut __m128i,
                byte_swap(block),
            );

            if remaining < 16 {
                let tmp = u8x16::from(byte_swap(block));
                tag[..16 - remaining].copy_from_slice(&tmp.as_array()[tag_start..]);
                tag_start = 16 - remaining;
                //_mm_storeu_si128(tag[tag_start..].as_ptr() as *mut __m128i, byte_swap(block));
            }

            //block_start += 16;

            lup = gf128_mul2(&lup);
            ldown = gf128_mul2(&ldown);

            block = _mm_xor_si128(checksum, lup);
            block = self.bc_encrypt(block);

            rho(&mut block, &mut w);

            block = self.bc_encrypt(block);
            block = _mm_xor_si128(block, ldown);

            _mm_storeu_si128(buf.as_ptr() as *mut __m128i, byte_swap(block));
            tag[tag_start..].copy_from_slice(&buf[..remaining]);
            Ok(tag.into())
        }
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &aead::Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag,
    ) -> Result<(), Error> {
        unsafe {
            let buf = [0u8; 16];
            let (mut w, mut block, mut lup, mut ldown, mut inb): (
                __m128i,
                __m128i,
                __m128i,
                __m128i,
                __m128i,
            );
            let mut checksum = _mm_setzero_si128();
            let mut ll = _mm_setzero_si128();

            let mut block_end = 16;
            let mut block_start = 0;
            let mut remaining = buffer.len();

            if tag.len() < 16 {
                return Err(Error);
            }

            ll = self.bc_encrypt(ll);
            lup = ll;
            ldown = gf128_mul3(&gf128_mul3(&ll));

            // mac AD + nonce
            w = self.mac(associated_data, nonce, &ll);

            // Decryption of complete blocks
            while remaining > 16 {
                lup = gf128_mul2(&lup);
                ldown = gf128_mul2(&ldown);

                inb = _mm_loadu_si128(buffer[block_start..block_end].as_ptr() as *const __m128i);
                inb = byte_swap(inb);
                block = _mm_xor_si128(inb, ldown);
                block = self.bc_decrypt(block);

                rho_inv(&mut block, &mut w);

                block = self.bc_decrypt(block);
                block = _mm_xor_si128(block, lup);
                checksum = _mm_xor_si128(checksum, block);

                _mm_storeu_si128(
                    buffer[block_start..block_end].as_ptr() as *mut __m128i,
                    byte_swap(block),
                );

                block_start += 16;
                block_end += 16;
                remaining -= 16;
            }

            lup = gf128_mul7(&lup);
            ldown = gf128_mul7(&ldown);
            if remaining < 16 {
                lup = gf128_mul7(&lup);
                ldown = gf128_mul7(&ldown);
            }

            inb = _mm_loadu_si128(buffer[block_start..].as_ptr() as *const __m128i);
            inb = byte_swap(inb);
            block = _mm_xor_si128(inb, ldown);
            block = self.bc_decrypt(block);

            rho_inv(&mut block, &mut w);

            block = self.bc_decrypt(block);
            block = _mm_xor_si128(block, lup);

            checksum = _mm_xor_si128(checksum, block);

            // output last (maybe partial) plaintext block
            _mm_storeu_si128(buf.as_ptr() as *mut __m128i, byte_swap(checksum));
            buffer[block_start..].copy_from_slice(&buf[..remaining]);

            lup = gf128_mul2(&lup);
            ldown = gf128_mul2(&ldown);

            block = _mm_xor_si128(block, lup);
            block = self.bc_encrypt(block);

            rho(&mut block, &mut w);

            block = self.bc_encrypt(block);
            block = _mm_xor_si128(block, ldown);

            _mm_storeu_si128(buf.as_ptr() as *mut __m128i, byte_swap(block));

            // Checking tag correctness
            if tag[16 - remaining..] != GenericArray::from(buf)[..remaining] {
                return Err(Error);
            }
            if remaining < 16 {
                _mm_storeu_si128(buf.as_ptr() as *mut __m128i, byte_swap(checksum));
                if buf[remaining] != 0x80 {
                    return Err(Error);
                }
                for i in buf.iter().skip(remaining + 1) {
                    if *i != 0 {
                        return Err(Error);
                    }
                }
            }
            Ok(())
        }
    }
}

impl<B, NonceSize> Colm0<B, NonceSize>
where
    B: BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt + BlockDecrypt,
    NonceSize: ArrayLength<u8>,
{
    /// COLM's AD processing
    #[inline]
    fn mac(&self, ad: &[u8], nonce: &Nonce<NonceSize>, ll: &__m128i) -> __m128i {
        unsafe {
            let mut v: __m128i;
            let mut delta: __m128i;
            let mut block: __m128i;
            let mut buf = [0u8; 16];
            let mut len = ad.len();
            let mut block_end = 16;
            let mut block_start = 0;
            let mut npub = [0u8; 8];

            npub[..].copy_from_slice(nonce);

            delta = gf128_mul3(ll);
            v = _mm_set_epi64x(0, i64::from_be_bytes(npub));
            v = byte_swap(v);
            v = _mm_xor_si128(v, delta);
            v = self.bc_encrypt(v);

            // MAC full length blocks
            while len >= 16 {
                delta = gf128_mul2(&delta);
                block = _mm_loadu_si128(ad[block_start..block_end].as_ptr() as *const __m128i);
                block = byte_swap(block);
                block = _mm_xor_si128(block, delta);
                block = self.bc_encrypt(block);
                v = _mm_xor_si128(v, block);

                len -= 16;
                block_end += 16;
                block_start += 16;
            }

            if len > 0 {
                // last block partial
                delta = gf128_mul7(&delta);
                buf[0..len].copy_from_slice(&ad[block_start..block_start + len]);
                buf[len] ^= 0x80; // padding
                block = _mm_loadu_si128(buf[0..16].as_ptr() as *const __m128i);
                block = byte_swap(block);
                block = _mm_xor_si128(block, delta);
                block = self.bc_encrypt(block);
                v = _mm_xor_si128(v, block);
            }

            v
        }
    }

    // Encryption procedure of the internal block cipher
    #[inline]
    fn bc_encrypt(&self, _in: __m128i) -> __m128i {
        let mut tmp = u8x16::from(byte_swap(_in));
        self.cipher.encrypt_block(tmp.as_mut_array().into());
        byte_swap(tmp.into())
    }

    // Decryption procedure of the internal block cipher
    #[inline]
    fn bc_decrypt(&self, _in: __m128i) -> __m128i {
        let mut tmp = u8x16::from(byte_swap(_in));
        self.cipher.decrypt_block(tmp.as_mut_array().into());
        byte_swap(tmp.into())
    }
}
