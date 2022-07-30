//! EAX: [Authenticated Encryption and Associated Data (AEAD)][1] cipher
//! based on AES in counter mode.
//!
//! # Usage
//!
//! Simple usage (allocating, no associated data):
//!
#![cfg_attr(all(feature = "getrandom", feature = "std"), doc = "```")]
#![cfg_attr(not(all(feature = "getrandom", feature = "std")), doc = "```ignore")]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use aes::Aes256;
//! use eax::{
//!     aead::{Aead, KeyInit, OsRng, generic_array::GenericArray},
//!     Eax, Nonce
//! };
//!
//! pub type Aes256Eax = Eax<Aes256>;
//!
//! let key = Aes256Eax::generate_key(&mut OsRng);
//! let cipher = Aes256Eax::new(&key);
//! let nonce = GenericArray::from_slice(b"my unique nonces"); // 128-bits; unique per message
//! let ciphertext = cipher.encrypt(nonce, b"plaintext message".as_ref())?;
//! let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())?;
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
//! use aes::Aes256;
//! use eax::Eax;
//! use eax::aead::{AeadInPlace, KeyInit, generic_array::GenericArray};
//! use eax::aead::heapless::Vec;
//!
//! let key = GenericArray::from_slice(b"an example very very secret key.");
//! let cipher = Eax::<Aes256>::new(key);
//!
//! let nonce = GenericArray::from_slice(b"my unique nonces"); // 128-bits; unique per message
//!
//! let mut buffer: Vec<u8, 128> = Vec::new();
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
//! ## Custom Tag Length
//!
//! The tag for eax is usually 16 bytes long but it can be shortened if needed.
//! The second generic argument of `Eax` can be set to the tag length:
//!
//! ```
//! # #[cfg(feature = "heapless")]
//! # {
//! use aes::Aes256;
//! use eax::Eax;
//! use eax::aead::{AeadInPlace, KeyInit, generic_array::GenericArray};
//! use eax::aead::heapless::Vec;
//! use eax::aead::consts::{U8, U128};
//!
//! let key = GenericArray::from_slice(b"an example very very secret key.");
//! let cipher = Eax::<Aes256, U8>::new(key);
//!
//! let nonce = GenericArray::from_slice(b"my unique nonces"); // 128-bits; unique per message
//!
//! let mut buffer: Vec<u8, 128> = Vec::new();
//! buffer.extend_from_slice(b"plaintext message");
//!
//! // Encrypt `buffer` in-place, replacing the plaintext contents with ciphertext
//! let tag = cipher.encrypt_in_place_detached(nonce, b"", &mut buffer).expect("encryption failure!");
//!
//! // The tag has only 8 bytes, compared to the usual 16 bytes
//! assert_eq!(tag.len(), 8);
//!
//! // `buffer` now contains the message ciphertext
//! assert_ne!(&buffer, b"plaintext message");
//!
//! // Decrypt `buffer` in-place, replacing its ciphertext context with the original plaintext
//! cipher.decrypt_in_place_detached(nonce, b"", &mut buffer, &tag).expect("decryption failure!");
//! assert_eq!(&buffer, b"plaintext message");
//! # }
//! ```
//!
//! [1]: https://en.wikipedia.org/wiki/Authenticated_encryption

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub use aead::{self, AeadCore, AeadInPlace, Error, Key, KeyInit, KeySizeUser};
pub use cipher;

use cipher::{
    consts::{U0, U16},
    generic_array::{functional::FunctionalSequence, GenericArray},
    BlockCipher, BlockEncrypt, InnerIvInit, StreamCipherCore,
};
use cmac::{digest::Output, Cmac, Mac};
use core::marker::PhantomData;

mod traits;

use traits::TagSize;

// TODO Max values?
/// Maximum length of associated data
pub const A_MAX: u64 = 1 << 36;

/// Maximum length of plaintext
pub const P_MAX: u64 = 1 << 36;

/// Maximum length of ciphertext
pub const C_MAX: u64 = (1 << 36) + 16;

/// EAX nonces
pub type Nonce<NonceSize> = GenericArray<u8, NonceSize>;

/// EAX tags
pub type Tag<TagSize> = GenericArray<u8, TagSize>;

pub mod online;

/// Counter mode with a 128-bit big endian counter.
type Ctr128BE<C> = ctr::CtrCore<C, ctr::flavors::Ctr128BE>;

/// EAX: generic over an underlying block cipher implementation.
///
/// This type is generic to support substituting alternative cipher
/// implementations.
///
/// If in doubt, use the built-in [`Aes128Eax`] and [`Aes256Eax`] type aliases.
///
/// Type parameters:
/// - `Cipher`: block cipher.
/// - `M`: size of MAC tag, valid values: up to `U16`.
#[derive(Clone)]
pub struct Eax<Cipher, M = U16>
where
    Cipher: BlockCipher<BlockSize = U16> + BlockEncrypt + Clone + KeyInit,
    M: TagSize,
{
    /// Encryption key
    key: Key<Cipher>,
    _tag_size: PhantomData<M>,
}

impl<Cipher, M> KeySizeUser for Eax<Cipher, M>
where
    Cipher: BlockCipher<BlockSize = U16> + BlockEncrypt + Clone + KeyInit,
    M: TagSize,
{
    type KeySize = Cipher::KeySize;
}

impl<Cipher, M> KeyInit for Eax<Cipher, M>
where
    Cipher: BlockCipher<BlockSize = U16> + BlockEncrypt + Clone + KeyInit,
    M: TagSize,
{
    fn new(key: &Key<Cipher>) -> Self {
        Self {
            key: key.clone(),
            _tag_size: PhantomData,
        }
    }
}

impl<Cipher, M> AeadCore for Eax<Cipher, M>
where
    Cipher: BlockCipher<BlockSize = U16> + BlockEncrypt + Clone + KeyInit,
    M: TagSize,
{
    type NonceSize = Cipher::BlockSize;
    type TagSize = M;
    type CiphertextOverhead = U0;
}

impl<Cipher, M> AeadInPlace for Eax<Cipher, M>
where
    Cipher: BlockCipher<BlockSize = U16> + BlockEncrypt + Clone + KeyInit,
    M: TagSize,
{
    fn encrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self::NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag<M>, Error> {
        if buffer.len() as u64 > P_MAX || associated_data.len() as u64 > A_MAX {
            return Err(Error);
        }

        // https://crypto.stackexchange.com/questions/26948/eax-cipher-mode-with-nonce-equal-header
        // has an explanation of eax.

        // l = block cipher size = 128 (for AES-128) = 16 byte
        // 1. n ← OMAC(0 || Nonce)
        // (the 0 means the number zero in l bits)
        let n = Self::cmac_with_iv(&self.key, 0, nonce);

        // 2. h ← OMAC(1 || associated data)
        let h = Self::cmac_with_iv(&self.key, 1, associated_data);

        // 3. enc ← CTR(M) using n as iv
        Ctr128BE::<Cipher>::inner_iv_init(Cipher::new(&self.key), &n)
            .apply_keystream_partial(buffer.into());

        // 4. c ← OMAC(2 || enc)
        let c = Self::cmac_with_iv(&self.key, 2, buffer);

        // 5. tag ← n ^ h ^ c
        // (^ means xor)
        let full_tag = n.zip(h, |a, b| a ^ b).zip(c, |a, b| a ^ b);
        let tag = Tag::<M>::clone_from_slice(&full_tag[..M::to_usize()]);
        Ok(tag)
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self::NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag<M>,
    ) -> Result<(), Error> {
        if buffer.len() as u64 > C_MAX || associated_data.len() as u64 > A_MAX {
            return Err(Error);
        }

        // 1. n ← OMAC(0 || Nonce)
        let n = Self::cmac_with_iv(&self.key, 0, nonce);

        // 2. h ← OMAC(1 || associated data)
        let h = Self::cmac_with_iv(&self.key, 1, associated_data);

        // 4. c ← OMAC(2 || enc)
        let c = Self::cmac_with_iv(&self.key, 2, buffer);

        // 5. tag ← n ^ h ^ c
        // (^ means xor)
        let expected_tag = n.zip(h, |a, b| a ^ b).zip(c, |a, b| a ^ b);

        let expected_tag = &expected_tag[..tag.len()];

        // Constant-time MAC comparison
        use subtle::ConstantTimeEq;
        if expected_tag.ct_eq(tag).into() {
            // Decrypt
            Ctr128BE::<Cipher>::inner_iv_init(Cipher::new(&self.key), &n)
                .apply_keystream_partial(buffer.into());

            Ok(())
        } else {
            Err(Error)
        }
    }
}

impl<Cipher, M> Eax<Cipher, M>
where
    Cipher: BlockCipher<BlockSize = U16> + BlockEncrypt + Clone + KeyInit,
    M: TagSize,
{
    /// CMAC/OMAC1
    ///
    /// To avoid constructing new buffers on the heap, an iv encoded into 16
    /// bytes is prepended inside this function.
    fn cmac_with_iv(
        key: &GenericArray<u8, Cipher::KeySize>,
        iv: u8,
        data: &[u8],
    ) -> Output<Cmac<Cipher>> {
        let mut mac = <Cmac<Cipher> as Mac>::new(key);
        mac.update(&[0; 15]);
        mac.update(&[iv]);
        mac.update(data);

        mac.finalize().into_bytes()
    }
}
