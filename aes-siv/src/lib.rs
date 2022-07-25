//! [AES-SIV][1] ([RFC 5297][2]):
//! [Authenticated Encryption with Associated Data (AEAD)][3] cipher which also
//! provides [nonce reuse misuse resistance][4].
//!
//! # Usage
//!
//! Simple usage (allocating, no associated data):
//!
#![cfg_attr(all(feature = "getrandom", feature = "std"), doc = "```")]
#![cfg_attr(not(all(feature = "getrandom", feature = "std")), doc = "```ignore")]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use aes_siv::{
//!     aead::{Aead, KeyInit, OsRng},
//!     Aes256SivAead, Nonce // Or `Aes128SivAead`
//! };
//!
//! let key = Aes256SivAead::generate_key(&mut OsRng);
//! let cipher = Aes256SivAead::new(&key);
//! let nonce = Nonce::from_slice(b"any unique nonce"); // 128-bits; unique per message
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
#![cfg_attr(
    all(feature = "getrandom", feature = "heapless", feature = "std"),
    doc = "```"
)]
#![cfg_attr(
    not(all(feature = "getrandom", feature = "heapless", feature = "std")),
    doc = "```ignore"
)]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use aes_siv::{
//!     aead::{AeadInPlace, KeyInit, OsRng, heapless::Vec},
//!     Aes256SivAead, Nonce, // Or `Aes128SivAead`
//! };
//!
//! let key = Aes256SivAead::generate_key(&mut OsRng);
//! let cipher = Aes256SivAead::new(&key);
//! let nonce = Nonce::from_slice(b"any unique nonce"); // 128-bits; unique per message
//!
//! let mut buffer: Vec<u8, 128> = Vec::new(); // Note: buffer needs 16-bytes overhead for auth tag tag
//! buffer.extend_from_slice(b"plaintext message");
//!
//! // Encrypt `buffer` in-place, replacing the plaintext contents with ciphertext
//! cipher.encrypt_in_place(nonce, b"", &mut buffer)?;
//!
//! // `buffer` now contains the message ciphertext
//! assert_ne!(&buffer, b"plaintext message");
//!
//! // Decrypt `buffer` in-place, replacing its ciphertext context with the original plaintext
//! cipher.decrypt_in_place(nonce, b"", &mut buffer)?;
//! assert_eq!(&buffer, b"plaintext message");
//! # Ok(())
//! # }
//! ```
//!
//! [1]: https://github.com/miscreant/meta/wiki/AES-SIV
//! [2]: https://tools.ietf.org/html/rfc5297
//! [3]: https://en.wikipedia.org/wiki/Authenticated_encryption
//! [4]: https://github.com/miscreant/meta/wiki/Nonce-Reuse-Misuse-Resistance

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod siv;

pub use aead::{self, AeadCore, AeadInPlace, Error, Key, KeyInit, KeySizeUser};

use crate::siv::Siv;
use aead::{
    consts::{U0, U16, U32, U64},
    generic_array::GenericArray,
    Buffer,
};
use aes::{Aes128, Aes256};
use cipher::{BlockCipher, BlockEncryptMut};
use cmac::Cmac;
use core::{marker::PhantomData, ops::Add};
use digest::{FixedOutputReset, Mac};

#[cfg(feature = "pmac")]
use pmac::Pmac;

/// AES-SIV nonces
pub type Nonce = GenericArray<u8, U16>;

/// AES-SIV tags (i.e. the Synthetic Initialization Vector value)
pub type Tag = GenericArray<u8, U16>;

/// The `SivAead` type wraps the more powerful `Siv` interface in a more
/// commonly used Authenticated Encryption with Associated Data (AEAD) API,
/// which accepts a key, nonce, and associated data when encrypting/decrypting.
pub struct SivAead<C, M>
where
    Self: KeySizeUser,
    C: BlockCipher<BlockSize = U16> + BlockEncryptMut + KeyInit + KeySizeUser,
    M: Mac<OutputSize = U16> + FixedOutputReset + KeyInit,
    <C as KeySizeUser>::KeySize: Add,
{
    key: GenericArray<u8, <Self as KeySizeUser>::KeySize>,
    mac: PhantomData<M>, // TODO(tarcieri): include `M` in `KeySize` calculation
}

/// SIV AEAD modes based on CMAC
pub type CmacSivAead<BlockCipher> = SivAead<BlockCipher, Cmac<BlockCipher>>;

/// SIV AEAD modes based on PMAC
#[cfg(feature = "pmac")]
#[cfg_attr(docsrs, doc(cfg(feature = "pmac")))]
pub type PmacSivAead<BlockCipher> = SivAead<BlockCipher, Pmac<BlockCipher>>;

/// AES-CMAC-SIV in AEAD mode with 256-bit key size (128-bit security)
pub type Aes128SivAead = CmacSivAead<Aes128>;

/// AES-CMAC-SIV in AEAD mode with 512-bit key size (256-bit security)
pub type Aes256SivAead = CmacSivAead<Aes256>;

/// AES-PMAC-SIV in AEAD mode with 256-bit key size (128-bit security)
#[cfg(feature = "pmac")]
#[cfg_attr(docsrs, doc(cfg(feature = "pmac")))]
pub type Aes128PmacSivAead = PmacSivAead<Aes128>;

/// AES-PMAC-SIV in AEAD mode with 512-bit key size (256-bit security)
#[cfg(feature = "pmac")]
#[cfg_attr(docsrs, doc(cfg(feature = "pmac")))]
pub type Aes256PmacSivAead = PmacSivAead<Aes256>;

impl<M> KeySizeUser for SivAead<Aes128, M>
where
    M: Mac<OutputSize = U16> + FixedOutputReset + KeyInit,
{
    type KeySize = U32;
}

impl<M> KeySizeUser for SivAead<Aes256, M>
where
    M: Mac<OutputSize = U16> + FixedOutputReset + KeyInit,
{
    type KeySize = U64;
}

impl<M> KeyInit for SivAead<Aes128, M>
where
    M: Mac<OutputSize = U16> + FixedOutputReset + KeyInit,
{
    fn new(key: &GenericArray<u8, Self::KeySize>) -> Self {
        Self {
            key: *key,
            mac: PhantomData,
        }
    }
}

impl<M> KeyInit for SivAead<Aes256, M>
where
    M: Mac<OutputSize = U16> + FixedOutputReset + KeyInit,
{
    fn new(key: &GenericArray<u8, Self::KeySize>) -> Self {
        Self {
            key: *key,
            mac: PhantomData,
        }
    }
}

impl<C, M> AeadCore for SivAead<C, M>
where
    Self: KeySizeUser,
    C: BlockCipher<BlockSize = U16> + BlockEncryptMut + KeyInit + KeySizeUser,
    M: Mac<OutputSize = U16> + FixedOutputReset + KeyInit,
    <C as KeySizeUser>::KeySize: Add,
{
    // "If the nonce is random, it SHOULD be at least 128 bits in length"
    // https://tools.ietf.org/html/rfc5297#section-3
    // TODO(tarcieri): generic nonce sizes
    type NonceSize = U16;
    type TagSize = U16;
    type CiphertextOverhead = U0;
}

impl<C, M> AeadInPlace for SivAead<C, M>
where
    Self: KeySizeUser,
    Siv<C, M>: KeyInit + KeySizeUser<KeySize = <Self as KeySizeUser>::KeySize>,
    C: BlockCipher<BlockSize = U16> + BlockEncryptMut + KeyInit + KeySizeUser,
    M: Mac<OutputSize = U16> + FixedOutputReset + KeyInit,
    <C as KeySizeUser>::KeySize: Add,
{
    fn encrypt_in_place(
        &self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        associated_data: &[u8],
        buffer: &mut dyn Buffer,
    ) -> Result<(), Error> {
        // "SIV performs nonce-based authenticated encryption when a component of
        // the associated data is a nonce.  For purposes of interoperability the
        // final component -- i.e., the string immediately preceding the
        // plaintext in the vector input to S2V -- is used for the nonce."
        // https://tools.ietf.org/html/rfc5297#section-3
        Siv::<C, M>::new(&self.key).encrypt_in_place(&[associated_data, nonce.as_slice()], buffer)
    }

    fn encrypt_in_place_detached(
        &self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<GenericArray<u8, Self::TagSize>, Error> {
        Siv::<C, M>::new(&self.key)
            .encrypt_in_place_detached(&[associated_data, nonce.as_slice()], buffer)
    }

    fn decrypt_in_place(
        &self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        associated_data: &[u8],
        buffer: &mut dyn Buffer,
    ) -> Result<(), Error> {
        Siv::<C, M>::new(&self.key).decrypt_in_place(&[associated_data, nonce.as_slice()], buffer)
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &GenericArray<u8, Self::TagSize>,
    ) -> Result<(), Error> {
        Siv::<C, M>::new(&self.key).decrypt_in_place_detached(
            &[associated_data, nonce.as_slice()],
            buffer,
            tag,
        )
    }
}
