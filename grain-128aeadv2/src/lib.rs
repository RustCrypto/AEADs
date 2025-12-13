#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg"
)]
#![deny(unsafe_code)]
#![warn(missing_docs)]

//! ## Quickstart
//!
//! Basic usage (with default `vec` feature):
//!
//! If you don't want to use the module to generate the keys :
#![cfg_attr(feature = "vec", doc = "```")]
#![cfg_attr(not(feature = "vec"), doc = "```ignore")]
//! use grain_128aeadv2::{
//!     Grain128, Key, Nonce,
//!     aead::{KeyInit, AeadCore}
//! };
//!
//! // PLEASE use a RANDOM key/nonce (don't copy-paste this...)
//! let key = [12, 33, 91, 88, 1, 0, 132, 11, 231, 28, 1, 3, 5, 1, 5, 1];
//! let nonce = [91, 88, 1, 0, 132, 11, 231, 1, 23, 32, 22, 33];
//! let cipher = Grain128::new(&key.into());
//!
//! let (ciphertext, tag) = cipher.encrypt_aead(
//!     &nonce.into(),
//!     b"Some additional data",
//!     b"this is a secret message"
//! );
//!
//! let plaintext = cipher.decrypt_aead(
//!     &nonce.into(),
//!     b"Some additional data",
//!     &ciphertext,
//!     &tag
//! ).expect("Tag verification failed");
//!
//! assert_eq!(&plaintext, b"this is a secret message");
//!
//! ```
//! With randomly sampled keys and nonces (requires `getrandom` feature):
//!
#![cfg_attr(all(feature = "vec", feature = "getrandom"), doc = "```")]
#![cfg_attr(not(all(feature = "vec", feature = "getrandom")), doc = "```ignore")]
//! use grain_128aeadv2::{Grain128, aead::{Aead, AeadCore, KeyInit}};
//!
//! let key = Grain128::generate_key().expect("Unable to generate key");
//! let cipher = Grain128::new(&key);
//!
//! // A nonce must be USED ONLY ONCE !
//! let nonce = Grain128::generate_nonce().expect("Unable to generate nonce");
//! let (ciphertext, tag) = cipher.encrypt_aead(
//!     &nonce,
//!     b"Some additional data",
//!     b"this is a secret message"
//! );
//!
//! let plaintext = cipher.decrypt_aead(
//!     &nonce,
//!     b"Some additional data",
//!     &ciphertext,
//!     &tag
//! ).expect("Tag verification failed");
//!
//! assert_eq!(&plaintext, b"this is a secret message");
//! ```
//!
//! ## In-place encryption (`arrayvec` or `alloc`)
//!
//! The [`AeadInOut::encrypt_in_place`] and [`AeadInOut::decrypt_in_place`]
//! methods accept any type that impls the [`aead::Buffer`] trait which
//! contains the plaintext for encryption or ciphertext for decryption.
//!
//! Enabling the `arrayvec` feature of this crate will provide an impl of
//! [`aead::Buffer`] for `arrayvec::ArrayVec` (re-exported from the [`aead`] crate as
//! [`aead::arrayvec::ArrayVec`]).
//! Enabling the `alloc` feature of this crate will provide an impl of
//! [`aead::Buffer`] for `Vec`.
//!
//! It can then be passed as the `buffer` parameter to the in-place encrypt
//! and decrypt methods:
//!
#![cfg_attr(all(feature = "getrandom", feature = "arrayvec"), doc = "```")]
#![cfg_attr(
    not(all(feature = "getrandom", feature = "arrayvec")),
    doc = "```ignore"
)]
//! use grain_128aeadv2::{
//!     Grain128, Key, Nonce,
//!     aead::{AeadCore, AeadInOut, KeyInit, arrayvec::ArrayVec}
//! };
//!
//! let key = Grain128::generate_key().expect("Unable to generate key");
//! let cipher = Grain128::new(&key);
//!
//! // A nonce must be USED ONLY ONCE !
//! let nonce = Grain128::generate_nonce().expect("Unable to generate nonce");
//! // Take care : 8 bytes overhead to store the tag
//! let mut buffer: ArrayVec<u8, 24> = ArrayVec::new();
//! buffer.try_extend_from_slice(b"a secret message").unwrap();
//!
//! // Perform in place encryption inside 'buffer'
//! cipher.encrypt_in_place(&nonce, b"Some AD", &mut buffer).expect("Unable to encrypt");
//!
//! // Perform in place decryption
//! cipher.decrypt_in_place(&nonce, b"Some AD", &mut buffer).expect("Tag verification failed");
//!
//! assert_eq!(buffer.as_ref(), b"a secret message");
//! ```
#![cfg_attr(all(feature = "getrandom", feature = "alloc"), doc = "```")]
#![cfg_attr(not(all(feature = "getrandom", feature = "alloc")), doc = "```ignore")]
//! use grain_128aeadv2::{
//!     Grain128, Key, Nonce,
//!     aead::{AeadCore, AeadInOut, KeyInit, arrayvec::ArrayVec}
//! };
//!
//! let key = Grain128::generate_key().expect("Unable to generate key");
//! let cipher = Grain128::new(&key);
//!
//! // A nonce must be USED ONLY ONCE !
//! let nonce = Grain128::generate_nonce().expect("Unable to generate nonce");
//! // Take care : 8 bytes overhead to store the tag
//! let mut buffer: Vec<u8> = vec![];
//! buffer.extend_from_slice(b"a secret message");
//!
//! // Perform in place encryption inside 'buffer'
//! cipher.encrypt_in_place(&nonce, b"Some AD", &mut buffer).expect("Unable to encrypt");
//!
//! // Perform in place decryption
//! cipher.decrypt_in_place(&nonce, b"Some AD", &mut buffer).expect("Tag verification failed");
//!
//! assert_eq!(&buffer, b"a secret message");
//! ```

#[cfg(feature = "vec")]
extern crate alloc;
#[cfg(feature = "vec")]
use alloc::vec::Vec;

#[cfg(feature = "zeroize")]
pub use zeroize;

pub use aead::{
    self, AeadCore, AeadInOut, Buffer, Error, Key, KeyInit, KeySizeUser, Nonce, Tag, TagPosition,
    array::Array,
    consts::{U1, U8, U12, U16},
    inout::InOutBuf,
};

mod fsr;
mod grain_core;
mod traits;
mod utils;

use grain_core::GrainCore;

/// Grain-128AEADv2 cipher.
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop))]
pub struct Grain128 {
    pub(crate) key: u128,
}

// Implement to define key/iv size
impl KeySizeUser for Grain128 {
    type KeySize = U16;
}

impl KeyInit for Grain128 {
    fn new(key: &Key<Self>) -> Self {
        let mut key_int: u128 = 0;
        for i in 0..key.len() {
            key_int |= (key[i] as u128) << (i * 8);
        }

        Grain128 { key: key_int }
    }
}

// Implement to define Nonce/Tag size and
// where the tag is stored inside the buffer
impl AeadCore for Grain128 {
    type NonceSize = U12;
    type TagSize = U8;
    const TAG_POSITION: TagPosition = TagPosition::Postfix;
}

#[cfg(feature = "vec")]
impl Grain128 {
    /// Init a new grain128-AEADv2 cipher for the given nonce
    /// and encrypts the plaintext. One may provide associated
    /// data that will be authenticated too.
    ///
    /// ```
    /// use grain_128aeadv2::{Grain128, KeyInit};
    ///
    /// let key = b"my secret key !!";
    /// let cipher = Grain128::new(key.into());
    ///
    /// // A nonce must be USED ONLY ONCE !
    /// let (ciphertext, tag) = cipher.encrypt_aead(
    ///     b"super nonce!".into(),
    ///     b"this is associated data",
    ///     b"my secret"
    /// );
    /// ```
    pub fn encrypt_aead(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> (Vec<u8>, Tag<Self>) {
        let mut nonce_int: u128 = 0;
        for i in 0..nonce.len() {
            nonce_int |= (nonce[i] as u128) << (i * 8);
        }

        let mut cipher = GrainCore::new(self.key, nonce_int);

        let (ct, tag) = cipher.encrypt_aead(associated_data, plaintext);

        (ct, Tag::<Self>::from(tag))
    }

    /// Init a new grain128-AEADv2 cipher for the given nonce
    /// and decrypts the ciphertext. You need to provide the
    /// associated data if any.
    ///
    /// ```
    /// use grain_128aeadv2::{Grain128, KeyInit};
    ///
    /// let key = b"my secret key !!";
    /// let cipher = Grain128::new(key.into());
    ///
    /// // A nonce must be USED ONLY ONCE !
    /// let (ciphertext, tag) = cipher.encrypt_aead(
    ///     b"super nonce!".into(),
    ///     b"this is associated data",
    ///     b"my secret"
    /// );
    /// let decrypted = cipher.decrypt_aead(
    ///     b"super nonce!".into(),
    ///     b"this is associated data",
    ///     &ciphertext,
    ///     &tag
    /// ).expect("Unable to decrypt");
    ////
    /// assert_eq!(decrypted, b"my secret");
    /// ```
    pub fn decrypt_aead(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        ciphertext: &[u8],
        expected_tag: &Tag<Self>,
    ) -> Result<Vec<u8>, Error> {
        let mut nonce_int: u128 = 0;
        for i in 0..nonce.len() {
            nonce_int |= (nonce[i] as u128) << (i * 8);
        }

        let mut cipher = GrainCore::new(self.key, nonce_int);

        cipher.decrypt_aead(associated_data, ciphertext, expected_tag.as_slice())
    }
}

impl AeadInOut for Grain128 {
    fn encrypt_inout_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
    ) -> Result<Tag<Self>, Error> {
        let mut nonce_int: u128 = 0;
        for i in 0..nonce.len() {
            nonce_int |= (nonce[i] as u128) << (i * 8);
        }

        let mut cipher = GrainCore::new(self.key, nonce_int);

        let tag = Tag::<Self>::from(cipher.encrypt_auth_aead_inout(associated_data, buffer));

        Ok(tag)
    }

    fn decrypt_inout_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        mut buffer: InOutBuf<'_, '_, u8>,
        tag: &Tag<Self>,
    ) -> Result<(), Error> {
        let mut nonce_int: u128 = 0;
        for i in 0..nonce.len() {
            nonce_int |= (nonce[i] as u128) << (i * 8);
        }

        let mut cipher = GrainCore::new(self.key, nonce_int);

        let decrypt_res =
            cipher.decrypt_auth_aead_inout(associated_data, buffer.reborrow(), tag.as_slice());

        match decrypt_res {
            Ok(()) => Ok(()),
            _ => {
                // Avoid leaking the decrypted ciphertext
                buffer.get_out().fill(0);
                // Then return the error
                Err(Error)
            }
        }
    }
}
