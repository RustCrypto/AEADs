// Copyright 2021-2023 Sebastian Ramacher
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![warn(missing_docs)]

//! ## Usage
//!
//! Simple usage (allocating, no associated data):
//!
//! ```
//! use ascon_aead::{Ascon128, Key, Nonce}; // Or `Ascon128a`
//! use ascon_aead::aead::{Aead, KeyInit};
//!
//! let key = Key::<Ascon128>::from_slice(b"very secret key.");
//! let cipher = Ascon128::new(key);
//!
//! let nonce = Nonce::<Ascon128>::from_slice(b"unique nonce 012"); // 128-bits; unique per message
//!
//! let ciphertext = cipher.encrypt(nonce, b"plaintext message".as_ref())
//!     .expect("encryption failure!"); // NOTE: handle this error to avoid panics!
//!
//! let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
//!     .expect("decryption failure!"); // NOTE: handle this error to avoid panics!
//!
//! assert_eq!(&plaintext, b"plaintext message");
//! ```
//!
//! ## In-place Usage (eliminates `alloc` requirement)
//!
//! Similar to other crates implementing [`aead`] interfaces, this crate also offers an optional
//! `alloc` feature which can be disabled in e.g. microcontroller environments that don't have a
//! heap. See [`aead::AeadInPlace`] for more details.
//!
//! ```
//! # #[cfg(feature = "heapless")] {
//! use ascon_aead::{Ascon128, Key, Nonce}; // Or `Ascon128a`
//! use ascon_aead::aead::{AeadInPlace, KeyInit};
//! use ascon_aead::aead::heapless::Vec;
//!
//! let key = Key::<Ascon128>::from_slice(b"very secret key.");
//! let cipher = Ascon128::new(key);
//!
//! let nonce = Nonce::<Ascon128>::from_slice(b"unique nonce 012"); // 128-bits; unique per message
//!
//! let mut buffer: Vec<u8, 128> = Vec::new(); // Buffer needs 16-bytes overhead for authentication tag
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

pub use aead::{self, Error, Key, Nonce, Tag};
use aead::{
    consts::{U0, U16, U20},
    AeadCore, AeadInPlace, KeyInit, KeySizeUser,
};

mod asconcore;

use asconcore::{AsconCore, Parameters, Parameters128, Parameters128a, Parameters80pq};

/// Ascon generic over some Parameters
///
/// This type is generic to support substituting various Ascon parameter sets. It is not intended to
/// be uses directly. Use the [`Ascon128`], [`Ascon128a`], [`Ascon80pq`] type aliases instead.
#[derive(Clone)]
struct Ascon<P: Parameters> {
    key: P::InternalKey,
}

impl<P: Parameters> KeySizeUser for Ascon<P> {
    type KeySize = P::KeySize;
}

impl<P: Parameters> KeyInit for Ascon<P> {
    fn new(key: &Key<Self>) -> Self {
        Self {
            key: P::InternalKey::from(key),
        }
    }
}

impl<P: Parameters> AeadCore for Ascon<P> {
    type NonceSize = U16;
    type TagSize = U16;
    type CiphertextOverhead = U0;
}

impl<P: Parameters> AeadInPlace for Ascon<P> {
    fn encrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag<Self>, Error> {
        if (buffer.len() as u64)
            .checked_add(associated_data.len() as u64)
            .is_none()
        {
            return Err(Error);
        }

        let mut core = AsconCore::<P>::new(&self.key, nonce);
        Ok(core.encrypt_inplace(buffer, associated_data))
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag<Self>,
    ) -> Result<(), Error> {
        if (buffer.len() as u64)
            .checked_add(associated_data.len() as u64)
            .is_none()
        {
            return Err(Error);
        }

        let mut core = AsconCore::<P>::new(&self.key, nonce);
        core.decrypt_inplace(buffer, associated_data, tag)
    }
}

/// Ascon-128
pub struct Ascon128(Ascon<Parameters128>);
/// Key for Ascon-128
pub type Ascon128Key = Key<Ascon128>;
/// Nonce for Ascon-128
pub type Ascon128Nonce = Nonce<Ascon128>;
/// Tag for Ascon-128
pub type Ascon128Tag = Tag<Ascon128>;

impl KeySizeUser for Ascon128 {
    type KeySize = U16;
}

impl KeyInit for Ascon128 {
    fn new(key: &Key<Self>) -> Self {
        Self(Ascon::<Parameters128>::new(key))
    }
}

impl AeadCore for Ascon128 {
    type NonceSize = U16;
    type TagSize = U16;
    type CiphertextOverhead = U0;
}

impl AeadInPlace for Ascon128 {
    #[inline(always)]
    fn encrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag<Self>, Error> {
        self.0
            .encrypt_in_place_detached(nonce, associated_data, buffer)
    }

    #[inline(always)]
    fn decrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag<Self>,
    ) -> Result<(), Error> {
        self.0
            .decrypt_in_place_detached(nonce, associated_data, buffer, tag)
    }
}

/// Ascon-128a
pub struct Ascon128a(Ascon<Parameters128a>);

/// Key for Ascon-128a
pub type Ascon128aKey = Key<Ascon128a>;
/// Nonce for Ascon-128a
pub type Ascon128aNonce = Nonce<Ascon128a>;
/// Tag for Ascon-128a
pub type Ascon128aTag = Tag<Ascon128a>;

impl KeySizeUser for Ascon128a {
    type KeySize = U16;
}

impl KeyInit for Ascon128a {
    fn new(key: &Key<Self>) -> Self {
        Self(Ascon::<Parameters128a>::new(key))
    }
}

impl AeadCore for Ascon128a {
    type NonceSize = U16;
    type TagSize = U16;
    type CiphertextOverhead = U0;
}

impl AeadInPlace for Ascon128a {
    #[inline(always)]
    fn encrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag<Self>, Error> {
        self.0
            .encrypt_in_place_detached(nonce, associated_data, buffer)
    }

    #[inline(always)]
    fn decrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag<Self>,
    ) -> Result<(), Error> {
        self.0
            .decrypt_in_place_detached(nonce, associated_data, buffer, tag)
    }
}

/// Ascon-80pq
pub struct Ascon80pq(Ascon<Parameters80pq>);
/// Key for Ascon-80pq
pub type Ascon80pqKey = Key<Ascon80pq>;
/// Nonce for Ascon-80pq
pub type Ascon80pqNonce = Nonce<Ascon80pq>;
/// Tag for Ascon-80pq
pub type Ascon80pqTag = Tag<Ascon80pq>;

impl KeySizeUser for Ascon80pq {
    type KeySize = U20;
}

impl KeyInit for Ascon80pq {
    fn new(key: &Key<Self>) -> Self {
        Self(Ascon::<Parameters80pq>::new(key))
    }
}

impl AeadCore for Ascon80pq {
    type NonceSize = U16;
    type TagSize = U16;
    type CiphertextOverhead = U0;
}

impl AeadInPlace for Ascon80pq {
    #[inline(always)]
    fn encrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag<Self>, Error> {
        self.0
            .encrypt_in_place_detached(nonce, associated_data, buffer)
    }

    #[inline(always)]
    fn decrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag<Self>,
    ) -> Result<(), Error> {
        self.0
            .decrypt_in_place_detached(nonce, associated_data, buffer, tag)
    }
}
