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
//! # #[cfg(feature = "alloc")] {
//! use ascon_aead128::{AsconAead128, Key, Nonce};
//! use ascon_aead128::aead::{Aead, KeyInit};
//!
//! let key = Key::<AsconAead128>::from_slice(b"very secret key.");
//! let cipher = AsconAead128::new(key);
//!
//! let nonce = Nonce::<AsconAead128>::from_slice(b"unique nonce 012"); // 128-bits; unique per message
//!
//! let ciphertext = cipher.encrypt(nonce, b"plaintext message".as_ref())
//!     .expect("encryption failure!"); // NOTE: handle this error to avoid panics!
//!
//! let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
//!     .expect("decryption failure!"); // NOTE: handle this error to avoid panics!
//!
//! assert_eq!(&plaintext, b"plaintext message");
//! # }
//! ```
//!
//! With randomly sampled keys and nonces (requires `getrandom` feature):
//!
//! ```
//! # #[cfg(feature = "getrandom")] {
//! use ascon_aead128::AsconAead128;
//! use ascon_aead128::aead::{Aead, AeadCore, KeyInit, OsRng};
//!
//! let key = AsconAead128::generate_key().expect("generate key");
//! let cipher = AsconAead128::new(&key);
//!
//! let nonce = AsconAead128::generate_nonce().expect("generate nonce"); // 128 bits; unique per message
//!
//! let ciphertext = cipher.encrypt(&nonce, b"plaintext message".as_ref())
//!     .expect("encryption failure!"); // NOTE: handle this error to avoid panics!
//!
//! let plaintext = cipher.decrypt(&nonce, ciphertext.as_ref())
//!     .expect("decryption failure!"); // NOTE: handle this error to avoid panics!
//!
//! assert_eq!(&plaintext, b"plaintext message");
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
//! # #[cfg(feature = "heapless")] {
//! use ascon_aead128::{AsconAead128, Key, Nonce};
//! use ascon_aead128::aead::{AeadInPlace, KeyInit};
//! use ascon_aead128::aead::heapless::Vec;
//!
//! let key = Key::<AsconAead128>::from_slice(b"very secret key.");
//! let cipher = AsconAead128::new(key);
//!
//! let nonce = Nonce::<AsconAead128>::from_slice(b"unique nonce 012"); // 128-bits; unique per message
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
//!
//! Similarly, enabling the `arrayvec` feature of this crate will provide an impl of
//! [`aead::Buffer`] for `arrayvec::ArrayVec` (re-exported from the [`aead`] crate as
//! [`aead::arrayvec::ArrayVec`]), and enabling the `bytes` feature of this crate will
//! provide an impl of [`aead::Buffer`] for `bytes::BytesMut` (re-exported from the
//! [`aead`] crate as [`aead::bytes::BytesMut`]).

#[cfg(feature = "zeroize")]
pub use zeroize;

pub use aead::{self, Error, Key, Nonce, Tag};
use aead::{AeadCore, AeadInPlaceDetached, KeyInit, KeySizeUser, PostfixTagged, consts::U16};

mod asconcore;

use asconcore::{AsconCore, Parameters, Parameters128};

/// Ascon generic over some Parameters
///
/// This type is generic to support substituting various Ascon parameter sets. It is not intended to
/// be uses directly. Use the [`AsconAead128`] type aliases instead.
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
}

impl<P: Parameters> PostfixTagged for Ascon<P> {}

impl<P: Parameters> AeadInPlaceDetached for Ascon<P> {
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

/// Ascon-AEAD128
pub struct AsconAead128(Ascon<Parameters128>);
/// Key for Ascon-AEAD128
pub type AsconAead128Key = Key<AsconAead128>;
/// Nonce for Ascon-AEAD128
pub type AsconAead128Nonce = Nonce<AsconAead128>;
/// Tag for Ascon-AEAD128
pub type AsconAead128Tag = Tag<AsconAead128>;

impl KeySizeUser for AsconAead128 {
    type KeySize = U16;
}

impl KeyInit for AsconAead128 {
    fn new(key: &Key<Self>) -> Self {
        Self(Ascon::<Parameters128>::new(key))
    }
}

impl AeadCore for AsconAead128 {
    type NonceSize = U16;
    type TagSize = U16;
}

impl PostfixTagged for AsconAead128 {}

impl AeadInPlaceDetached for AsconAead128 {
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
