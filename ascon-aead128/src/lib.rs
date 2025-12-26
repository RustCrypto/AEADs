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
#![cfg_attr(feature = "getrandom", doc = "```")]
#![cfg_attr(not(feature = "getrandom"), doc = "```ignore")]
//! # fn main() -> Result<(), Box<dyn core::error::Error>> {
//! // NOTE: requires the `getrandom` feature is enabled
//!
//! use ascon_aead128::{
//!     aead::{Aead, Generate, KeyInit, AeadCore},
//!     AsconAead128, AsconAead128Key, AsconAead128Nonce
//! };
//!
//! let key = AsconAead128Key::generate();
//! let cipher = AsconAead128::new(&key);
//!
//! let nonce = AsconAead128Nonce::generate(); // MUST be unique per message
//! let ciphertext = cipher.encrypt(&nonce, b"plaintext message".as_ref())?;
//!
//! let plaintext = cipher.decrypt(&nonce, ciphertext.as_ref())?;
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
//! The [`AeadInOut::encrypt_in_place`] and [`AeadInOut::decrypt_in_place`]
//! methods accept any type that impls the [`aead::Buffer`] trait which
//! contains the plaintext for encryption or ciphertext for decryption.
//!
//! Enabling the `arrayvec` feature of this crate will provide an impl of
//! [`aead::Buffer`] for `arrayvec::ArrayVec` (re-exported from the [`aead`] crate as
//! [`aead::arrayvec::ArrayVec`]), and enabling the `bytes` feature of this crate will
//! provide an impl of [`aead::Buffer`] for `bytes::BytesMut` (re-exported from the
//! [`aead`] crate as [`aead::bytes::BytesMut`]).
//!
//! It can then be passed as the `buffer` parameter to the in-place encrypt
//! and decrypt methods:
//!
#![cfg_attr(all(feature = "getrandom", feature = "arrayvec"), doc = "```")]
#![cfg_attr(
    not(all(feature = "getrandom", feature = "arrayvec")),
    doc = "```ignore"
)]
//! # fn main() -> Result<(), Box<dyn core::error::Error>> {
//! // NOTE: requires the `arrayvec` and `getrandom` features are enabled
//!
//! use ascon_aead128::{
//!     aead::{AeadCore, AeadInOut, Generate, KeyInit, arrayvec::ArrayVec},
//!     AsconAead128, AsconAead128Key, AsconAead128Nonce
//! };
//!
//! let key = AsconAead128Key::generate();
//! let cipher = AsconAead128::new(&key);
//!
//! let nonce = AsconAead128Nonce::generate(); // MUST be unique per message
//! let mut buffer: ArrayVec<u8, 128> = ArrayVec::new(); // Buffer needs 16-bytes overhead for authentication tag
//! buffer.try_extend_from_slice(b"plaintext message").unwrap();
//!
//! // Encrypt `buffer` in-place, replacing the plaintext contents with ciphertext
//! cipher.encrypt_in_place(&nonce, b"", &mut buffer).expect("encryption failure!");
//!
//! // `buffer` now contains the message ciphertext
//! assert_ne!(buffer.as_ref(), b"plaintext message");
//!
//! // Decrypt `buffer` in-place, replacing its ciphertext context with the original plaintext
//! cipher.decrypt_in_place(&nonce, b"", &mut buffer).expect("decryption failure!");
//! assert_eq!(buffer.as_ref(), b"plaintext message");
//! # Ok(())
//! # }
//! ```

#[cfg(feature = "zeroize")]
pub use zeroize;

pub use aead::{self, Error, Key, Nonce, Tag};
use aead::{AeadCore, AeadInOut, KeyInit, KeySizeUser, TagPosition, consts::U16, inout::InOutBuf};

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
    const TAG_POSITION: TagPosition = TagPosition::Postfix;
}

impl<P: Parameters> AeadInOut for Ascon<P> {
    fn encrypt_inout_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
    ) -> Result<Tag<Self>, Error> {
        if (buffer.len() as u64)
            .checked_add(associated_data.len() as u64)
            .is_none()
        {
            return Err(Error);
        }

        let mut core = AsconCore::<P>::new(&self.key, nonce);
        Ok(core.encrypt_inout(buffer, associated_data))
    }

    fn decrypt_inout_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
        tag: &Tag<Self>,
    ) -> Result<(), Error> {
        if (buffer.len() as u64)
            .checked_add(associated_data.len() as u64)
            .is_none()
        {
            return Err(Error);
        }

        let mut core = AsconCore::<P>::new(&self.key, nonce);
        core.decrypt_inout(buffer, associated_data, tag)
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
    const TAG_POSITION: TagPosition = TagPosition::Postfix;
}

impl AeadInOut for AsconAead128 {
    #[inline(always)]
    fn encrypt_inout_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
    ) -> Result<Tag<Self>, Error> {
        self.0
            .encrypt_inout_detached(nonce, associated_data, buffer)
    }

    #[inline(always)]
    fn decrypt_inout_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
        tag: &Tag<Self>,
    ) -> Result<(), Error> {
        self.0
            .decrypt_inout_detached(nonce, associated_data, buffer, tag)
    }
}
