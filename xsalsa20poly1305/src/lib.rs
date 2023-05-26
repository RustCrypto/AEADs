#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

//! # Usage
//!
#![cfg_attr(all(feature = "getrandom", feature = "std"), doc = "```")]
#![cfg_attr(not(all(feature = "getrandom", feature = "std")), doc = "```ignore")]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use xsalsa20poly1305::{
//!     aead::{Aead, KeyInit, OsRng},
//!     XSalsa20Poly1305, Nonce
//! };
//!
//! let key = XSalsa20Poly1305::generate_key(&mut OsRng);
//! let cipher = XSalsa20Poly1305::new(&key);
//! let nonce = XSalsa20Poly1305::generate_nonce(&mut OsRng); // unique per message
//! let ciphertext = cipher.encrypt(&nonce, b"plaintext message".as_ref())?;
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
//! The [`AeadInPlace::encrypt_in_place`] and [`AeadInPlace::decrypt_in_place`]
//! methods accept any type that impls the [`aead::Buffer`] trait which
//! contains the plaintext for encryption or ciphertext for decryption.
//!
//! Note that if you enable the `heapless` feature of this crate,
//! you will receive an impl of [`aead::Buffer`] for `heapless::Vec`
//! (re-exported from the `aead` crate as [`aead::heapless::Vec`]),
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
//! use xsalsa20poly1305::{
//!     aead::{AeadInPlace, KeyInit, OsRng, heapless::Vec},
//!     XSalsa20Poly1305, Nonce,
//! };
//!
//! let key = XSalsa20Poly1305::generate_key(&mut OsRng);
//! let cipher = XSalsa20Poly1305::new(&key);
//! let nonce = XSalsa20Poly1305::generate_nonce(&mut OsRng); // unique per message
//!
//! let mut buffer: Vec<u8, 128> = Vec::new(); // Note: buffer needs 16-bytes overhead for auth tag
//! buffer.extend_from_slice(b"plaintext message");
//!
//! // Encrypt `buffer` in-place, replacing the plaintext contents with ciphertext
//! cipher.encrypt_in_place(&nonce, b"", &mut buffer)?;
//!
//! // `buffer` now contains the message ciphertext
//! assert_ne!(&buffer, b"plaintext message");
//!
//! // Decrypt `buffer` in-place, replacing its ciphertext context with the original plaintext
//! cipher.decrypt_in_place(&nonce, b"", &mut buffer)?;
//! assert_eq!(&buffer, b"plaintext message");
//! # Ok(())
//! # }
//! ```
//!
//! ```
//! # #[cfg(feature = "heapless")]
//! # {
//! use xsalsa20poly1305::XSalsa20Poly1305;
//! use xsalsa20poly1305::aead::{AeadInPlace, KeyInit, generic_array::GenericArray};
//! use xsalsa20poly1305::aead::heapless::Vec;
//!
//! let key = GenericArray::from_slice(b"an example very very secret key.");
//! let cipher = XSalsa20Poly1305::new(key);
//!
//! let nonce = GenericArray::from_slice(b"extra long unique nonce!"); // 24-bytes; unique
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
//! Similarly, enabling the `arrayvec` feature of this crate will provide an impl of
//! [`aead::Buffer`] for `arrayvec::ArrayVec` (re-exported from the [`aead`] crate as
//! [`aead::arrayvec::ArrayVec`]).
//!
//! [1]: https://nacl.cr.yp.to/secretbox.html
//! [2]: https://en.wikipedia.org/wiki/Authenticated_encryption
//! [3]: https://docs.rs/salsa20
//! [4]: http://docs.rs/chacha20poly1305
//! [5]: https://docs.rs/chacha20poly1305/latest/chacha20poly1305/struct.XChaCha20Poly1305.html
//! [6]: https://tools.ietf.org/html/rfc8439

pub use aead::{self, consts, AeadCore, AeadInPlace, Error, KeyInit, KeySizeUser};
pub use salsa20::{Key, XNonce as Nonce};

use aead::{
    consts::{U0, U16, U24, U32},
    generic_array::GenericArray,
    Buffer,
};
use poly1305::Poly1305;
use salsa20::{
    cipher::{KeyIvInit, StreamCipher, StreamCipherSeek},
    XSalsa20,
};
use zeroize::Zeroize;

#[cfg(feature = "rand_core")]
use aead::rand_core::{CryptoRng, RngCore};

/// Size of an XSalsa20Poly1305 key in bytes
pub const KEY_SIZE: usize = 32;

/// Size of an XSalsa20Poly1305 nonce in bytes
pub const NONCE_SIZE: usize = 24;

/// Size of a Poly1305 tag in bytes
pub const TAG_SIZE: usize = 16;

/// Poly1305 tags
pub type Tag = GenericArray<u8, U16>;

/// **XSalsa20Poly1305** (a.k.a. NaCl `crypto_secretbox`) authenticated
/// encryption cipher.
#[derive(Clone)]
pub struct XSalsa20Poly1305 {
    /// Secret key
    key: Key,
}

impl XSalsa20Poly1305 {
    /// Generate a random nonce: every message MUST have a unique nonce!
    ///
    /// Do *NOT* ever reuse the same nonce for two messages!
    // TODO(tarcieri): remove this in favor of `AeadCore::generate_nonce`
    #[cfg(feature = "rand_core")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rand_core")))]
    pub fn generate_nonce<T>(csprng: &mut T) -> Nonce
    where
        T: RngCore + CryptoRng,
    {
        let mut nonce = [0u8; NONCE_SIZE];
        csprng.fill_bytes(&mut nonce);
        nonce.into()
    }
}

impl KeySizeUser for XSalsa20Poly1305 {
    type KeySize = U32;
}

impl KeyInit for XSalsa20Poly1305 {
    fn new(key: &Key) -> Self {
        XSalsa20Poly1305 { key: *key }
    }
}

impl AeadCore for XSalsa20Poly1305 {
    type NonceSize = U24;
    type TagSize = U16;
    type CiphertextOverhead = U0;
}

impl AeadInPlace for XSalsa20Poly1305 {
    fn encrypt_in_place(
        &self,
        nonce: &Nonce,
        associated_data: &[u8],
        buffer: &mut dyn Buffer,
    ) -> Result<(), Error> {
        let pt_len = buffer.len();

        // Make room in the buffer for the tag. It needs to be prepended.
        buffer.extend_from_slice(Tag::default().as_slice())?;

        // TODO(tarcieri): add offset param to `encrypt_in_place_detached`
        buffer.as_mut().copy_within(..pt_len, TAG_SIZE);

        let tag = self.encrypt_in_place_detached(
            nonce,
            associated_data,
            &mut buffer.as_mut()[TAG_SIZE..],
        )?;
        buffer.as_mut()[..TAG_SIZE].copy_from_slice(tag.as_slice());
        Ok(())
    }

    fn encrypt_in_place_detached(
        &self,
        nonce: &Nonce,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag, Error> {
        Cipher::new(XSalsa20::new(&self.key, nonce))
            .encrypt_in_place_detached(associated_data, buffer)
    }

    fn decrypt_in_place(
        &self,
        nonce: &Nonce,
        associated_data: &[u8],
        buffer: &mut dyn Buffer,
    ) -> Result<(), Error> {
        if buffer.len() < TAG_SIZE {
            return Err(Error);
        }

        let tag = Tag::clone_from_slice(&buffer.as_ref()[..TAG_SIZE]);
        self.decrypt_in_place_detached(
            nonce,
            associated_data,
            &mut buffer.as_mut()[TAG_SIZE..],
            &tag,
        )?;

        let pt_len = buffer.len() - TAG_SIZE;

        // TODO(tarcieri): add offset param to `encrypt_in_place_detached`
        buffer.as_mut().copy_within(TAG_SIZE.., 0);
        buffer.truncate(pt_len);
        Ok(())
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &Nonce,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag,
    ) -> Result<(), Error> {
        Cipher::new(XSalsa20::new(&self.key, nonce)).decrypt_in_place_detached(
            associated_data,
            buffer,
            tag,
        )
    }
}

impl Drop for XSalsa20Poly1305 {
    fn drop(&mut self) {
        self.key.as_mut_slice().zeroize();
    }
}

/// Salsa20Poly1305 instantiated with a particular nonce
pub(crate) struct Cipher<C>
where
    C: StreamCipher + StreamCipherSeek,
{
    cipher: C,
    mac: Poly1305,
}

impl<C> Cipher<C>
where
    C: StreamCipher + StreamCipherSeek,
{
    /// Instantiate the underlying cipher with a particular nonce
    pub(crate) fn new(mut cipher: C) -> Self {
        // Derive Poly1305 key from the first 32-bytes of the Salsa20 keystream
        let mut mac_key = poly1305::Key::default();
        cipher.apply_keystream(&mut mac_key);
        let mac = Poly1305::new(GenericArray::from_slice(&mac_key));
        mac_key.zeroize();

        Self { cipher, mac }
    }

    /// Encrypt the given message in-place, returning the authentication tag
    pub(crate) fn encrypt_in_place_detached(
        mut self,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag, Error> {
        // XSalsa20Poly1305 doesn't support AAD
        if !associated_data.is_empty() {
            return Err(Error);
        }

        self.cipher.apply_keystream(buffer);
        Ok(self.mac.compute_unpadded(buffer))
    }

    /// Decrypt the given message, first authenticating ciphertext integrity
    /// and returning an error if it's been tampered with.
    pub(crate) fn decrypt_in_place_detached(
        mut self,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag,
    ) -> Result<(), Error> {
        // XSalsa20Poly1305 doesn't support AAD
        if !associated_data.is_empty() {
            return Err(Error);
        }

        use subtle::ConstantTimeEq;
        let expected_tag = self.mac.compute_unpadded(buffer);

        // This performs a constant-time comparison using the `subtle` crate
        if expected_tag.ct_eq(tag).into() {
            self.cipher.apply_keystream(buffer);
            Ok(())
        } else {
            Err(Error)
        }
    }
}
