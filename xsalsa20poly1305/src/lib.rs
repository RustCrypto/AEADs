//! **XSalsa20Poly1305** (a.k.a. NaCl `crypto_secretbox`[1]) is an
//! [authenticated encryption][2] cipher amenable to fast, constant-time
//! implementations in software, based on the [Salsa20][3] stream cipher
//! (with [XSalsa20][4] 192-bit nonce extension) and the [Poly1305][5] universal
//! hash function, which acts as a message authentication code.
//!
//! This algorithm has largely been replaced by the newer [ChaCha20Poly1305][6]
//! (and the associated [XChaCha20Poly1305][7]) AEAD ciphers ([RFC 8439][8]),
//! but is useful for interoperability with legacy NaCl-based protocols.
//!
//! ## Security Warning
//!
//! No security audits of this crate have ever been performed, and it has not been
//! thoroughly assessed to ensure its operation is constant-time on common CPU
//! architectures.
//!
//! Where possible the implementation uses constant-time hardware intrinsics,
//! or otherwise falls back to an implementation which contains no secret-dependent
//! branches or table lookups, however it's possible LLVM may insert such
//! operations in certain scenarios.
//!
//! # Usage
//!
//! ```
//! use xsalsa20poly1305::XSalsa20Poly1305;
//! use aead::{Aead, NewAead, generic_array::GenericArray};
//!
//! let key = GenericArray::clone_from_slice(b"an example very very secret key.");
//! let aead = XSalsa20Poly1305::new(key);
//!
//! let nonce = GenericArray::from_slice(b"extra long unique nonce!"); // 24-bytes; unique
//! let ciphertext = aead.encrypt(nonce, b"plaintext message".as_ref()).expect("encryption failure!");
//! let plaintext = aead.decrypt(nonce, ciphertext.as_ref()).expect("decryption failure!");
//! assert_eq!(&plaintext, b"plaintext message");
//! ```
//!
//! ## In-place Usage (eliminates `alloc` requirement)
//!
//! This crate has an optional `alloc` feature which can be disabled in e.g.
//! microcontroller environments that don't have a heap.
//!
//! The [`Aead::encrypt_in_place`][3] and [`Aead::decrypt_in_place`][4]
//! methods accept any type that impls the [`aead::Buffer`][5] trait which
//! contains the plaintext for encryption or ciphertext for decryption.
//!
//! Note that if you enable the `heapless` feature of this crate,
//! you will receive an impl of `aead::Buffer` for [`heapless::Vec`][8]
//! (re-exported from the `aead` crate as `aead::heapless::Vec`),
//! which can then be passed as the `buffer` parameter to the in-place encrypt
//! and decrypt methods:
//!
//! ```
//! use xsalsa20poly1305::XSalsa20Poly1305;
//! use aead::{Aead, NewAead};
//! use aead::generic_array::{GenericArray, typenum::U128};
//! use aead::heapless::Vec;
//!
//! let key = GenericArray::clone_from_slice(b"an example very very secret key.");
//! let aead = XSalsa20Poly1305::new(key);
//!
//! let nonce = GenericArray::from_slice(b"extra long unique nonce!"); // 24-bytes; unique
//!
//! let mut buffer: Vec<u8, U128> = Vec::new();
//! buffer.extend_from_slice(b"plaintext message");
//!
//! // Encrypt `buffer` in-place, replacing the plaintext contents with ciphertext
//! aead.encrypt_in_place(nonce, b"", &mut buffer).expect("encryption failure!");
//!
//! // `buffer` now contains the message ciphertext
//! assert_ne!(&buffer, b"plaintext message");
//!
//! // Decrypt `buffer` in-place, replacing its ciphertext context with the original plaintext
//! aead.decrypt_in_place(nonce, b"", &mut buffer).expect("decryption failure!");
//! assert_eq!(&buffer, b"plaintext message");
//! ```
//!
//! [1]: https://nacl.cr.yp.to/secretbox.html
//! [2]: https://en.wikipedia.org/wiki/Authenticated_encryption
//! [3]: https://github.com/RustCrypto/stream-ciphers/tree/master/salsa20
//! [4]: https://cr.yp.to/snuffle/xsalsa-20081128.pdf
//! [5]: https://github.com/RustCrypto/universal-hashes/tree/master/poly1305
//! [6]: https://github.com/RustCrypto/AEADs/tree/master/chacha20poly1305
//! [7]: https://docs.rs/chacha20poly1305/latest/chacha20poly1305/struct.XChaCha20Poly1305.html
//! [8]: https://tools.ietf.org/html/rfc8439

#![no_std]
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
#![warn(missing_docs, rust_2018_idioms)]

pub use aead;

use aead::generic_array::{
    typenum::{Unsigned, U0, U16, U24, U32},
    GenericArray,
};
use aead::{Aead, Buffer, Error, NewAead};
use poly1305::{universal_hash::UniversalHash, Poly1305};
use salsa20::stream_cipher::{NewStreamCipher, SyncStreamCipher, SyncStreamCipherSeek};
use salsa20::XSalsa20;
use zeroize::{Zeroize, Zeroizing};

/// Poly1305 tags
pub type Tag = GenericArray<u8, U16>;

/// **XSalsa20Poly1305** (a.k.a. NaCl `crypto_secretbox`) authenticated
/// encryption cipher.
#[derive(Clone)]
pub struct XSalsa20Poly1305 {
    /// Secret key
    key: GenericArray<u8, U32>,
}

impl NewAead for XSalsa20Poly1305 {
    type KeySize = U32;

    fn new(key: GenericArray<u8, U32>) -> Self {
        XSalsa20Poly1305 { key }
    }
}

impl Aead for XSalsa20Poly1305 {
    type NonceSize = U24;
    type TagSize = U16;
    type CiphertextOverhead = U0;

    fn encrypt_in_place(
        &self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        associated_data: &[u8],
        buffer: &mut impl Buffer,
    ) -> Result<(), Error> {
        let pt_len = buffer.len();
        let tag_len = Self::TagSize::to_usize();

        // Make room in the buffer for the tag. It needs to be prepended.
        buffer.extend_from_slice(Tag::default().as_slice())?;

        // TODO(tarcieri): add offset param to `encrypt_in_place_detached`
        buffer.as_mut().copy_within(..pt_len, tag_len);

        let tag = self.encrypt_in_place_detached(
            nonce,
            associated_data,
            &mut buffer.as_mut()[tag_len..],
        )?;
        buffer.as_mut()[..tag_len].copy_from_slice(tag.as_slice());
        Ok(())
    }

    fn encrypt_in_place_detached(
        &self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag, Error> {
        Cipher::new(XSalsa20::new(&self.key, nonce))
            .encrypt_in_place_detached(associated_data, buffer)
    }

    fn decrypt_in_place(
        &self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        associated_data: &[u8],
        buffer: &mut impl Buffer,
    ) -> Result<(), Error> {
        let tag_len = Self::TagSize::to_usize();

        if buffer.len() < tag_len {
            return Err(Error);
        }

        let tag = Tag::clone_from_slice(&buffer.as_ref()[..tag_len]);
        self.decrypt_in_place_detached(
            nonce,
            associated_data,
            &mut buffer.as_mut()[tag_len..],
            &tag,
        )?;

        let pt_len = buffer.len() - tag_len;

        // TODO(tarcieri): add offset param to `encrypt_in_place_detached`
        buffer.as_mut().copy_within(tag_len.., 0);
        buffer.truncate(pt_len);
        Ok(())
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &GenericArray<u8, Self::NonceSize>,
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
    C: SyncStreamCipher + SyncStreamCipherSeek,
{
    cipher: C,
    mac: Poly1305,
}

impl<C> Cipher<C>
where
    C: SyncStreamCipher + SyncStreamCipherSeek,
{
    /// Instantiate the underlying cipher with a particular nonce
    pub(crate) fn new(mut cipher: C) -> Self {
        // Derive Poly1305 key from the first 32-bytes of the Salsa20 keystream
        let mut mac_key = Zeroizing::new(poly1305::Key::default());
        cipher.apply_keystream(&mut *mac_key);

        let mac = Poly1305::new(GenericArray::from_slice(&*mac_key));
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
        self.mac.update(buffer);
        Ok(self.mac.result().into_bytes())
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

        self.mac.update(buffer);

        // This performs a constant-time comparison using the `subtle` crate
        if self.mac.verify(tag).is_ok() {
            self.cipher.apply_keystream(buffer);
            Ok(())
        } else {
            Err(Error)
        }
    }
}
