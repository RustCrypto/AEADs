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
//! [1]: https://nacl.cr.yp.to/secretbox.html
//! [2]: https://en.wikipedia.org/wiki/Authenticated_encryption
//! [3]: https://github.com/RustCrypto/stream-ciphers/tree/master/salsa20
//! [4]: https://cr.yp.to/snuffle/xsalsa-20081128.pdf
//! [5]: https://github.com/RustCrypto/universal-hashes/tree/master/poly1305
//! [6]: https://github.com/RustCrypto/AEADs/tree/master/chacha20poly1305
//! [7]: https://docs.rs/chacha20poly1305/latest/chacha20poly1305/struct.XChaCha20Poly1305.html
//! [8]: https://tools.ietf.org/html/rfc8439

#![no_std]

extern crate alloc;

pub use aead;

use aead::generic_array::{
    typenum::{U0, U16, U24, U32},
    GenericArray,
};
use aead::{Aead, Error, NewAead, Payload};
use alloc::vec::Vec;
use core::convert::TryInto;
use poly1305::{universal_hash::UniversalHash, Poly1305, Tag};
use salsa20::stream_cipher::{NewStreamCipher, SyncStreamCipher, SyncStreamCipherSeek};
use salsa20::XSalsa20;
use zeroize::{Zeroize, Zeroizing};

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

    fn encrypt<'msg, 'aad>(
        &self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        plaintext: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>, Error> {
        Cipher::new(XSalsa20::new(&self.key, nonce)).encrypt(plaintext.into())
    }

    fn decrypt<'msg, 'aad>(
        &self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        ciphertext: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>, Error> {
        Cipher::new(XSalsa20::new(&self.key, nonce)).decrypt(ciphertext.into())
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

    /// Encrypt the given message, allocating a vector for the resulting ciphertext
    pub(crate) fn encrypt(self, payload: Payload) -> Result<Vec<u8>, Error> {
        let mut buffer = Vec::with_capacity(payload.msg.len() + poly1305::BLOCK_SIZE);
        buffer.extend_from_slice(&[0u8; poly1305::BLOCK_SIZE]);
        buffer.extend_from_slice(payload.msg);

        let tag = self.encrypt_in_place(&mut buffer[poly1305::BLOCK_SIZE..], payload.aad)?;
        buffer[..poly1305::BLOCK_SIZE].copy_from_slice(tag.into_bytes().as_slice());
        Ok(buffer)
    }

    /// Encrypt the given message in-place, returning the authentication tag
    pub(crate) fn encrypt_in_place(
        mut self,
        buffer: &mut [u8],
        associated_data: &[u8],
    ) -> Result<Tag, Error> {
        // XSalsa20Poly1305 doesn't support AAD
        if !associated_data.is_empty() {
            return Err(Error);
        }

        self.cipher.apply_keystream(buffer);
        self.mac.update(buffer);
        Ok(self.mac.result())
    }

    /// Decrypt the given message, allocating a vector for the resulting plaintext
    pub(crate) fn decrypt(self, payload: Payload) -> Result<Vec<u8>, Error> {
        if payload.msg.len() < poly1305::BLOCK_SIZE {
            return Err(Error);
        }

        let mut buffer = Vec::from(&payload.msg[poly1305::BLOCK_SIZE..]);
        let tag: [u8; poly1305::BLOCK_SIZE] =
            payload.msg[..poly1305::BLOCK_SIZE].try_into().unwrap();
        self.decrypt_in_place(&mut buffer, payload.aad, &tag)?;

        Ok(buffer)
    }

    /// Decrypt the given message, first authenticating ciphertext integrity
    /// and returning an error if it's been tampered with.
    pub(crate) fn decrypt_in_place(
        mut self,
        buffer: &mut [u8],
        associated_data: &[u8],
        tag: &[u8; poly1305::BLOCK_SIZE],
    ) -> Result<(), Error> {
        // XSalsa20Poly1305 doesn't support AAD
        if !associated_data.is_empty() {
            return Err(Error);
        }

        self.mac.update(buffer);

        // This performs a constant-time comparison using the `subtle` crate
        if self.mac.verify(GenericArray::from_slice(tag)).is_ok() {
            self.cipher.apply_keystream(buffer);
            Ok(())
        } else {
            Err(Error)
        }
    }
}
