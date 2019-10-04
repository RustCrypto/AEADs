//! XChaCha20Poly1305 is an extended nonce variant of ChaCha20Poly1305

use crate::{cipher::Cipher, Tag};
use aead::generic_array::{
    typenum::{U0, U16, U24, U32},
    GenericArray,
};
use aead::{Aead, Error, NewAead, Payload};
use alloc::vec::Vec;
use chacha20::{stream_cipher::NewStreamCipher, XChaCha20};
use zeroize::Zeroize;

/// XChaCha20Poly1305 is a ChaCha20Poly1305 variant with an extended
/// 192-bit (24-byte) nonce.
///
/// The construction is an adaptation of the same techniques used by
/// XSalsa20 as described in the paper "Extending the Salsa20 Nonce"
/// to the 96-bit nonce variant of ChaCha20, which derive a
/// separate subkey/nonce for each extended nonce:
///
/// <https://cr.yp.to/snuffle/xsalsa-20081128.pdf>
///
/// No authoritative specification exists for XChaCha20Poly1305, however the
/// construction has "rough consensus and running code" in the form of
/// several interoperable libraries and protocols (e.g. libsodium, WireGuard)
/// and is documented in an (expired) IETF draft:
///
/// <https://tools.ietf.org/html/draft-arciszewski-xchacha-03>
///
/// It is worth noting that libsodium's default "secretbox" algorithm is
/// XSalsa20Poly1305, not XChaCha20Poly1305, and thus not compatible with
/// this library.
///
/// The `xchacha20poly1305` Cargo feature must be enabled in order to use this
/// (which it is by default).
#[derive(Clone)]
pub struct XChaCha20Poly1305 {
    /// Secret key
    key: GenericArray<u8, U32>,
}

impl NewAead for XChaCha20Poly1305 {
    type KeySize = U32;

    fn new(key: GenericArray<u8, U32>) -> Self {
        XChaCha20Poly1305 { key }
    }
}

impl Aead for XChaCha20Poly1305 {
    type NonceSize = U24;
    type TagSize = U16;
    type CiphertextOverhead = U0;

    fn encrypt<'msg, 'aad>(
        &self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        plaintext: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>, Error> {
        Cipher::new(XChaCha20::new(&self.key, nonce)).encrypt(plaintext.into())
    }

    fn decrypt<'msg, 'aad>(
        &self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        ciphertext: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>, Error> {
        Cipher::new(XChaCha20::new(&self.key, nonce)).decrypt(ciphertext.into())
    }
}

impl XChaCha20Poly1305 {
    /// Encrypt the data in-place, returning the authentication tag
    pub fn encrypt_in_place_detached(
        &self,
        nonce: &GenericArray<u8, <Self as Aead>::NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag, Error> {
        Cipher::new(XChaCha20::new(&self.key, nonce))
            .encrypt_in_place_detached(associated_data, buffer)
    }

    /// Decrypt the data in-place, returning an error in the event the provided
    /// authentication tag does not match the given ciphertext (i.e. ciphertext
    /// is modified/unauthentic)
    pub fn decrypt_in_place_detached(
        &self,
        nonce: &GenericArray<u8, <Self as Aead>::NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag,
    ) -> Result<(), Error> {
        Cipher::new(XChaCha20::new(&self.key, nonce)).decrypt_in_place_detached(
            associated_data,
            buffer,
            tag,
        )
    }
}

impl Drop for XChaCha20Poly1305 {
    fn drop(&mut self) {
        self.key.as_mut_slice().zeroize();
    }
}
