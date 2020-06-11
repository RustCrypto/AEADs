//! XChaCha20Poly1305 is an extended nonce variant of ChaCha20Poly1305.
//!
//! See [`XChaCha20Poly1305`] documentation for usage.

pub use chacha20::XNonce;

use crate::{cipher::Cipher, Key, Tag};
use aead::{
    consts::{U0, U16, U24, U32},
    AeadInPlace, Error, NewAead,
};
use chacha20::XChaCha20;
use stream_cipher::NewStreamCipher;
use zeroize::Zeroize;

/// ChaCha20Poly1305 variant with an extended 192-bit (24-byte) nonce.
///
/// The `xchacha20poly1305` Cargo feature must be enabled in order to use this
/// (which it is by default).
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
/// and is documented in an (expired) IETF draft, which also applies the
/// proof from the XSalsa20 paper to the construction in order to demonstrate
/// that XChaCha20 is secure if ChaCha20 is secure (see Section 3.1):
///
/// <https://tools.ietf.org/html/draft-arciszewski-xchacha-03>
///
/// It is worth noting that NaCl/libsodium's default "secretbox" algorithm is
/// XSalsa20Poly1305, not XChaCha20Poly1305, and thus not compatible with
/// this library. If you are interested in that construction, please see the
/// `xsalsa20poly1305` crate:
///
/// <https://docs.rs/xsalsa20poly1305/>
///
/// # Usage
///
/// ```
/// use chacha20poly1305::{XChaCha20Poly1305, Key, XNonce};
/// use chacha20poly1305::aead::{Aead, NewAead};
///
/// let key = Key::from_slice(b"an example very very secret key."); // 32-bytes
/// let aead = XChaCha20Poly1305::new(key);
///
/// let nonce = XNonce::from_slice(b"extra long unique nonce!"); // 24-bytes; unique
/// let ciphertext = aead.encrypt(nonce, b"plaintext message".as_ref()).expect("encryption failure!");
/// let plaintext = aead.decrypt(nonce, ciphertext.as_ref()).expect("decryption failure!");
/// assert_eq!(&plaintext, b"plaintext message");
/// ```
#[derive(Clone)]
#[cfg_attr(docsrs, doc(cfg(feature = "xchacha20poly1305")))]
pub struct XChaCha20Poly1305 {
    /// Secret key
    key: Key,
}

impl NewAead for XChaCha20Poly1305 {
    type KeySize = U32;

    fn new(key: &Key) -> Self {
        XChaCha20Poly1305 { key: *key }
    }
}

impl AeadInPlace for XChaCha20Poly1305 {
    type NonceSize = U24;
    type TagSize = U16;
    type CiphertextOverhead = U0;

    fn encrypt_in_place_detached(
        &self,
        nonce: &XNonce,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag, Error> {
        Cipher::new(XChaCha20::new(&self.key, nonce))
            .encrypt_in_place_detached(associated_data, buffer)
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &XNonce,
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
