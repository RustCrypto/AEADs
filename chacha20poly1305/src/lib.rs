//! ChaCha20Poly1305 Authenticated Encryption with Additional Data Algorithm
//! (RFC 8439)

#![no_std]

extern crate alloc;

mod cipher;
#[cfg(feature = "xchacha20poly1305")]
mod xchacha20poly1305;

pub use aead;
#[cfg(feature = "xchacha20poly1305")]
pub use xchacha20poly1305::XChaCha20Poly1305;

use self::cipher::Cipher;
use aead::generic_array::{
    typenum::{U0, U12, U16, U32},
    GenericArray,
};
use aead::{Error, NewAead, StatelessAead};
use alloc::vec::Vec;
use chacha20::{stream_cipher::NewStreamCipher, ChaCha20};
use zeroize::Zeroize;

/// ChaCha20Poly1305 Authenticated Encryption with Additional Data (AEAD)
#[derive(Clone)]
pub struct ChaCha20Poly1305 {
    /// Secret key
    key: GenericArray<u8, U32>,
}

impl NewAead for ChaCha20Poly1305 {
    type KeySize = U32;

    fn new(key: GenericArray<u8, U32>) -> Self {
        ChaCha20Poly1305 { key }
    }
}

impl StatelessAead for ChaCha20Poly1305 {
    type NonceSize = U12;
    type TagSize = U16;
    type CiphertextOverhead = U0;

    fn encrypt(
        &self,
        associated_data: &[u8],
        nonce: &GenericArray<u8, Self::NonceSize>,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        Cipher::new(ChaCha20::new(&self.key, nonce)).encrypt(associated_data, plaintext)
    }

    fn decrypt(
        &self,
        associated_data: &[u8],
        nonce: &GenericArray<u8, Self::NonceSize>,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        Cipher::new(ChaCha20::new(&self.key, nonce)).decrypt(associated_data, ciphertext)
    }
}

impl Drop for ChaCha20Poly1305 {
    fn drop(&mut self) {
        self.key.as_mut_slice().zeroize();
    }
}
