//! ChaCha20Poly1305 Authenticated Encryption with Additional Data Algorithm
//! (RFC 8439)

#![no_std]

extern crate alloc;

pub use aead;

use aead::generic_array::typenum::{U0, U12, U16, U32};
use aead::{generic_array::GenericArray, StatelessAead, Error, NewAead};
use alloc::vec::Vec;
use chacha20::stream_cipher::{NewStreamCipher, SyncStreamCipher, SyncStreamCipherSeek};
use chacha20::ChaCha20;
use core::convert::TryInto;
use poly1305::{Poly1305, Tag};
use zeroize::{Zeroize, Zeroizing};

/// ChaCha20Poly1305 AEAD
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
        CipherInstance::new(&self.key, nonce).encrypt(associated_data, plaintext)
    }

    fn decrypt(
        &self,
        associated_data: &[u8],
        nonce: &GenericArray<u8, Self::NonceSize>,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        CipherInstance::new(&self.key, nonce).decrypt(associated_data, ciphertext)
    }
}

impl Drop for ChaCha20Poly1305 {
    fn drop(&mut self) {
        self.key.as_mut_slice().zeroize();
    }
}

/// ChaCha20Poly1305 instantiated with a particular nonce
struct CipherInstance {
    chacha20: ChaCha20,
    poly1305: Poly1305,
}

impl CipherInstance {
    /// Instantiate the underlying cipher with a particular nonce
    fn new(key: &GenericArray<u8, U32>, nonce: &GenericArray<u8, U12>) -> Self {
        let mut chacha20 = ChaCha20::new(key, nonce);

        // Derive Poly1305 key from the first 32-bytes of the ChaCha20 keystream
        let mut auth_key = Zeroizing::new([0u8; poly1305::KEY_SIZE]);
        chacha20.apply_keystream(&mut *auth_key);

        // Set ChaCha20 counter to 1
        chacha20.seek(chacha20::BLOCK_SIZE as u64);

        let poly1305 = Poly1305::new(&auth_key);
        Self { chacha20, poly1305 }
    }

    /// Encrypt the given message, allocating a vector for the resulting ciphertext
    fn encrypt(self, associated_data: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let mut buffer = Vec::with_capacity(plaintext.len() + poly1305::BLOCK_SIZE);
        buffer.extend_from_slice(plaintext);

        let tag = self.encrypt_in_place(associated_data, &mut buffer)?;
        buffer.extend_from_slice(tag.code().as_slice());
        Ok(buffer)
    }

    /// Encrypt the given message in-place, returning the authentication tag
    fn encrypt_in_place(mut self, associated_data: &[u8], buffer: &mut [u8]) -> Result<Tag, Error> {
        if buffer.len() / chacha20::BLOCK_SIZE >= chacha20::MAX_BLOCKS {
            return Err(Error);
        }

        self.poly1305.input_padded(associated_data);
        self.chacha20.apply_keystream(buffer);
        self.poly1305.input_padded(buffer);
        self.authenticate_lengths(associated_data, buffer)?;
        Ok(self.poly1305.result())
    }

    /// Decrypt the given message, allocating a vector for the resulting plaintext
    fn decrypt(self, associated_data: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        if ciphertext.len() < poly1305::BLOCK_SIZE {
            return Err(Error);
        }

        let tag_start = ciphertext.len() - poly1305::BLOCK_SIZE;
        let mut buffer = Vec::from(&ciphertext[..tag_start]);
        let tag: [u8; poly1305::BLOCK_SIZE] = ciphertext[tag_start..].try_into().unwrap();
        self.decrypt_in_place(associated_data, &mut buffer, &tag)?;

        Ok(buffer)
    }

    /// Decrypt the given message, first authenticating ciphertext integrity
    /// and returning an error if it's been tampered with.
    fn decrypt_in_place(
        mut self,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &[u8; poly1305::BLOCK_SIZE],
    ) -> Result<(), Error> {
        if buffer.len() / chacha20::BLOCK_SIZE >= chacha20::MAX_BLOCKS {
            return Err(Error);
        }

        self.poly1305.input_padded(associated_data);
        self.poly1305.input_padded(buffer);
        self.authenticate_lengths(associated_data, buffer)?;

        // This performs a constant-time comparison using the `subtle` crate
        if self.poly1305.result() == Tag::new(*GenericArray::from_slice(tag)) {
            self.chacha20.apply_keystream(buffer);
            Ok(())
        } else {
            Err(Error)
        }
    }

    /// Authenticate the lengths of the associated data and message
    fn authenticate_lengths(&mut self, associated_data: &[u8], buffer: &[u8]) -> Result<(), Error> {
        let associated_data_len: u64 = associated_data.len().try_into().map_err(|_| Error)?;
        let buffer_len: u64 = buffer.len().try_into().map_err(|_| Error)?;

        self.poly1305.input(&associated_data_len.to_le_bytes());
        self.poly1305.input(&buffer_len.to_le_bytes());
        Ok(())
    }
}
