//! ChaCha20Poly1305 Authenticated Encryption with Additional Data Algorithm
//! (RFC 8439)

#![no_std]

extern crate alloc;

pub use aead;
// TODO(tarcieri): re-export this from the AEAD crate
pub use generic_array;

use aead::{Aead, Error, NewAead};
use alloc::vec::Vec;
use chacha20::stream_cipher::{NewStreamCipher, SyncStreamCipher, SyncStreamCipherSeek};
use chacha20::ChaCha20;
use core::convert::TryInto;
use generic_array::{
    typenum::{U0, U12, U16, U32},
    GenericArray,
};
use poly1305::Poly1305;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

/// Maximum number of blocks that can be encrypted with ChaCha20 before the
/// counter overflows.
// TODO(tarcieri): move this to the `chacha20` crate?
const CHACHA20_MAX_BLOCKS: usize = (1 << 32) - 1;

/// Size of a ChaCha20 block in bytes
// TODO(tarcieri): move this to the `chacha20` crate?
const CHACHA20_BLOCK_SIZE: usize = 64;

/// Maximum length of a ChaCha20 ciphertext
// TODO(tarcieri): move this to the `chacha20` crate?
const CHACHA20_MAX_MSG_SIZE: usize = CHACHA20_MAX_BLOCKS * CHACHA20_BLOCK_SIZE;

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

impl Aead for ChaCha20Poly1305 {
    type NonceSize = U12;
    type TagSize = U16;
    type CiphertextOverhead = U0;

    fn encrypt(
        &mut self,
        associated_data: &[u8],
        nonce: &GenericArray<u8, Self::NonceSize>,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        CipherInstance::new(&self.key, nonce).encrypt(associated_data, plaintext)
    }

    fn decrypt(
        &mut self,
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
        chacha20.seek(CHACHA20_BLOCK_SIZE as u64);

        let poly1305 = Poly1305::new(&auth_key);
        Self { chacha20, poly1305 }
    }

    /// Encrypt the given message, allocating a vector for the resulting ciphertext
    fn encrypt(self, associated_data: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let mut buffer = Vec::with_capacity(plaintext.len() + poly1305::BLOCK_SIZE);
        buffer.extend_from_slice(plaintext);

        let tag = self.encrypt_in_place(associated_data, &mut buffer)?;
        buffer.extend_from_slice(&tag);
        Ok(buffer)
    }

    /// Encrypt the given message in-place, returning the authentication tag
    fn encrypt_in_place(
        mut self,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<[u8; poly1305::BLOCK_SIZE], Error> {
        if buffer.len() > CHACHA20_MAX_MSG_SIZE {
            return Err(Error);
        }

        self.padded_auth(associated_data);
        self.chacha20.apply_keystream(buffer);
        self.padded_auth(buffer);
        self.auth_lengths(associated_data, buffer)?;
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
        if buffer.len() > CHACHA20_MAX_MSG_SIZE {
            return Err(Error);
        }

        self.padded_auth(associated_data);
        self.padded_auth(buffer);
        self.auth_lengths(associated_data, buffer)?;

        let mut cipher = self.verify_tag(tag)?;
        cipher.apply_keystream(buffer);
        Ok(())
    }

    /// Input data into Poly1305 padded to its block size
    // TODO(tarcieri): factor this upstream into the `poly1305` crate
    fn padded_auth(&mut self, msg: &[u8]) {
        self.poly1305.input(msg);

        // Pad associated data with `\0` if it's unaligned with the block size
        let unaligned_len = msg.len() % poly1305::BLOCK_SIZE;

        if unaligned_len != 0 {
            let pad = [0u8; poly1305::BLOCK_SIZE];
            let pad_len = poly1305::BLOCK_SIZE - unaligned_len;
            self.poly1305.input(&pad[..pad_len]);
        }
    }

    /// Authenticate the lengths of the associated data and message
    fn auth_lengths(&mut self, associated_data: &[u8], buffer: &[u8]) -> Result<(), Error> {
        let associated_data_len: u64 = associated_data.len().try_into().map_err(|_| Error)?;
        let buffer_len: u64 = buffer.len().try_into().map_err(|_| Error)?;

        self.poly1305.input(&associated_data_len.to_le_bytes());
        self.poly1305.input(&buffer_len.to_le_bytes());
        Ok(())
    }

    /// Verify the Poly1305 tag is authentic
    // TODO(tarcieri): factor this upstream into the `poly1305` crate
    fn verify_tag(self, expected_tag: &[u8; poly1305::BLOCK_SIZE]) -> Result<ChaCha20, Error> {
        let actual_tag = self.poly1305.result();
        if expected_tag.ct_eq(&actual_tag[..]).unwrap_u8() == 1 {
            Ok(self.chacha20)
        } else {
            Err(Error)
        }
    }
}
