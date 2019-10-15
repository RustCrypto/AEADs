//! Core AEAD cipher implementation for (X)ChaCha20Poly1305.

use aead::generic_array::GenericArray;
use aead::{Error, Payload};
use alloc::vec::Vec;
use chacha20::stream_cipher::{SyncStreamCipher, SyncStreamCipherSeek};
use core::convert::TryInto;
use poly1305::{universal_hash::UniversalHash, Poly1305};
use zeroize::Zeroizing;

use super::Tag;

/// ChaCha20Poly1305 instantiated with a particular nonce
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
        // Derive Poly1305 key from the first 32-bytes of the ChaCha20 keystream
        let mut mac_key = Zeroizing::new(poly1305::Key::default());
        cipher.apply_keystream(&mut *mac_key);
        let mac = Poly1305::new(GenericArray::from_slice(&*mac_key));

        // Set ChaCha20 counter to 1
        cipher.seek(chacha20::BLOCK_SIZE as u64);

        Self { cipher, mac }
    }

    /// Encrypt the given message, allocating a vector for the resulting ciphertext
    pub(crate) fn encrypt(self, payload: Payload<'_, '_>) -> Result<Vec<u8>, Error> {
        let mut buffer = Vec::with_capacity(payload.msg.len() + poly1305::BLOCK_SIZE);
        buffer.extend_from_slice(payload.msg);

        let tag = self.encrypt_in_place_detached(payload.aad, &mut buffer)?;
        buffer.extend_from_slice(tag.as_slice());
        Ok(buffer)
    }

    /// Encrypt the given message in-place, returning the authentication tag
    pub(crate) fn encrypt_in_place_detached(
        mut self,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag, Error> {
        if buffer.len() / chacha20::BLOCK_SIZE >= chacha20::MAX_BLOCKS {
            return Err(Error);
        }

        self.mac.update_padded(associated_data);
        self.cipher.apply_keystream(buffer);
        self.mac.update_padded(buffer);
        self.authenticate_lengths(associated_data, buffer)?;
        Ok(self.mac.result().into_bytes())
    }

    /// Decrypt the given message, allocating a vector for the resulting plaintext
    pub(crate) fn decrypt(self, payload: Payload<'_, '_>) -> Result<Vec<u8>, Error> {
        if payload.msg.len() < poly1305::BLOCK_SIZE {
            return Err(Error);
        }

        let tag_start = payload.msg.len() - poly1305::BLOCK_SIZE;
        let mut buffer = Vec::from(&payload.msg[..tag_start]);
        let tag = Tag::from_slice(&payload.msg[tag_start..]);
        self.decrypt_in_place_detached(payload.aad, &mut buffer, tag)?;

        Ok(buffer)
    }

    /// Decrypt the given message, first authenticating ciphertext integrity
    /// and returning an error if it's been tampered with.
    pub(crate) fn decrypt_in_place_detached(
        mut self,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag,
    ) -> Result<(), Error> {
        if buffer.len() / chacha20::BLOCK_SIZE >= chacha20::MAX_BLOCKS {
            return Err(Error);
        }

        self.mac.update_padded(associated_data);
        self.mac.update_padded(buffer);
        self.authenticate_lengths(associated_data, buffer)?;

        // This performs a constant-time comparison using the `subtle` crate
        if self.mac.verify(tag).is_ok() {
            self.cipher.apply_keystream(buffer);
            Ok(())
        } else {
            Err(Error)
        }
    }

    /// Authenticate the lengths of the associated data and message
    fn authenticate_lengths(&mut self, associated_data: &[u8], buffer: &[u8]) -> Result<(), Error> {
        let associated_data_len: u64 = associated_data.len().try_into().map_err(|_| Error)?;
        let buffer_len: u64 = buffer.len().try_into().map_err(|_| Error)?;
        self.mac.update(&associated_data_len.to_le_bytes());
        self.mac.update(&buffer_len.to_le_bytes());
        Ok(())
    }
}
