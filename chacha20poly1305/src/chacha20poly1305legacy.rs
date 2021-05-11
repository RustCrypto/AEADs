pub use chacha20::LegacyNonce;

use crate::{Key, Tag};
use aead::{
    consts::{U0, U16, U32, U8},
    AeadCore, AeadInPlace, Buffer, Error, NewAead,
};
use chacha20::ChaCha20Legacy;
use cipher::NewCipher;
use zeroize::Zeroize;

use aead::generic_array::GenericArray;
use cipher::{StreamCipher, StreamCipherSeek};
use core::convert::TryInto;
use poly1305::{
    universal_hash::{NewUniversalHash, UniversalHash},
    Poly1305,
};
use subtle::ConstantTimeEq;

#[derive(Clone)]
#[cfg_attr(docsrs, doc(cfg(feature = "legacy")))]
pub struct ChaCha20Poly1305Legacy {
    /// Secret key
    key: Key,
}

impl NewAead for ChaCha20Poly1305Legacy {
    type KeySize = U32;

    fn new(key: &Key) -> Self {
        ChaCha20Poly1305Legacy { key: *key }
    }
}

impl AeadCore for ChaCha20Poly1305Legacy {
    type NonceSize = U8;
    type TagSize = U16;
    type CiphertextOverhead = U0;
}

impl AeadInPlace for ChaCha20Poly1305Legacy {
    fn encrypt_in_place_detached(
        &self,
        nonce: &LegacyNonce,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag, Error> {
        Cipher::new(ChaCha20Legacy::new(&self.key, nonce))
            .encrypt_in_place_detached(associated_data, buffer)
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &LegacyNonce,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag,
    ) -> Result<(), Error> {
        Cipher::new(ChaCha20Legacy::new(&self.key, nonce)).decrypt_in_place_detached(
            associated_data,
            buffer,
            tag,
        )
    }
}

impl Drop for ChaCha20Poly1305Legacy {
    fn drop(&mut self) {
        self.key.as_mut_slice().zeroize();
    }
}

/// Size of a ChaCha20 block in bytes
const BLOCK_SIZE: usize = 64;

/// Maximum number of blocks that can be encrypted with ChaCha20 before the
/// counter overflows.
const MAX_BLOCKS: usize = core::u32::MAX as usize;

/// ChaCha20Poly1305 instantiated with a particular nonce
pub(crate) struct Cipher<C>
where
    C: StreamCipher + StreamCipherSeek,
{
    cipher: C,
    mac: BufferedPoly1305,
}

impl<C> Cipher<C>
where
    C: StreamCipher + StreamCipherSeek,
{
    /// Instantiate the underlying cipher with a particular nonce
    pub(crate) fn new(mut cipher: C) -> Self {
        // Derive Poly1305 key from the first 32-bytes of the ChaCha20 keystream
        let mut mac_key = poly1305::Key::default();
        cipher.apply_keystream(&mut *mac_key);
        let mac = BufferedPoly1305::new(GenericArray::from_slice(&*mac_key));
        mac_key.zeroize();

        // Set ChaCha20 counter to 1
        cipher.seek(BLOCK_SIZE as u64);

        Self { cipher, mac }
    }

    /// Encrypt the given message in-place, returning the authentication tag
    pub(crate) fn encrypt_in_place_detached(
        mut self,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag, Error> {
        if buffer.len() / BLOCK_SIZE >= MAX_BLOCKS {
            return Err(Error);
        }

        // TODO(tarcieri): interleave encryption with Poly1305
        // See: <https://github.com/RustCrypto/AEADs/issues/74>
        self.cipher.apply_keystream(buffer);

        self.mac.update_buffered(associated_data);
        self.mac
            .update_buffered(&(associated_data.len() as u64).to_le_bytes());
        self.mac.update_buffered(buffer);
        self.mac
            .update_buffered(&(buffer.len() as u64).to_le_bytes());

        Ok(self.mac.finalize().into_bytes())
    }

    /// Decrypt the given message, first authenticating ciphertext integrity
    /// and returning an error if it's been tampered with.
    pub(crate) fn decrypt_in_place_detached(
        mut self,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag,
    ) -> Result<(), Error> {
        if buffer.len() / BLOCK_SIZE >= MAX_BLOCKS {
            return Err(Error);
        }

        self.mac.update_buffered(associated_data);
        self.mac
            .update_buffered(&(associated_data.len() as u64).to_le_bytes());
        self.mac.update_buffered(buffer);
        self.mac
            .update_buffered(&(buffer.len() as u64).to_le_bytes());

        let expected_tag = self.mac.finalize().into_bytes();

        // This performs a constant-time comparison using the `subtle` crate
        if expected_tag.ct_eq(tag).unwrap_u8() == 1 {
            // TODO(tarcieri): interleave decryption with Poly1305
            // See: <https://github.com/RustCrypto/AEADs/issues/74>
            self.cipher.apply_keystream(buffer);
            Ok(())
        } else {
            Err(Error)
        }
    }
}

struct BufferedPoly1305 {
    poly1305: Poly1305,
    remainder: [u8; poly1305::BLOCK_SIZE],
    rem_size: usize,
}

impl BufferedPoly1305 {
    fn new(key: &poly1305::Key) -> Self {
        BufferedPoly1305 {
            poly1305: Poly1305::new(key),
            remainder: [0; 16],
            rem_size: 0,
        }
    }

    fn update_buffered(&mut self, data: &[u8]) {
        if data.len() + self.rem_size < self.remainder.len() {
            self.remainder[self.rem_size..self.rem_size + data.len()].copy_from_slice(data);
            self.rem_size += data.len();
        } else {
            let (head, body) = data.split_at(self.remainder.len() - self.rem_size);
            self.remainder[self.rem_size..self.rem_size + head.len()].copy_from_slice(head);
            self.poly1305.update((&self.remainder).into());

            let mut chunks = body.chunks_exact(poly1305::BLOCK_SIZE);

            for chunk in chunks.by_ref() {
                self.poly1305.update(chunk.into());
            }

            let rem = chunks.remainder();

            self.remainder[0..rem.len()].copy_from_slice(rem);
            self.rem_size = rem.len();
        }
    }

    fn finalize(self) -> poly1305::Tag {
        self.poly1305
            .compute_unpadded(&self.remainder[..self.rem_size])
    }
}
