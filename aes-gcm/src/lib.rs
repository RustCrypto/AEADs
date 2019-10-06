//! AES-GCM: [Authenticated Encryption and Associated Data (AEAD)][1] cipher
//! based on AES in [Galois/Counter Mode][2].
//!
//! ## Performance Notes
//!
//! By default this crate will use software implementations of both AES and
//! the POLYVAL universal hash function.
//!
//! When targeting modern x86/x86_64 CPUs, use the following `RUSTFLAGS` to
//! take advantage of high performance AES-NI and CLMUL CPU intrinsics:
//!
//! ```text
//! RUSTFLAGS="-Ctarget-cpu=sandybridge -Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3"
//! ```
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
//! use aes_gcm::Aes256Gcm; // Or `Aes128Gcm`
//! use aead::{Aead, NewAead, generic_array::GenericArray};
//!
//! let key = GenericArray::clone_from_slice(b"an example very very secret key.");
//! let aead = Aes256Gcm::new(key);
//!
//! let nonce = GenericArray::from_slice(b"unique nonce"); // 96-bits; unique per message
//! let ciphertext = aead.encrypt(nonce, b"plaintext message".as_ref()).expect("encryption failure!");
//! let plaintext = aead.decrypt(nonce, ciphertext.as_ref()).expect("decryption failure!");
//! assert_eq!(&plaintext, b"plaintext message");
//! ```
//!
//! [1]: https://en.wikipedia.org/wiki/Authenticated_encryption
//! [2]: https://en.wikipedia.org/wiki/Galois/Counter_Mode

#![no_std]
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
#![warn(missing_docs, rust_2018_idioms)]

extern crate alloc;

mod ctr32;

pub use aead;

use self::ctr32::Ctr32;
use aead::generic_array::{
    typenum::{Unsigned, U0, U12, U16, U8},
    GenericArray,
};
use aead::{Aead, Error, NewAead, Payload};
use aes::{block_cipher_trait::BlockCipher, Aes128, Aes256};
use alloc::vec::Vec;
use ghash::{universal_hash::UniversalHash, GHash};
use zeroize::Zeroize;

/// Maximum length of associated data
pub const A_MAX: u64 = 1 << 36;

/// Maximum length of plaintext
pub const P_MAX: u64 = 1 << 36;

/// Maximum length of ciphertext
pub const C_MAX: u64 = (1 << 36) + 16;

/// AES-GCM tags
pub type Tag = GenericArray<u8, U16>;

/// AES-GCM with a 128-bit key
pub type Aes128Gcm = AesGcm<Aes128>;

/// AES-GCM with a 256-bit key
pub type Aes256Gcm = AesGcm<Aes256>;

/// AES-GCM
#[derive(Clone)]
pub struct AesGcm<C: BlockCipher<BlockSize = U16, ParBlocks = U8>> {
    /// Encryption cipher
    cipher: C,

    /// GHASH authenticator
    ghash: GHash,
}

impl<C> NewAead for AesGcm<C>
where
    C: BlockCipher<BlockSize = U16, ParBlocks = U8>,
{
    type KeySize = C::KeySize;

    fn new(mut key: GenericArray<u8, C::KeySize>) -> Self {
        let cipher = C::new(&key);
        key.as_mut_slice().zeroize();

        let mut ghash_key = GenericArray::default();
        cipher.encrypt_block(&mut ghash_key);

        let ghash = GHash::new(&ghash_key);
        ghash_key.zeroize();

        Self { cipher, ghash }
    }
}

impl<C> Aead for AesGcm<C>
where
    C: BlockCipher<BlockSize = U16, ParBlocks = U8>,
{
    type NonceSize = U12;
    type TagSize = U16;
    type CiphertextOverhead = U0;

    fn encrypt<'msg, 'aad>(
        &self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        plaintext: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>, Error> {
        let payload = plaintext.into();
        let mut buffer = Vec::with_capacity(payload.msg.len() + Self::TagSize::to_usize());
        buffer.extend_from_slice(payload.msg);

        let tag = self.encrypt_in_place_detached(nonce, payload.aad, &mut buffer)?;
        buffer.extend_from_slice(tag.as_slice());
        Ok(buffer)
    }

    fn decrypt<'msg, 'aad>(
        &self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        ciphertext: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>, Error> {
        let payload = ciphertext.into();

        if payload.msg.len() < Self::TagSize::to_usize() {
            return Err(Error);
        }

        let tag_start = payload.msg.len() - Self::TagSize::to_usize();
        let mut buffer = Vec::from(&payload.msg[..tag_start]);
        let tag = Tag::from_slice(&payload.msg[tag_start..]);
        self.decrypt_in_place_detached(nonce, payload.aad, &mut buffer, tag)?;

        Ok(buffer)
    }
}

impl<C> AesGcm<C>
where
    C: BlockCipher<BlockSize = U16, ParBlocks = U8>,
{
    /// Encrypt the given message in-place, returning the authentication tag
    pub fn encrypt_in_place_detached(
        &self,
        nonce: &GenericArray<u8, <Self as Aead>::NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag, Error> {
        if buffer.len() as u64 > P_MAX || associated_data.len() as u64 > A_MAX {
            return Err(Error);
        }

        // TODO(tarcieri): interleave encryption with GHASH
        let mut ctr = Ctr32::new(&self.cipher, nonce);
        ctr.seek(1);
        ctr.apply_keystream(buffer);

        let mut tag = compute_tag(&mut self.ghash.clone(), associated_data, buffer);
        ctr.seek(0);
        ctr.apply_keystream(tag.as_mut_slice());

        Ok(tag)
    }

    /// Decrypt the given message, first authenticating ciphertext integrity
    /// and returning an error if it's been tampered with.
    pub fn decrypt_in_place_detached(
        &self,
        nonce: &GenericArray<u8, <Self as Aead>::NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag,
    ) -> Result<(), Error> {
        if buffer.len() as u64 > C_MAX || associated_data.len() as u64 > A_MAX {
            return Err(Error);
        }

        // TODO(tarcieri): interleave decryption with GHASH
        let mut expected_tag = compute_tag(&mut self.ghash.clone(), associated_data, buffer);
        let mut ctr = Ctr32::new(&self.cipher, nonce);
        ctr.apply_keystream(expected_tag.as_mut_slice());

        use subtle::ConstantTimeEq;
        if expected_tag.ct_eq(&tag).unwrap_u8() == 1 {
            ctr.apply_keystream(buffer);
            Ok(())
        } else {
            Err(Error)
        }
    }
}

/// Authenticate the given plaintext and associated data using GHASH
fn compute_tag(ghash: &mut GHash, associated_data: &[u8], buffer: &[u8]) -> Tag {
    ghash.update_padded(associated_data);
    ghash.update_padded(buffer);

    let associated_data_bits = (associated_data.len() as u64) * 8;
    let buffer_bits = (buffer.len() as u64) * 8;

    let mut block = GenericArray::default();
    block[..8].copy_from_slice(&associated_data_bits.to_be_bytes());
    block[8..].copy_from_slice(&buffer_bits.to_be_bytes());
    ghash.update_block(&block);

    ghash.result_reset().into_bytes()
}
