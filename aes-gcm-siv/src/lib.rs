#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![warn(missing_docs, rust_2018_idioms)]

//! # Usage
//!
//! Simple usage (allocating, no associated data):
//!
#![cfg_attr(all(feature = "getrandom", feature = "std"), doc = "```")]
#![cfg_attr(not(all(feature = "getrandom", feature = "std")), doc = "```ignore")]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use aes_gcm_siv::{
//!     aead::{Aead, KeyInit, OsRng},
//!     Aes256GcmSiv, Nonce // Or `Aes128GcmSiv`
//! };
//!
//! let key = Aes256GcmSiv::generate_key(&mut OsRng);
//! let cipher = Aes256GcmSiv::new(&key);
//! let nonce = Nonce::from_slice(b"unique nonce"); // 96-bits; unique per message
//! let ciphertext = cipher.encrypt(nonce, b"plaintext message".as_ref())?;
//! let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())?;
//! assert_eq!(&plaintext, b"plaintext message");
//! # Ok(())
//! # }
//! ```
//!
//! ## In-place Usage (eliminates `alloc` requirement)
//!
//! This crate has an optional `alloc` feature which can be disabled in e.g.
//! microcontroller environments that don't have a heap.
//!
//! The [`AeadInPlace::encrypt_in_place`] and [`AeadInPlace::decrypt_in_place`]
//! methods accept any type that impls the [`aead::Buffer`] trait which
//! contains the plaintext for encryption or ciphertext for decryption.
//!
//! Note that if you enable the `heapless` feature of this crate,
//! you will receive an impl of [`aead::Buffer`] for `heapless::Vec`
//! (re-exported from the [`aead`] crate as [`aead::heapless::Vec`]),
//! which can then be passed as the `buffer` parameter to the in-place encrypt
//! and decrypt methods:
//!
#![cfg_attr(
    all(feature = "getrandom", feature = "heapless", feature = "std"),
    doc = "```"
)]
#![cfg_attr(
    not(all(feature = "getrandom", feature = "heapless", feature = "std")),
    doc = "```ignore"
)]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use aes_gcm_siv::{
//!     aead::{AeadInPlace, KeyInit, OsRng, heapless::Vec},
//!     Aes256GcmSiv, Nonce, // Or `Aes128GcmSiv`
//! };
//!
//! let key = Aes256GcmSiv::generate_key(&mut OsRng);
//! let cipher = Aes256GcmSiv::new(&key);
//! let nonce = Nonce::from_slice(b"unique nonce"); // 96-bits; unique per message
//!
//! let mut buffer: Vec<u8, 128> = Vec::new(); // Note: buffer needs 16-bytes overhead for auth tag tag
//! buffer.extend_from_slice(b"plaintext message");
//!
//! // Encrypt `buffer` in-place, replacing the plaintext contents with ciphertext
//! cipher.encrypt_in_place(nonce, b"", &mut buffer)?;
//!
//! // `buffer` now contains the message ciphertext
//! assert_ne!(&buffer, b"plaintext message");
//!
//! // Decrypt `buffer` in-place, replacing its ciphertext context with the original plaintext
//! cipher.decrypt_in_place(nonce, b"", &mut buffer)?;
//! assert_eq!(&buffer, b"plaintext message");
//! # Ok(())
//! # }
//! ```

pub use aead::{self, AeadCore, AeadInPlace, Error, Key, KeyInit, KeySizeUser};

use cipher::{
    consts::{U0, U12, U16},
    generic_array::GenericArray,
    BlockCipher, BlockEncrypt, InnerIvInit, StreamCipherCore,
};
use polyval::{universal_hash::UniversalHash, Polyval};
use zeroize::Zeroize;

/// AES is optional to allow swapping in hardware-specific backends.
#[cfg(feature = "aes")]
use aes::{Aes128, Aes256};

/// Maximum length of associated data (from RFC8452 § 6).
pub const A_MAX: u64 = 1 << 36;

/// Maximum length of plaintext (from RFC8452 § 6).
pub const P_MAX: u64 = 1 << 36;

/// Maximum length of ciphertext (from RFC8452 § 6).
pub const C_MAX: u64 = (1 << 36) + 16;

/// AES-GCM-SIV nonces.
pub type Nonce = GenericArray<u8, U12>;

/// AES-GCM-SIV tags.
pub type Tag = GenericArray<u8, U16>;

/// AES-GCM-SIV with a 128-bit key.
#[cfg(feature = "aes")]
pub type Aes128GcmSiv = AesGcmSiv<Aes128>;

/// AES-GCM-SIV with a 256-bit key.
#[cfg(feature = "aes")]
pub type Aes256GcmSiv = AesGcmSiv<Aes256>;

/// Counter mode with a 32-bit little endian counter.
type Ctr32LE<Aes> = ctr::CtrCore<Aes, ctr::flavors::Ctr32LE>;

/// AES-GCM-SIV: Misuse-Resistant Authenticated Encryption Cipher (RFC 8452).
#[derive(Clone)]
pub struct AesGcmSiv<Aes> {
    /// Key generating key used to derive AES-GCM-SIV subkeys.
    key_generating_key: Aes,
}

impl<Aes> KeySizeUser for AesGcmSiv<Aes>
where
    Aes: KeySizeUser,
{
    type KeySize = Aes::KeySize;
}

impl<Aes> KeyInit for AesGcmSiv<Aes>
where
    Aes: BlockCipher<BlockSize = U16> + BlockEncrypt + KeyInit,
{
    fn new(key_bytes: &Key<Self>) -> Self {
        Self {
            key_generating_key: Aes::new(key_bytes),
        }
    }
}

impl<Aes> From<Aes> for AesGcmSiv<Aes>
where
    Aes: BlockCipher<BlockSize = U16> + BlockEncrypt,
{
    fn from(key_generating_key: Aes) -> Self {
        Self { key_generating_key }
    }
}

impl<Aes> AeadCore for AesGcmSiv<Aes>
where
    Aes: BlockCipher<BlockSize = U16> + BlockEncrypt + KeyInit,
{
    type NonceSize = U12;
    type TagSize = U16;
    type CiphertextOverhead = U0;
}

impl<Aes> AeadInPlace for AesGcmSiv<Aes>
where
    Aes: BlockCipher<BlockSize = U16> + BlockEncrypt + KeyInit,
{
    fn encrypt_in_place_detached(
        &self,
        nonce: &Nonce,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag, Error> {
        Cipher::<Aes>::new(&self.key_generating_key, nonce)
            .encrypt_in_place_detached(associated_data, buffer)
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &Nonce,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag,
    ) -> Result<(), Error> {
        Cipher::<Aes>::new(&self.key_generating_key, nonce).decrypt_in_place_detached(
            associated_data,
            buffer,
            tag,
        )
    }
}

/// AES-GCM-SIV: Misuse-Resistant Authenticated Encryption Cipher (RFC8452).
struct Cipher<Aes>
where
    Aes: BlockCipher<BlockSize = U16> + BlockEncrypt,
{
    /// Encryption cipher.
    enc_cipher: Aes,

    /// POLYVAL universal hash.
    polyval: Polyval,

    /// Nonce.
    nonce: Nonce,
}

impl<Aes> Cipher<Aes>
where
    Aes: BlockCipher<BlockSize = U16> + BlockEncrypt + KeyInit,
{
    /// Initialize AES-GCM-SIV, deriving per-nonce message-authentication and
    /// message-encryption keys.
    pub(crate) fn new(key_generating_key: &Aes, nonce: &Nonce) -> Self {
        let mut mac_key = polyval::Key::default();
        let mut enc_key = GenericArray::default();
        let mut block = cipher::Block::<Aes>::default();
        let mut counter = 0u32;

        // Derive subkeys from the master key-generating-key in counter mode.
        //
        // From RFC8452 § 4: <https://tools.ietf.org/html/rfc8452#section-4>
        //
        // > The message-authentication key is 128 bit, and the message-encryption
        // > key is either 128 (for AES-128) or 256 bit (for AES-256).
        // >
        // > These keys are generated by encrypting a series of plaintext blocks
        // > that contain a 32-bit, little-endian counter followed by the nonce,
        // > and then discarding the second half of the resulting ciphertext.  In
        // > the AES-128 case, 128 + 128 = 256 bits of key material need to be
        // > generated, and, since encrypting each block yields 64 bits after
        // > discarding half, four blocks need to be encrypted.  The counter
        // > values for these blocks are 0, 1, 2, and 3.  For AES-256, six blocks
        // > are needed in total, with counter values 0 through 5 (inclusive).
        for derived_key in &mut [mac_key.as_mut_slice(), enc_key.as_mut_slice()] {
            for chunk in derived_key.chunks_mut(8) {
                block[..4].copy_from_slice(&counter.to_le_bytes());
                block[4..].copy_from_slice(nonce.as_slice());

                key_generating_key.encrypt_block(&mut block);
                chunk.copy_from_slice(&block.as_slice()[..8]);

                counter += 1;
            }
        }

        let result = Self {
            enc_cipher: Aes::new(&enc_key),
            polyval: Polyval::new(&mac_key),
            nonce: *nonce,
        };

        // Zeroize all intermediate buffers
        // TODO(tarcieri): use `Zeroizing` when const generics land
        mac_key.as_mut_slice().zeroize();
        enc_key.as_mut_slice().zeroize();
        block.as_mut_slice().zeroize();

        result
    }

    /// Encrypt the given message in-place, returning the authentication tag.
    pub(crate) fn encrypt_in_place_detached(
        mut self,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag, Error> {
        if buffer.len() as u64 > P_MAX || associated_data.len() as u64 > A_MAX {
            return Err(Error);
        }

        self.polyval.update_padded(associated_data);
        self.polyval.update_padded(buffer);

        let tag = self.finish_tag(associated_data.len(), buffer.len());
        init_ctr(&self.enc_cipher, &tag).apply_keystream_partial(buffer.into());

        Ok(tag)
    }

    /// Decrypt the given message, first authenticating ciphertext integrity
    /// and returning an error if it's been tampered with.
    pub(crate) fn decrypt_in_place_detached(
        mut self,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag,
    ) -> Result<(), Error> {
        if buffer.len() as u64 > C_MAX || associated_data.len() as u64 > A_MAX {
            return Err(Error);
        }

        self.polyval.update_padded(associated_data);

        // TODO(tarcieri): interleave decryption and authentication
        init_ctr(&self.enc_cipher, tag).apply_keystream_partial(buffer.into());
        self.polyval.update_padded(buffer);

        let expected_tag = self.finish_tag(associated_data.len(), buffer.len());

        use subtle::ConstantTimeEq;
        if expected_tag.ct_eq(tag).into() {
            Ok(())
        } else {
            // On MAC verify failure, re-encrypt the plaintext buffer to
            // prevent accidental exposure.
            init_ctr(&self.enc_cipher, tag).apply_keystream_partial(buffer.into());
            Err(Error)
        }
    }

    /// Finish computing POLYVAL tag for AAD and buffer of the given length.
    fn finish_tag(&mut self, associated_data_len: usize, buffer_len: usize) -> Tag {
        let associated_data_bits = (associated_data_len as u64) * 8;
        let buffer_bits = (buffer_len as u64) * 8;

        let mut block = polyval::Block::default();
        block[..8].copy_from_slice(&associated_data_bits.to_le_bytes());
        block[8..].copy_from_slice(&buffer_bits.to_le_bytes());
        self.polyval.update(&[block]);

        let mut tag = self.polyval.finalize_reset();

        // XOR the nonce into the resulting tag
        for (i, byte) in tag[..12].iter_mut().enumerate() {
            *byte ^= self.nonce[i];
        }

        // Clear the highest bit
        tag[15] &= 0x7f;

        self.enc_cipher.encrypt_block(&mut tag);
        tag
    }
}

/// Initialize counter mode.
///
/// From RFC8452 § 4: <https://tools.ietf.org/html/rfc8452#section-4>
///
/// > The initial counter block is the tag with the most significant bit
/// > of the last byte set to one.
#[inline]
fn init_ctr<Aes>(cipher: Aes, nonce: &cipher::Block<Aes>) -> Ctr32LE<Aes>
where
    Aes: BlockCipher<BlockSize = U16> + BlockEncrypt,
{
    let mut counter_block = *nonce;
    counter_block[15] |= 0x80;
    Ctr32LE::inner_iv_init(cipher, &counter_block)
}
