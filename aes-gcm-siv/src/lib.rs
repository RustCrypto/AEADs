//! [AES-GCM-SIV][1] ([RFC 8452][2]): high-performance
//! [Authenticated Encryption with Associated Data (AEAD)][3] cipher which also
//! provides [nonce reuse misuse resistance][4].
//!
//! Suitable as a general purpose symmetric encryption cipher, AES-GCM-SIV also
//! removes many of the "sharp edges" of AES-GCM, providing significantly better
//! security bounds while simultaneously eliminating the most catastrophic risks
//! of nonce reuse that exist in AES-GCM.
//!
//! Decryption performance is equivalent to AES-GCM.
//! Encryption is marginally slower.
//!
//! See also:
//!
//! - [Adam Langley: AES-GCM-SIV][5]
//! - [Coda Hale: Towards A Safer Footgun][6]
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
//! Simple usage (allocating, no associated data):
//!
//! ```
//! use aes_gcm_siv::Aes256GcmSiv; // Or `Aes128GcmSiv`
//! use aead::{Aead, NewAead, generic_array::GenericArray};
//!
//! let key = GenericArray::clone_from_slice(b"an example very very secret key.");
//! let aead = Aes256GcmSiv::new(key);
//!
//! let nonce = GenericArray::from_slice(b"unique nonce"); // 96-bits; unique per message
//! let ciphertext = aead.encrypt(nonce, b"plaintext message".as_ref()).expect("encryption failure!");
//! let plaintext = aead.decrypt(nonce, ciphertext.as_ref()).expect("decryption failure!");
//! assert_eq!(&plaintext, b"plaintext message");
//! ```
//!
//! ## In-place Usage (eliminates `alloc` requirement)
//!
//! This crate has an optional `alloc` feature which can be disabled in e.g.
//! microcontroller environments that don't have a heap.
//!
//! The [`Aead::encrypt_in_place`][7] and [`Aead::decrypt_in_place`][8]
//! methods accept any type that impls the [`aead::Buffer`][9] trait which
//! contains the plaintext for encryption or ciphertext for decryption.
//!
//! Note that if you enable the `heapless` feature of this crate,
//! you will receive an impl of `aead::Buffer` for [`heapless::Vec`][10]
//! (re-exported from the `aead` crate as `aead::heapless::Vec`),
//! which can then be passed as the `buffer` parameter to the in-place encrypt
//! and decrypt methods:
//!
//! ```
//! use aes_gcm_siv::Aes256GcmSiv; // Or `Aes128GcmSiv`
//! use aead::{Aead, NewAead};
//! use aead::generic_array::{GenericArray, typenum::U128};
//! use aead::heapless::Vec;
//!
//! let key = GenericArray::clone_from_slice(b"an example very very secret key.");
//! let aead = Aes256GcmSiv::new(key);
//!
//! let nonce = GenericArray::from_slice(b"unique nonce"); // 96-bits; unique per message
//!
//! let mut buffer: Vec<u8, U128> = Vec::new();
//! buffer.extend_from_slice(b"plaintext message");
//!
//! // Encrypt `buffer` in-place, replacing the plaintext contents with ciphertext
//! aead.encrypt_in_place(nonce, b"", &mut buffer).expect("encryption failure!");
//!
//! // `buffer` now contains the message ciphertext
//! assert_ne!(&buffer, b"plaintext message");
//!
//! // Decrypt `buffer` in-place, replacing its ciphertext context with the original plaintext
//! aead.decrypt_in_place(nonce, b"", &mut buffer).expect("decryption failure!");
//! assert_eq!(&buffer, b"plaintext message");
//! ```
//!
//! [1]: https://en.wikipedia.org/wiki/AES-GCM-SIV
//! [2]: https://tools.ietf.org/html/rfc8452
//! [3]: https://en.wikipedia.org/wiki/Authenticated_encryption
//! [4]: https://github.com/miscreant/meta/wiki/Nonce-Reuse-Misuse-Resistance
//! [5]: https://www.imperialviolet.org/2017/05/14/aesgcmsiv.html
//! [6]: https://codahale.com/towards-a-safer-footgun/
//! [7]: https://docs.rs/aead/latest/aead/trait.Aead.html#method.encrypt_in_place
//! [8]: https://docs.rs/aead/latest/aead/trait.Aead.html#method.decrypt_in_place
//! [9]: https://docs.rs/aead/latest/aead/trait.Buffer.html
//! [10]: https://docs.rs/heapless/latest/heapless/struct.Vec.html

#![no_std]
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
#![warn(missing_docs, rust_2018_idioms)]

pub mod ctr;

pub use aead;

use self::ctr::{Ctr, Ctr32x8, BLOCK8_SIZE};
use aead::generic_array::{
    typenum::{U0, U12, U16},
    ArrayLength, GenericArray,
};
use aead::{Aead, Error, NewAead};
use block_cipher_trait::BlockCipher;
use core::marker::PhantomData;
use polyval::{universal_hash::UniversalHash, Polyval};
use zeroize::Zeroize;

/// AES is optional to allow swapping in hardware-specific backends
#[cfg(feature = "aes")]
use aes::{Aes128, Aes256};

/// Maximum length of associated data (from RFC 8452 Section 6)
pub const A_MAX: u64 = 1 << 36;

/// Maximum length of plaintext (from RFC 8452 Section 6)
pub const P_MAX: u64 = 1 << 36;

/// Maximum length of ciphertext (from RFC 8452 Section 6)
pub const C_MAX: u64 = (1 << 36) + 16;

/// AES-GCM-SIV tags
pub type Tag = GenericArray<u8, U16>;

/// AES-GCM-SIV with a 128-bit key
#[cfg(feature = "aes")]
pub type Aes128GcmSiv = AesGcmSiv<Aes128>;

/// AES-GCM-SIV with a 256-bit key
#[cfg(feature = "aes")]
pub type Aes256GcmSiv = AesGcmSiv<Aes256>;

/// AES-GCM-SIV: Misuse-Resistant Authenticated Encryption Cipher (RFC 8452)
#[derive(Clone)]
pub struct AesGcmSiv<B, C = Ctr32x8<B>>
where
    B: BlockCipher<BlockSize = U16>,
    B::ParBlocks: ArrayLength<GenericArray<u8, B::BlockSize>>,
    C: Ctr<B>,
{
    /// Block cipher (i.e. key generating key)
    key: B,

    /// Counter mode implementation
    ctr: PhantomData<C>,
}

impl<B, C> NewAead for AesGcmSiv<B, C>
where
    B: BlockCipher<BlockSize = U16>,
    B::ParBlocks: ArrayLength<GenericArray<u8, B::BlockSize>>,
    C: Ctr<B>,
{
    type KeySize = B::KeySize;

    fn new(mut key_bytes: GenericArray<u8, B::KeySize>) -> Self {
        let key = B::new(&key_bytes);
        key_bytes.zeroize();
        Self {
            key,
            ctr: PhantomData,
        }
    }
}

impl<B, C> From<B> for AesGcmSiv<B, C>
where
    B: BlockCipher<BlockSize = U16>,
    B::ParBlocks: ArrayLength<GenericArray<u8, B::BlockSize>>,
    C: Ctr<B>,
{
    fn from(key: B) -> Self {
        Self {
            key,
            ctr: PhantomData,
        }
    }
}

impl<B, C> Aead for AesGcmSiv<B, C>
where
    B: BlockCipher<BlockSize = U16>,
    B::ParBlocks: ArrayLength<GenericArray<u8, B::BlockSize>>,
    C: Ctr<B>,
{
    type NonceSize = U12;
    type TagSize = U16;
    type CiphertextOverhead = U0;

    fn encrypt_in_place_detached(
        &self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag, Error> {
        Cipher::<B, C>::new(&self.key, nonce).encrypt_in_place_detached(associated_data, buffer)
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag,
    ) -> Result<(), Error> {
        Cipher::<B, C>::new(&self.key, nonce).decrypt_in_place_detached(
            associated_data,
            buffer,
            tag,
        )
    }
}

/// AES-GCM-SIV: Misuse-Resistant Authenticated Encryption Cipher (RFC 8452)
struct Cipher<B, C>
where
    B: BlockCipher<BlockSize = U16>,
    B::ParBlocks: ArrayLength<GenericArray<u8, B::BlockSize>>,
    C: Ctr<B>,
{
    /// Encryption cipher
    enc_cipher: B,

    /// Counter mode implementation
    ctr: PhantomData<C>,

    /// POLYVAL universal hash
    polyval: Polyval,

    /// Nonce
    nonce: GenericArray<u8, U12>,
}

impl<B, C> Cipher<B, C>
where
    B: BlockCipher<BlockSize = U16>,
    B::ParBlocks: ArrayLength<GenericArray<u8, B::BlockSize>>,
    C: Ctr<B>,
{
    /// Initialize AES-GCM-SIV, deriving per-nonce message-authentication and
    /// message-encryption keys.
    pub(crate) fn new(key_generating_key: &B, nonce: &GenericArray<u8, U12>) -> Self {
        let mut mac_key = GenericArray::default();
        let mut enc_key = GenericArray::default();
        let mut block = GenericArray::default();
        let mut counter = 0u32;

        // Derive subkeys from the master key-generating-key in counter mode.
        //
        // From RFC 8452 Section 4:
        // <https://tools.ietf.org/html/rfc8452#section-4>
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
        for derived_key in &mut [mac_key.as_mut(), enc_key.as_mut()] {
            for chunk in derived_key.chunks_mut(8) {
                block[..4].copy_from_slice(&counter.to_le_bytes());
                block[4..].copy_from_slice(nonce.as_slice());

                key_generating_key.encrypt_block(&mut block);
                chunk.copy_from_slice(&block.as_slice()[..8]);

                counter += 1;
            }
        }

        let result = Self {
            enc_cipher: B::new(&enc_key),
            ctr: PhantomData,
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

    /// Encrypt the given message in-place, returning the authentication tag
    pub(crate) fn encrypt_in_place_detached(
        mut self,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag, Error> {
        if buffer.len() as u64 > P_MAX || associated_data.len() as u64 > A_MAX {
            return Err(Error);
        }

        let tag = self.compute_tag(associated_data, buffer);
        C::new(&tag).apply_keystream(&self.enc_cipher, buffer);
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
        let mut ctr = C::new(tag);

        for chunk in buffer.chunks_mut(BLOCK8_SIZE) {
            ctr.apply_keystream(&self.enc_cipher, chunk);
            self.polyval.update_padded(chunk);
        }

        let expected_tag = self.finish_tag(associated_data.len(), buffer.len());

        use subtle::ConstantTimeEq;
        if expected_tag.ct_eq(&tag).unwrap_u8() == 1 {
            Ok(())
        } else {
            // On MAC verify failure, re-encrypt the plaintext buffer to
            // prevent accidental exposure.
            C::new(tag).apply_keystream(&self.enc_cipher, buffer);
            Err(Error)
        }
    }

    /// Authenticate the given plaintext and associated data using POLYVAL
    fn compute_tag(&mut self, associated_data: &[u8], buffer: &mut [u8]) -> Tag {
        self.polyval.update_padded(associated_data);
        self.polyval.update_padded(buffer);
        self.finish_tag(associated_data.len(), buffer.len())
    }

    /// Finish computing POLYVAL tag for AAD and buffer of the given length
    fn finish_tag(&mut self, associated_data_len: usize, buffer_len: usize) -> Tag {
        let associated_data_bits = (associated_data_len as u64) * 8;
        let buffer_bits = (buffer_len as u64) * 8;

        let mut block = GenericArray::default();
        block[..8].copy_from_slice(&associated_data_bits.to_le_bytes());
        block[8..].copy_from_slice(&buffer_bits.to_le_bytes());
        self.polyval.update_block(&block);

        let mut tag = self.polyval.result_reset().into_bytes();

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
