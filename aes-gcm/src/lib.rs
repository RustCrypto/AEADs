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
//! ## Security Notes
//!
//! This crate has received one [security audit by NCC Group][3], with no significant
//! findings. We would like to thank [MobileCoin][4] for funding the audit.
//!
//! All implementations contained in the crate are designed to execute in constant
//! time, either by relying on hardware intrinsics (i.e. AES-NI and CLMUL on
//! x86/x86_64), or using a portable implementation which is only constant time
//! on processors which implement constant-time multiplication.
//!
//! It is not suitable for use on processors with a variable-time multiplication
//! operation (e.g. short circuit on multiply-by-zero / multiply-by-one, such as
//! certain 32-bit PowerPC CPUs and some non-ARM microcontrollers).
//!
//! # Usage
//!
//! Simple usage (allocating, no associated data):
//!
//! ```
//! use aes_gcm::{Aes256Gcm, Key, Nonce}; // Or `Aes128Gcm`
//! use aes_gcm::aead::{Aead, NewAead};
//!
//! let key = Key::from_slice(b"an example very very secret key.");
//! let cipher = Aes256Gcm::new(key);
//!
//! let nonce = Nonce::from_slice(b"unique nonce"); // 96-bits; unique per message
//!
//! let ciphertext = cipher.encrypt(nonce, b"plaintext message".as_ref())
//!     .expect("encryption failure!"); // NOTE: handle this error to avoid panics!
//!
//! let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
//!     .expect("decryption failure!"); // NOTE: handle this error to avoid panics!
//!
//! assert_eq!(&plaintext, b"plaintext message");
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
//! ```
//! # #[cfg(feature = "heapless")]
//! # {
//! use aes_gcm::{Aes256Gcm, Key, Nonce}; // Or `Aes128Gcm`
//! use aes_gcm::aead::{AeadInPlace, NewAead};
//! use aes_gcm::aead::heapless::Vec;
//!
//! let key = Key::from_slice(b"an example very very secret key.");
//! let cipher = Aes256Gcm::new(key);
//!
//! let nonce = Nonce::from_slice(b"unique nonce"); // 96-bits; unique per message
//!
//! let mut buffer: Vec<u8, 128> = Vec::new(); // Buffer needs 16-bytes overhead for GCM tag
//! buffer.extend_from_slice(b"plaintext message");
//!
//! // Encrypt `buffer` in-place, replacing the plaintext contents with ciphertext
//! cipher.encrypt_in_place(nonce, b"", &mut buffer).expect("encryption failure!");
//!
//! // `buffer` now contains the message ciphertext
//! assert_ne!(&buffer, b"plaintext message");
//!
//! // Decrypt `buffer` in-place, replacing its ciphertext context with the original plaintext
//! cipher.decrypt_in_place(nonce, b"", &mut buffer).expect("decryption failure!");
//! assert_eq!(&buffer, b"plaintext message");
//! # }
//! ```
//!
//! [1]: https://en.wikipedia.org/wiki/Authenticated_encryption
//! [2]: https://en.wikipedia.org/wiki/Galois/Counter_Mode
//! [3]: https://research.nccgroup.com/2020/02/26/public-report-rustcrypto-aes-gcm-and-chacha20poly1305-implementation-review/
//! [4]: https://www.mobilecoin.com/

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub use aead::{self, AeadCore, AeadInPlace, Error, NewAead};

#[cfg(feature = "aes")]
pub use aes;

use cipher::{
    consts::{U0, U16},
    generic_array::{typenum::Unsigned, ArrayLength, GenericArray},
    Block, BlockCipher, BlockCipherKey, BlockEncrypt, FromBlockCipher, NewBlockCipher,
    StreamCipher, StreamCipherSeek,
};
use core::marker::PhantomData;
use ctr::Ctr32BE;
use ghash::{
    universal_hash::{NewUniversalHash, UniversalHash},
    GHash,
};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

#[cfg(feature = "aes")]
use aes::{cipher::consts::U12, Aes128, Aes256};

/// Maximum length of associated data
pub const A_MAX: u64 = 1 << 36;

/// Maximum length of plaintext
pub const P_MAX: u64 = 1 << 36;

/// Maximum length of ciphertext
pub const C_MAX: u64 = (1 << 36) + 16;

/// AES-GCM keys
pub type Key<KeySize> = GenericArray<u8, KeySize>;

/// AES-GCM nonces
pub type Nonce<NonceSize> = GenericArray<u8, NonceSize>;

/// AES-GCM tags
pub type Tag = GenericArray<u8, U16>;

/// AES-GCM with a 128-bit key and 96-bit nonce
#[cfg(feature = "aes")]
#[cfg_attr(docsrs, doc(cfg(feature = "aes")))]
pub type Aes128Gcm = AesGcm<Aes128, U12>;

/// AES-GCM with a 256-bit key and 96-bit nonce
#[cfg(feature = "aes")]
#[cfg_attr(docsrs, doc(cfg(feature = "aes")))]
pub type Aes256Gcm = AesGcm<Aes256, U12>;

/// AES-GCM: generic over an underlying AES implementation and nonce size.
///
/// This type is generic to support substituting alternative AES implementations
/// (e.g. embedded hardware implementations)
///
/// It is NOT intended to be instantiated with any block cipher besides AES!
/// Doing so runs the risk of unintended cryptographic properties!
///
/// The `N` generic parameter can be used to instantiate AES-GCM with other
/// nonce sizes, however it's recommended to use it with `typenum::U12`,
/// the default of 96-bits.
///
/// If in doubt, use the built-in [`Aes128Gcm`] and [`Aes256Gcm`] type aliases.
#[derive(Clone)]
pub struct AesGcm<Aes, NonceSize>
where
    Aes: BlockCipher<BlockSize = U16> + BlockEncrypt,
    Aes::ParBlocks: ArrayLength<Block<Aes>>,
    NonceSize: ArrayLength<u8>,
{
    /// Encryption cipher
    cipher: Aes,

    /// GHASH authenticator
    ghash: GHash,

    /// Length of the nonce
    nonce_size: PhantomData<NonceSize>,
}

impl<Aes, NonceSize> NewAead for AesGcm<Aes, NonceSize>
where
    Aes: NewBlockCipher + BlockCipher<BlockSize = U16> + BlockEncrypt,
    Aes::ParBlocks: ArrayLength<Block<Aes>>,
    NonceSize: ArrayLength<u8>,
{
    type KeySize = Aes::KeySize;

    fn new(key: &BlockCipherKey<Aes>) -> Self {
        Aes::new(key).into()
    }
}

impl<Aes, NonceSize> From<Aes> for AesGcm<Aes, NonceSize>
where
    Aes: NewBlockCipher + BlockCipher<BlockSize = U16> + BlockEncrypt,
    Aes::ParBlocks: ArrayLength<Block<Aes>>,
    NonceSize: ArrayLength<u8>,
{
    fn from(cipher: Aes) -> Self {
        let mut ghash_key = ghash::Key::default();
        cipher.encrypt_block(&mut ghash_key);

        let ghash = GHash::new(&ghash_key);

        #[cfg(feature = "zeroize")]
        ghash_key.zeroize();

        Self {
            cipher,
            ghash,
            nonce_size: PhantomData,
        }
    }
}

impl<Aes, NonceSize> AeadCore for AesGcm<Aes, NonceSize>
where
    Aes: NewBlockCipher + BlockCipher<BlockSize = U16> + BlockEncrypt,
    Aes::ParBlocks: ArrayLength<Block<Aes>>,
    NonceSize: ArrayLength<u8>,
{
    type NonceSize = NonceSize;
    type TagSize = U16;
    type CiphertextOverhead = U0;
}

impl<Aes, NonceSize> AeadInPlace for AesGcm<Aes, NonceSize>
where
    Aes: NewBlockCipher + BlockCipher<BlockSize = U16> + BlockEncrypt,
    Aes::ParBlocks: ArrayLength<Block<Aes>>,
    NonceSize: ArrayLength<u8>,
{
    fn encrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self::NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag, Error> {
        if buffer.len() as u64 > P_MAX || associated_data.len() as u64 > A_MAX {
            return Err(Error);
        }

        // TODO(tarcieri): interleave encryption with GHASH
        // See: <https://github.com/RustCrypto/AEADs/issues/74>
        let mut ctr = self.init_ctr(nonce);
        ctr.seek(Aes::BlockSize::to_usize());
        ctr.apply_keystream(buffer);

        let mut tag = self.compute_tag(associated_data, buffer);
        ctr.seek(0);
        ctr.apply_keystream(tag.as_mut_slice());

        Ok(tag)
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self::NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag,
    ) -> Result<(), Error> {
        if buffer.len() as u64 > C_MAX || associated_data.len() as u64 > A_MAX {
            return Err(Error);
        }

        // TODO(tarcieri): interleave encryption with GHASH
        // See: <https://github.com/RustCrypto/AEADs/issues/74>
        let mut expected_tag = self.compute_tag(associated_data, buffer);
        let mut ctr = self.init_ctr(nonce);
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

impl<Aes, NonceSize> AesGcm<Aes, NonceSize>
where
    Aes: NewBlockCipher + BlockCipher<BlockSize = U16> + BlockEncrypt,
    Aes::ParBlocks: ArrayLength<Block<Aes>>,
    NonceSize: ArrayLength<u8>,
{
    /// Initialize counter mode.
    ///
    /// See algorithm described in Section 7.2 of NIST SP800-38D:
    /// <https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf>
    ///
    /// > Define a block, J0, as follows:
    /// > If len(IV)=96, then J0 = IV || 0{31} || 1.
    /// > If len(IV) ≠ 96, then let s = 128 ⎡len(IV)/128⎤-len(IV), and
    /// >     J0=GHASH(IV||0s+64||[len(IV)]64).
    fn init_ctr(&self, nonce: &Nonce<NonceSize>) -> Ctr32BE<&Aes> {
        let j0 = if NonceSize::to_usize() == 12 {
            let mut block = ghash::Block::default();
            block[..12].copy_from_slice(nonce);
            block[15] = 1;
            block
        } else {
            let mut ghash = self.ghash.clone();
            ghash.update_padded(nonce);

            let mut block = ghash::Block::default();
            let nonce_bits = (NonceSize::to_usize() as u64) * 8;
            block[8..].copy_from_slice(&nonce_bits.to_be_bytes());
            ghash.update(&block);
            ghash.finalize().into_bytes()
        };

        Ctr32BE::from_block_cipher(&self.cipher, &j0)
    }

    /// Authenticate the given plaintext and associated data using GHASH
    fn compute_tag(&self, associated_data: &[u8], buffer: &[u8]) -> Tag {
        let mut ghash = self.ghash.clone();
        ghash.update_padded(associated_data);
        ghash.update_padded(buffer);

        let associated_data_bits = (associated_data.len() as u64) * 8;
        let buffer_bits = (buffer.len() as u64) * 8;

        let mut block = ghash::Block::default();
        block[..8].copy_from_slice(&associated_data_bits.to_be_bytes());
        block[8..].copy_from_slice(&buffer_bits.to_be_bytes());
        ghash.update(&block);
        ghash.finalize().into_bytes()
    }
}
