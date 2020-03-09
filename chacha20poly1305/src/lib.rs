//! [`ChaCha20Poly1305`] ([RFC 8439][1]) is an
//! [Authenticated Encryption with Associated Data (AEAD)][2]
//! cipher amenable to fast, constant-time implementations in software, based on
//! the [ChaCha20][3] stream cipher and [Poly1305][4] universal hash function.
//!
//! This crate contains pure Rust implementations of `ChaCha20Poly1305`
//! (with optional AVX2 acceleration) as well as the following variants thereof:
//!
//! - [`XChaCha20Poly1305`] - ChaCha20Poly1305 variant with an extended 192-bit (24-byte) nonce.
//! - [`ChaCha8Poly1305`] / [`ChaCha12Poly1305`] - nonstandard, reduced round variants
//!   (gated under the `reduced-round` Cargo feature). See the [Too Much Crypto][5]
//!   paper for background and rationale on when these constructions shoudl be used.
//!   When in doubt, prefer `ChaCha20Poly1305`.
//!
//! ## Performance Notes
//!
//! By default this crate will use portable software implementations of the
//! underlying ChaCha20 and Poly1305 ciphers it's based on.
//!
//! When targeting modern x86/x86_64 CPUs, use the following `RUSTFLAGS` to
//! take advantage of AVX2 acceleration:
//!
//! ```text
//! RUSTFLAGS="-Ctarget-feature=+avx2"
//! ```
//!
//! Ideally target the `haswell` or `skylake` architectures as a baseline:
//!
//! ```text
//! RUSTFLAGS="-Ctarget-cpu=haswell -Ctarget-feature=+avx2"
//! ```
//!
//! ## Security Notes
//!
//! This crate has received one [security audit by NCC Group][6], with no significant
//! findings. We would like to thank [MobileCoin][7] for funding the audit.
//!
//! All implementations contained in the crate are designed to execute in
//! constant time, either by relying on hardware intrinsics (i.e. AVX2 on
//! x86/x86_64), or using a portable implementation which is only constant time
//! on processors which implement constant-time multiplication.
//!
//! It is not suitable for use on processors with a variable-time multiplication
//! operation (e.g. short circuit on multiply-by-zero / multiply-by-one, such as
//! certain 32-bit PowerPC CPUs and some non-ARM microcontrollers).
//!
//! # Usage
//!
//! ```
//! use chacha20poly1305::ChaCha20Poly1305; // Or `XChaCha20Poly1305`
//! use aead::{Aead, NewAead, generic_array::GenericArray};
//!
//! let key = GenericArray::clone_from_slice(b"an example very very secret key."); // 32-bytes
//! let aead = ChaCha20Poly1305::new(key);
//!
//! let nonce = GenericArray::from_slice(b"unique nonce"); // 12-bytes; unique per message
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
//! The [`Aead::encrypt_in_place`][8] and [`Aead::decrypt_in_place`][9]
//! methods accept any type that impls the [`aead::Buffer`][10] trait which
//! contains the plaintext for encryption or ciphertext for decryption.
//!
//! Note that if you enable the `heapless` feature of this crate,
//! you will receive an impl of `aead::Buffer` for [`heapless::Vec`][11]
//! (re-exported from the `aead` crate as `aead::heapless::Vec`),
//! which can then be passed as the `buffer` parameter to the in-place encrypt
//! and decrypt methods:
//!
//! ```
//! use chacha20poly1305::ChaCha20Poly1305; // Or `XChaCha20Poly1305`
//! use aead::{Aead, NewAead};
//! use aead::generic_array::{GenericArray, typenum::U128};
//! use aead::heapless::Vec;
//!
//! let key = GenericArray::clone_from_slice(b"an example very very secret key.");
//! let aead = ChaCha20Poly1305::new(key);
//!
//! let nonce = GenericArray::from_slice(b"unique nonce"); // 128-bits; unique per message
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
//! [1]: https://tools.ietf.org/html/rfc8439
//! [2]: https://en.wikipedia.org/wiki/Authenticated_encryption
//! [3]: https://github.com/RustCrypto/stream-ciphers/tree/master/chacha20
//! [4]: https://github.com/RustCrypto/universal-hashes/tree/master/poly1305
//! [5]: https://eprint.iacr.org/2019/1492.pdf
//! [6]: https://research.nccgroup.com/2020/02/26/public-report-rustcrypto-aes-gcm-and-chacha20poly1305-implementation-review/
//! [7]: https://www.mobilecoin.com/
//! [8]: https://docs.rs/aead/latest/aead/trait.Aead.html#method.encrypt_in_place
//! [9]: https://docs.rs/aead/latest/aead/trait.Aead.html#method.decrypt_in_place
//! [10]: https://docs.rs/aead/latest/aead/trait.Buffer.html
//! [11]: https://docs.rs/heapless/latest/heapless/struct.Vec.html

#![no_std]
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
#![warn(missing_docs, rust_2018_idioms, intra_doc_link_resolution_failure)]

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
use aead::{Aead, Error, NewAead};
use core::marker::PhantomData;
use stream_cipher::{NewStreamCipher, SyncStreamCipher, SyncStreamCipherSeek};
use zeroize::Zeroize;

#[cfg(feature = "chacha20")]
use chacha20::ChaCha20;

#[cfg(feature = "reduced-round")]
use chacha20::{ChaCha12, ChaCha8};

/// Poly1305 tags
pub type Tag = GenericArray<u8, U16>;

/// ChaCha20Poly1305 Authenticated Encryption with Additional Data (AEAD).
#[cfg(feature = "chacha20")]
pub type ChaCha20Poly1305 = ChaChaPoly1305<ChaCha20>;

/// ChaCha8Poly1305 (reduced round variant) Authenticated Encryption with Additional Data (AEAD).
#[cfg(feature = "reduced-round")]
pub type ChaCha8Poly1305 = ChaChaPoly1305<ChaCha8>;

/// ChaCha12Poly1305 (reduced round variant) Authenticated Encryption with Additional Data (AEAD).
#[cfg(feature = "reduced-round")]
pub type ChaCha12Poly1305 = ChaChaPoly1305<ChaCha12>;

/// ChaCha* + Poly1305 Authenticated Encryption with Additional Data (AEAD) construction.
///
/// The [`Aead`] and [`NewAead`] traits provide the primary API for using this construction.
///
/// See the [toplevel documentation](https://docs.rs/chacha20poly1305) for a usage example.
pub struct ChaChaPoly1305<C>
where
    C: NewStreamCipher<KeySize = U32, NonceSize = U12> + SyncStreamCipher + SyncStreamCipherSeek,
{
    /// Secret key
    key: GenericArray<u8, U32>,

    /// ChaCha stream cipher
    stream_cipher: PhantomData<C>,
}

impl<C> NewAead for ChaChaPoly1305<C>
where
    C: NewStreamCipher<KeySize = U32, NonceSize = U12> + SyncStreamCipher + SyncStreamCipherSeek,
{
    type KeySize = U32;

    fn new(key: GenericArray<u8, U32>) -> Self {
        Self {
            key,
            stream_cipher: PhantomData,
        }
    }
}

impl<C> Aead for ChaChaPoly1305<C>
where
    C: NewStreamCipher<KeySize = U32, NonceSize = U12> + SyncStreamCipher + SyncStreamCipherSeek,
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
        Cipher::new(C::new(&self.key, nonce)).encrypt_in_place_detached(associated_data, buffer)
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag,
    ) -> Result<(), Error> {
        Cipher::new(C::new(&self.key, nonce)).decrypt_in_place_detached(
            associated_data,
            buffer,
            tag,
        )
    }
}

impl<C> Clone for ChaChaPoly1305<C>
where
    C: NewStreamCipher<KeySize = U32, NonceSize = U12> + SyncStreamCipher + SyncStreamCipherSeek,
{
    fn clone(&self) -> Self {
        Self {
            key: self.key,
            stream_cipher: PhantomData,
        }
    }
}

impl<C> Drop for ChaChaPoly1305<C>
where
    C: NewStreamCipher<KeySize = U32, NonceSize = U12> + SyncStreamCipher + SyncStreamCipherSeek,
{
    fn drop(&mut self) {
        self.key.as_mut_slice().zeroize();
    }
}
