#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![warn(missing_docs, rust_2018_idioms)]

//! ## Supported Algorithms
//!
//! This crate contains pure Rust implementations of [`ChaCha20Poly1305`]
//! (with optional AVX2 acceleration) as well as the following variants thereof:
//!
//! - [`XChaCha20Poly1305`] - ChaCha20Poly1305 variant with an extended 192-bit (24-byte) nonce.
//! - [`ChaCha8Poly1305`] / [`ChaCha12Poly1305`] - non-standard, reduced-round variants
//!   (gated under the `reduced-round` Cargo feature). See the
//!   [Too Much Crypto](https://eprint.iacr.org/2019/1492.pdf)
//!   paper for background and rationale on when these constructions could be used.
//!   When in doubt, prefer [`ChaCha20Poly1305`].
//! - [`XChaCha8Poly1305`] / [`XChaCha12Poly1305`] - same as above,
//!   but with an extended 192-bit (24-byte) nonce.
//!
//! # Usage
//!
#![cfg_attr(feature = "os_rng", doc = "```")]
#![cfg_attr(not(feature = "os_rng"), doc = "```ignore")]
//! # fn main() -> Result<(), Box<dyn core::error::Error>> {
//! use chacha20poly1305::{
//!     aead::{Aead, AeadCore, KeyInit, rand_core::OsRng},
//!     ChaCha20Poly1305, Nonce
//! };
//!
//! let key = ChaCha20Poly1305::generate_key().expect("generate key");
//! let cipher = ChaCha20Poly1305::new(&key);
//! let nonce = ChaCha20Poly1305::generate_nonce().expect("Generate nonce"); // 96-bits; unique per message
//! let ciphertext = cipher.encrypt(&nonce, b"plaintext message".as_ref())?;
//! let plaintext = cipher.decrypt(&nonce, ciphertext.as_ref())?;
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
//! The [`AeadInOut::encrypt_in_place`] and [`AeadInOut::decrypt_in_place`]
//! methods accept any type that impls the [`aead::Buffer`] trait which
//! contains the plaintext for encryption or ciphertext for decryption.
//!
//! Note that if you enable the `heapless` feature of this crate,
//! you will receive an impl of [`aead::Buffer`] for `heapless::Vec`
//! (re-exported from the [`aead`] crate as [`aead::heapless::Vec`]),
//! which can then be passed as the `buffer` parameter to the in-place encrypt
//! and decrypt methods:
//!
#![cfg_attr(all(feature = "os_rng", feature = "heapless"), doc = "```")]
#![cfg_attr(not(all(feature = "os_rng", feature = "heapless")), doc = "```ignore")]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use chacha20poly1305::{
//!     aead::{AeadCore, AeadInOut, KeyInit, rand_core::OsRng, heapless::Vec},
//!     ChaCha20Poly1305, Nonce,
//! };
//!
//! let key = ChaCha20Poly1305::generate_key().expect("Generate key");
//! let cipher = ChaCha20Poly1305::new(&key);
//! let nonce = ChaCha20Poly1305::generate_nonce().expect("Generate nonce"); // 96-bits; unique per message
//!
//! let mut buffer: Vec<u8, 128> = Vec::new(); // Note: buffer needs 16-bytes overhead for auth tag
//! buffer.extend_from_slice(b"plaintext message");
//!
//! // Encrypt `buffer` in-place, replacing the plaintext contents with ciphertext
//! cipher.encrypt_in_place(&nonce, b"", &mut buffer)?;
//!
//! // `buffer` now contains the message ciphertext
//! assert_ne!(&buffer, b"plaintext message");
//!
//! // Decrypt `buffer` in-place, replacing its ciphertext context with the original plaintext
//! cipher.decrypt_in_place(&nonce, b"", &mut buffer)?;
//! assert_eq!(&buffer, b"plaintext message");
//! # Ok(())
//! # }
//! ```
//!
//! Similarly, enabling the `arrayvec` feature of this crate will provide an impl of
//! [`aead::Buffer`] for `arrayvec::ArrayVec` (re-exported from the [`aead`] crate as
//! [`aead::arrayvec::ArrayVec`]), and enabling the `bytes` feature of this crate will
//! provide an impl of [`aead::Buffer`] for `bytes::BytesMut` (re-exported from the
//! [`aead`] crate as [`aead::bytes::BytesMut`]).
//!
//! ## [`XChaCha20Poly1305`]
//!
//! ChaCha20Poly1305 variant with an extended 192-bit (24-byte) nonce.
//!
//! The construction is an adaptation of the same techniques used by
//! XSalsa20 as described in the paper "Extending the Salsa20 Nonce"
//! to the 96-bit nonce variant of ChaCha20, which derive a
//! separate subkey/nonce for each extended nonce:
//!
//! <https://cr.yp.to/snuffle/xsalsa-20081128.pdf>
//!
//! No authoritative specification exists for XChaCha20Poly1305, however the
//! construction has "rough consensus and running code" in the form of
//! several interoperable libraries and protocols (e.g. libsodium, WireGuard)
//! and is documented in an (expired) IETF draft, which also applies the
//! proof from the XSalsa20 paper to the construction in order to demonstrate
//! that XChaCha20 is secure if ChaCha20 is secure (see Section 3.1):
//!
//! <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha>
//!
//! It is worth noting that NaCl/libsodium's default "secretbox" algorithm is
//! XSalsa20Poly1305, not XChaCha20Poly1305, and thus not compatible with
//! this library. If you are interested in that construction, please see the
//! `crypto_secretbox` crate:
//!
//! <https://docs.rs/crypto_secretbox/>
//!
//! # Usage
//!
#![cfg_attr(feature = "os_rng", doc = "```")]
#![cfg_attr(not(feature = "os_rng"), doc = "```ignore")]
//! # fn main() -> Result<(), Box<dyn core::error::Error>> {
//! use chacha20poly1305::{
//!     aead::{Aead, AeadCore, KeyInit, rand_core::OsRng},
//!     XChaCha20Poly1305, XNonce
//! };
//!
//! let key = XChaCha20Poly1305::generate_key().expect("Generate key");
//! let cipher = XChaCha20Poly1305::new(&key);
//! let nonce = XChaCha20Poly1305::generate_nonce().expect("Generate nonce"); // 192-bits; unique per message
//! let ciphertext = cipher.encrypt(&nonce, b"plaintext message".as_ref())?;
//! let plaintext = cipher.decrypt(&nonce, ciphertext.as_ref())?;
//! assert_eq!(&plaintext, b"plaintext message");
//! # Ok(())
//! # }
//! ```

mod cipher;

pub use aead::{self, AeadCore, AeadInOut, Error, KeyInit, KeySizeUser, consts};

use self::cipher::Cipher;
use ::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use aead::{
    TagPosition,
    array::{Array, ArraySize},
    consts::{U12, U16, U24, U32},
    inout::InOutBuf,
};
use core::marker::PhantomData;

use chacha20::{ChaCha20, XChaCha20};

#[cfg(feature = "reduced-round")]
use chacha20::{ChaCha8, ChaCha12, XChaCha8, XChaCha12};

/// Key type (256-bits/32-bytes).
///
/// Implemented as an alias for [`Array`].
///
/// All [`ChaChaPoly1305`] variants (including `XChaCha20Poly1305`) use this
/// key type.
pub type Key = Array<u8, U32>;

/// Nonce type (96-bits/12-bytes).
///
/// Implemented as an alias for [`Array`].
pub type Nonce = Array<u8, U12>;

/// XNonce type (192-bits/24-bytes).
///
/// Implemented as an alias for [`Array`].
pub type XNonce = Array<u8, U24>;

/// Poly1305 tag.
///
/// Implemented as an alias for [`Array`].
pub type Tag = Array<u8, U16>;

/// ChaCha20Poly1305 Authenticated Encryption with Additional Data (AEAD).
pub type ChaCha20Poly1305 = ChaChaPoly1305<ChaCha20, U12>;

/// XChaCha20Poly1305 Authenticated Encryption with Additional Data (AEAD).
pub type XChaCha20Poly1305 = ChaChaPoly1305<XChaCha20, U24>;

/// ChaCha8Poly1305 (reduced round variant) Authenticated Encryption with Additional Data (AEAD).
#[cfg(feature = "reduced-round")]
#[cfg_attr(docsrs, doc(cfg(feature = "reduced-round")))]
pub type ChaCha8Poly1305 = ChaChaPoly1305<ChaCha8, U12>;

/// ChaCha12Poly1305 (reduced round variant) Authenticated Encryption with Additional Data (AEAD).
#[cfg(feature = "reduced-round")]
#[cfg_attr(docsrs, doc(cfg(feature = "reduced-round")))]
pub type ChaCha12Poly1305 = ChaChaPoly1305<ChaCha12, U12>;

/// XChaCha8Poly1305 (reduced round variant) Authenticated Encryption with Additional Data (AEAD).
#[cfg(feature = "reduced-round")]
#[cfg_attr(docsrs, doc(cfg(feature = "reduced-round")))]
pub type XChaCha8Poly1305 = ChaChaPoly1305<XChaCha8, U24>;

/// XChaCha12Poly1305 (reduced round variant) Authenticated Encryption with Additional Data (AEAD).
#[cfg(feature = "reduced-round")]
#[cfg_attr(docsrs, doc(cfg(feature = "reduced-round")))]
pub type XChaCha12Poly1305 = ChaChaPoly1305<XChaCha12, U24>;

/// Generic ChaCha+Poly1305 Authenticated Encryption with Additional Data (AEAD) construction.
///
/// See the [toplevel documentation](index.html) for a usage example.
pub struct ChaChaPoly1305<C, N: ArraySize = U12> {
    /// Secret key.
    key: Key,

    /// ChaCha stream cipher.
    stream_cipher: PhantomData<C>,

    /// Nonce size.
    nonce_size: PhantomData<N>,
}

impl<C, N> KeySizeUser for ChaChaPoly1305<C, N>
where
    N: ArraySize,
{
    type KeySize = U32;
}

impl<C, N> KeyInit for ChaChaPoly1305<C, N>
where
    N: ArraySize,
{
    #[inline]
    fn new(key: &Key) -> Self {
        Self {
            key: *key,
            stream_cipher: PhantomData,
            nonce_size: PhantomData,
        }
    }
}

impl<C, N> AeadCore for ChaChaPoly1305<C, N>
where
    N: ArraySize,
{
    type NonceSize = N;
    type TagSize = U16;
    const TAG_POSITION: TagPosition = TagPosition::Postfix;
}

impl<C, N> AeadInOut for ChaChaPoly1305<C, N>
where
    C: KeyIvInit<KeySize = U32, IvSize = N> + StreamCipher + StreamCipherSeek,
    N: ArraySize,
{
    fn encrypt_inout_detached(
        &self,
        nonce: &aead::Nonce<Self>,
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
    ) -> Result<Tag, Error> {
        Cipher::new(C::new(&self.key, nonce)).encrypt_inout_detached(associated_data, buffer)
    }

    fn decrypt_inout_detached(
        &self,
        nonce: &aead::Nonce<Self>,
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
        tag: &Tag,
    ) -> Result<(), Error> {
        Cipher::new(C::new(&self.key, nonce)).decrypt_inout_detached(associated_data, buffer, tag)
    }
}

impl<C, N> Clone for ChaChaPoly1305<C, N>
where
    N: ArraySize,
{
    fn clone(&self) -> Self {
        Self {
            key: self.key,
            stream_cipher: PhantomData,
            nonce_size: PhantomData,
        }
    }
}

impl<C, N> Drop for ChaChaPoly1305<C, N>
where
    N: ArraySize,
{
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use zeroize::Zeroize;
            self.key.as_mut_slice().zeroize();
        }
    }
}

#[cfg(feature = "zeroize")]
impl<C, N: ArraySize> zeroize::ZeroizeOnDrop for ChaChaPoly1305<C, N> {}
