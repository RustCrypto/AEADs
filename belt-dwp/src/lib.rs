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
#![cfg_attr(all(feature = "os_rng", feature = "heapless"), doc = "```")]
#![cfg_attr(not(all(feature = "os_rng", feature = "heapless")), doc = "```ignore")]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use belt_dwp::{
//!     aead::{Aead, AeadCore, KeyInit, OsRng},
//!     BeltDwp, Nonce
//! };
//!
//! let key = BeltDwp::generate_key().unwrap();
//! let cipher = BeltDwp::new(&key);
//! let nonce = BeltDwp::generate_nonce().unwrap(); // 128-bits; unique per message
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
#![cfg_attr(all(feature = "os_rng", feature = "heapless"), doc = "```")]
#![cfg_attr(not(all(feature = "os_rng", feature = "heapless")), doc = "```ignore")]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use belt_dwp::{
//!     aead::{AeadInPlaceDetached, KeyInit, OsRng, heapless::Vec},
//!     BeltDwp, Nonce
//! };
//!
//! let key = BeltDwp::generate_key(&mut OsRng);
//! let cipher = BeltDwp::new(&key);
//! let nonce = Nonce::from_slice(b"unique nonce1234"); // 128-bits; unique per message
//!
//! let mut buffer: Vec<u8, 128> = Vec::new(); // Note: buffer needs 16-bytes overhead for auth tag
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
//!
//! Similarly, enabling the `arrayvec` feature of this crate will provide an impl of
//! [`aead::Buffer`] for `arrayvec::ArrayVec` (re-exported from the [`aead`] crate as
//! [`aead::arrayvec::ArrayVec`]).

use aead::consts::{U16, U32, U8};
use aead::AeadInPlaceDetached;
pub use aead::{self, AeadCore, AeadInPlace, Error, Key, KeyInit, KeySizeUser};
use belt_block::cipher::{Block, BlockCipherEncrypt, KeyIvInit, StreamCipher};
use belt_block::{belt_block_raw, BeltBlock};
use belt_ctr::BeltCtr;
use universal_hash::UniversalHash;

use crate::{
    ghash::GHash,
    utils::{from_u32, to_u32},
};

/// Nonce type for [`BeltDwp`]
pub type Nonce = aead::Nonce<BeltDwp>;

/// Tag type for [`BeltDwp`]
pub type Tag = aead::Tag<BeltDwp>;

mod gf;
mod ghash;
mod utils;

/// T from the STB 34.101.31-2020
const T: u128 = 0xE45D4A588E006D363BF5080AC8BA94B1;

/// Belt-DWP authenticated encryption with associated data (AEAD) cipher, defined in
/// STB 34.101.31-2020
pub struct BeltDwp {
    key: Key<BeltBlock>,
}

impl KeySizeUser for BeltDwp {
    type KeySize = U32;
}

impl AeadInPlaceDetached for BeltDwp {
    fn encrypt_in_place_detached(
        &self,
        nonce: &Nonce,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> aead::Result<Tag> {
        Cipher::new(self.key, nonce).encrypt_in_place_detached(associated_data, buffer)
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &Nonce,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag,
    ) -> aead::Result<()> {
        Cipher::new(self.key, nonce).decrypt_in_place_detached(associated_data, buffer, tag)
    }
}

struct Cipher {
    enc_cipher: BeltCtr,
    mac_cipher: BeltBlock,
    ghash: GHash,
}

impl Cipher {
    fn new(key: Key<BeltBlock>, nonce: &Nonce) -> Self {
        let cipher: BeltCtr = BeltCtr::new(&key, nonce);

        let _s = to_u32::<4>(nonce);
        let _k = to_u32::<8>(&key);
        // 2.1. 𝑠 ← belt-block(𝑆, 𝐾);
        let s = belt_block_raw(_s, &_k);
        // 2.2. 𝑟 ← belt-block(𝑠, 𝐾);
        let r = from_u32::<16>(&belt_block_raw(s, &_k));

        Self {
            enc_cipher: cipher,
            mac_cipher: BeltBlock::new(&key),
            // Unwrap is safe because the key is always 16 bytes
            ghash: GHash::new_with_init_block(&Key::<GHash>::try_from(&r[..]).unwrap(), T),
        }
    }

    fn encrypt_in_place_detached(
        &mut self,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> aead::Result<Tag> {
        let sizes_block =
            get_sizes_block(associated_data.len() as u64 * 8, buffer.len() as u64 * 8);

        // 3. For 𝑖 = 1, 2, . . . , 𝑚 do:
        //  3.1 𝑡 ← 𝑡 ⊕ (𝐼𝑖 ‖ 0^{128−|𝐼𝑖|})
        //  3.2 𝑡 ← 𝑡 * 𝑟.
        self.ghash.update_padded(associated_data);

        // 4. For 𝑖 = 1, 2, . . . , 𝑛 do:
        //  4.1 𝑠 ← 𝑠 ⊞ ⟨1⟩_128
        //  4.2 𝑌𝑖 ← 𝑋𝑖 ⊕ Lo(belt-block(𝑠, 𝐾), |𝑋𝑖|)
        //  4.3 𝑡 ← 𝑡 ⊕ (𝑌𝑖 ‖ 0^{128−|𝑌𝑖|})
        //  4.4 𝑡 ← 𝑡 * 𝑟.
        buffer.chunks_mut(16).for_each(|block| {
            self.enc_cipher.apply_keystream(block);
            self.ghash.update_padded(block);
        });

        // 5. 𝑡 ← 𝑡 ⊕ (⟨|𝐼|⟩_64 ‖ ⟨|𝑋|⟩_64)
        self.ghash.xor_s(&sizes_block);

        // 6. 𝑡 ← belt-block(𝑡 * 𝑟, 𝐾).
        let mut tag = self.finish_tag();

        self.mac_cipher.encrypt_block(&mut tag);

        // Unwrap is safe because the tag is always 8 bytes
        Ok(Tag::try_from(&tag[..8]).unwrap())
    }

    fn decrypt_in_place_detached(
        &mut self,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag,
    ) -> aead::Result<()> {
        let sizes_block =
            get_sizes_block(associated_data.len() as u64 * 8, buffer.len() as u64 * 8);

        // 3. For 𝑖 = 1, 2, . . . , 𝑚 do:
        //  3.1 𝑡 ← 𝑡 ⊕ (𝐼𝑖 ‖ 0^{128−|𝐼𝑖|})
        //  3.2 𝑡 ← 𝑡 * 𝑟.
        self.ghash.update_padded(associated_data);
        // 4. For 𝑖 = 1, 2, . . . , 𝑛 do:
        //  4.1 𝑡 ← 𝑡 ⊕ (𝑌𝑖 ‖ 0^{128−|𝑌𝑖|})
        //  4.2 𝑡 ← 𝑡 * 𝑟.
        self.ghash.update_padded(buffer);

        // 5. 𝑡 ← 𝑡 ⊕ (⟨|𝐼|⟩_64 ‖ ⟨|𝑋|⟩_64)
        self.ghash.xor_s(&sizes_block);

        let mut tag_exact = self.finish_tag();

        // 6. 𝑡 ← belt-block(𝑡 * 𝑟, 𝐾).
        self.mac_cipher.encrypt_block(&mut tag_exact);

        // 7. If 𝑇 != Lo(𝑡, 64), return ⊥
        if tag_exact[..8] != tag[..] {
            return Err(aead::Error);
        }

        // 8. For 𝑖 = 1,2,...,𝑛 do:
        // 8.1. 𝑠 ← 𝑠 ⊞ ⟨1⟩128;
        // 8.2. 𝑋𝑖 ← 𝑌𝑖 ⊕ Lo(belt-block(𝑠, 𝐾), |𝑌𝑖|)
        buffer.chunks_mut(16).for_each(|block| {
            self.enc_cipher.apply_keystream(block);
        });

        Ok(())
    }

    pub(crate) fn finish_tag(&mut self) -> Block<GHash> {
        self.ghash.finalize_reset()
    }
}

impl KeyInit for BeltDwp {
    fn new(key: &Key<Self>) -> Self {
        Self { key: *key }
    }
}

impl AeadCore for BeltDwp {
    type NonceSize = U16;
    type TagSize = U8;
}

/// Get the sizes block for the GHASH
fn get_sizes_block(plain_cnt: u64, sec_cnt: u64) -> Block<GHash> {
    let mut sizes_block: Block<GHash> = Default::default();

    sizes_block[..8].copy_from_slice(&plain_cnt.to_le_bytes());
    sizes_block[8..].copy_from_slice(&sec_cnt.to_le_bytes());

    sizes_block
}
