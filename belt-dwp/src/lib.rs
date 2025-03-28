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
//!     aead::{Aead, AeadCore, KeyInit},
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
//!     aead::{AeadInPlace, AeadInPlaceDetached, KeyInit, heapless::Vec},
//!     BeltDwp, Nonce
//! };
//!
//! let key = BeltDwp::generate_key().unwrap();
//! let cipher = BeltDwp::new(&key);
//! let nonce = Nonce::try_from(&b"unique nonce1234"[..]).unwrap(); // 128-bits; unique per message
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
//! [`aead::arrayvec::ArrayVec`]).

use aead::consts::{U8, U16, U32};
pub use aead::{self, AeadCore, AeadInPlace, Error, Key, KeyInit, KeySizeUser};
use aead::{AeadInPlaceDetached, PostfixTagged};
use belt_block::BeltBlock;
use belt_block::cipher::{Block, BlockCipherEncrypt, StreamCipher};
use belt_ctr::cipher::InnerIvInit;
use belt_ctr::{BeltCtr, BeltCtrCore};
use universal_hash::UniversalHash;

use crate::ghash::GHash;

/// Nonce type for [`BeltDwp`]
pub type Nonce = aead::Nonce<BeltDwp>;

/// Tag type for [`BeltDwp`]
pub type Tag = aead::Tag<BeltDwp>;

mod gf;
mod ghash;

/// T from the STB 34.101.31-2020
const T: u128 = 0xE45D_4A58_8E00_6D36_3BF5_080A_C8BA_94B1;

/// Belt-DWP authenticated encryption with associated data (AEAD) cipher, defined in
/// STB 34.101.31-2020
pub struct BeltDwp {
    backend: BeltBlock,
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
        Cipher::new(self.backend.clone(), nonce).encrypt_in_place_detached(associated_data, buffer)
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &Nonce,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag,
    ) -> aead::Result<()> {
        Cipher::new(self.backend.clone(), nonce).decrypt_in_place_detached(
            associated_data,
            buffer,
            tag,
        )
    }
}

impl PostfixTagged for BeltDwp {}

struct Cipher {
    enc_cipher: BeltCtr,
    mac_cipher: BeltBlock,
    ghash: GHash,
}

impl Cipher {
    fn new(enc_cipher: BeltBlock, nonce: &Nonce) -> Self {
        let core = BeltCtrCore::inner_iv_init(enc_cipher.clone(), nonce);

        // 2.1. 𝑠 ← belt-block(𝑆, 𝐾);
        let mut s = *nonce;
        enc_cipher.encrypt_block(&mut s);

        // 2.2. 𝑟 ← belt-block(𝑠, 𝐾);
        let mut r = s;
        enc_cipher.encrypt_block(&mut r);

        Self {
            enc_cipher: BeltCtr::from_core(core),
            mac_cipher: enc_cipher,
            ghash: GHash::new_with_init_block(
                &Key::<GHash>::try_from(&r[..]).expect("Key is always 16 bytes"),
                T,
            ),
        }
    }

    fn encrypt_in_place_detached(
        &mut self,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> aead::Result<Tag> {
        let sizes_block = get_sizes_block(associated_data.len(), buffer.len());

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

        Ok(Tag::try_from(&tag[..8]).expect("Tag is always 8 bytes"))
    }

    fn decrypt_in_place_detached(
        &mut self,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag,
    ) -> aead::Result<()> {
        let sizes_block = get_sizes_block(associated_data.len(), buffer.len());

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

        use subtle::ConstantTimeEq;
        // 7. If 𝑇 != Lo(𝑡, 64), return ⊥
        if tag_exact[..8].ct_eq(tag).into() {
            // 8. For 𝑖 = 1,2,...,𝑛 do:
            // 8.1. 𝑠 ← 𝑠 ⊞ ⟨1⟩128;
            // 8.2. 𝑋𝑖 ← 𝑌𝑖 ⊕ Lo(belt-block(𝑠, 𝐾), |𝑌𝑖|)
            self.enc_cipher.apply_keystream(buffer);
            Ok(())
        } else {
            Err(Error)
        }
    }

    pub(crate) fn finish_tag(&mut self) -> Block<GHash> {
        self.ghash.finalize_reset()
    }
}

impl KeyInit for BeltDwp {
    fn new(key: &Key<Self>) -> Self {
        Self {
            backend: BeltBlock::new(key),
        }
    }
}

impl AeadCore for BeltDwp {
    type NonceSize = U16;
    type TagSize = U8;
}

/// Get the sizes block for the GHASH
fn get_sizes_block(aad_len: usize, msg_len: usize) -> Block<GHash> {
    let aad_bit_len = aad_len as u64 * 8;
    let msg_bit_len = msg_len as u64 * 8;

    let mut sizes_block: Block<GHash> = Default::default();

    sizes_block[..8].copy_from_slice(&aad_bit_len.to_le_bytes());
    sizes_block[8..].copy_from_slice(&msg_bit_len.to_le_bytes());

    sizes_block
}

#[cfg(feature = "zeroize")]
impl zeroize::ZeroizeOnDrop for BeltDwp {}
