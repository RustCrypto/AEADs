#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![warn(missing_docs)]

//! # Usage
//!
//! Simple usage (allocating, no associated data):
//!
#![cfg_attr(feature = "getrandom", doc = "```")]
#![cfg_attr(not(feature = "getrandom"), doc = "```ignore")]
//! # fn main() -> Result<(), Box<dyn core::error::Error>> {
//! use belt_dwp::{
//!     aead::{Aead, AeadCore, Generate, Key, KeyInit},
//!     BeltDwp, Nonce
//! };
//!
//! let key = Key::<BeltDwp>::generate();
//! let cipher = BeltDwp::new(&key);
//! let nonce = Nonce::generate(); // 128-bits; MUST be unique per message
//! let ciphertext = cipher.encrypt(&nonce, b"plaintext message".as_ref())?;
//! let plaintext = cipher.decrypt(&nonce, ciphertext.as_ref())?;
//! assert_eq!(&plaintext, b"plaintext message");
//! # Ok(()) }
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
//! Enabling the `arrayvec` feature of this crate will provide an impl of
//! [`aead::Buffer`] for `arrayvec::ArrayVec` (re-exported from the [`aead`] crate as
//! [`aead::arrayvec::ArrayVec`]).
//!
//! It can then be passed as the `buffer` parameter to the in-place encrypt
//! and decrypt methods:
//!
#![cfg_attr(all(feature = "getrandom", feature = "arrayvec"), doc = "```")]
#![cfg_attr(
    not(all(feature = "getrandom", feature = "arrayvec")),
    doc = "```ignore"
)]
//! # fn main() -> Result<(), Box<dyn core::error::Error>> {
//! use belt_dwp::{
//!     aead::{AeadInOut, Generate, Key, KeyInit, arrayvec::ArrayVec},
//!     BeltDwp, Nonce
//! };
//!
//! let key = Key::<BeltDwp>::generate();
//! let cipher = BeltDwp::new(&key);
//! let nonce = Nonce::generate(); // 128-bits; MUST be unique per message
//!
//! let mut buffer: ArrayVec<u8, 128> = ArrayVec::new(); // Note: buffer needs 16-bytes overhead for auth tag
//! buffer.try_extend_from_slice(b"plaintext message").unwrap();
//!
//! // Encrypt `buffer` in-place, replacing the plaintext contents with ciphertext
//! cipher.encrypt_in_place(&nonce, b"", &mut buffer)?;
//!
//! // `buffer` now contains the message ciphertext
//! assert_ne!(buffer.as_ref(), b"plaintext message");
//!
//! // Decrypt `buffer` in-place, replacing its ciphertext context with the original plaintext
//! cipher.decrypt_in_place(&nonce, b"", &mut buffer)?;
//! assert_eq!(buffer.as_ref(), b"plaintext message");
//! # Ok(()) }
//! ```

pub use aead::{self, AeadCore, AeadInOut, Error, Key, KeyInit, KeySizeUser, Tag};
pub use belt_block::BeltBlock;

use aead::array::ArraySize;
use aead::consts::{True, U8, U16};
use aead::{TagPosition, inout::InOutBuf};
use belt_block::cipher::crypto_common::InnerUser;
use belt_block::cipher::{Block, BlockCipherEncrypt, StreamCipher};
use belt_ctr::cipher::InnerIvInit;
use belt_ctr::{BeltCtr, BeltCtrCore};
use core::marker::PhantomData;
use universal_hash::UniversalHash;
use universal_hash::crypto_common::{BlockSizeUser, InnerInit};
use universal_hash::typenum::{IsLessOrEqual, NonZero};

/// Nonce type for [`Dwp`]
pub type Nonce = aead::Nonce<BeltDwp>;

mod gf;
mod ghash;

use ghash::GHash;

/// Constant `T` from the STB 34.101.31-2020
const T: u128 = 0xE45D_4A58_8E00_6D36_3BF5_080A_C8BA_94B1;

/// `belt-dwp` authenticated encryption with associated data (AEAD) cipher,
/// defined in STB 34.101.31-2020.
pub type BeltDwp = Dwp<BeltBlock, U8>;

/// `belt-dwp` authenticated encryption with associated data (AEAD) cipher
/// defined in STB 34.101.31-2020 generic over block cipher implementation
/// and tag size.
pub struct Dwp<C, TagSize>
where
    C: BlockCipherEncrypt + BlockSizeUser<BlockSize = U16>,
    TagSize: ArraySize + NonZero + IsLessOrEqual<U16, Output = True>,
{
    cipher: C,
    _pd: PhantomData<TagSize>,
}

impl<C, TagSize> InnerUser for Dwp<C, TagSize>
where
    C: BlockCipherEncrypt + BlockSizeUser<BlockSize = U16>,
    TagSize: ArraySize + NonZero + IsLessOrEqual<U16, Output = True>,
{
    type Inner = C;
}

impl<C, TagSize> InnerInit for Dwp<C, TagSize>
where
    C: BlockCipherEncrypt + BlockSizeUser<BlockSize = U16>,
    TagSize: ArraySize + NonZero + IsLessOrEqual<U16, Output = True>,
{
    fn inner_init(cipher: Self::Inner) -> Self {
        Self {
            cipher,
            _pd: PhantomData,
        }
    }
}

impl<C, TagSize> AeadInOut for Dwp<C, TagSize>
where
    C: BlockCipherEncrypt + BlockSizeUser<BlockSize = U16>,
    TagSize: ArraySize + NonZero + IsLessOrEqual<U16, Output = True>,
{
    fn encrypt_inout_detached(
        &self,
        nonce: &Nonce,
        associated_data: &[u8],
        mut buffer: InOutBuf<'_, '_, u8>,
    ) -> aead::Result<Tag<Self>> {
        let sizes_block = get_sizes_block(associated_data.len(), buffer.len());

        // 2.1. 𝑠 ← belt-block(𝑆, 𝐾);
        let mut s = *nonce;
        self.cipher.encrypt_block(&mut s);

        // 2.2. 𝑟 ← belt-block(𝑠, 𝐾);
        let mut r = s;
        self.cipher.encrypt_block(&mut r);

        // Initialize GHash
        let mut ghash = GHash::new_with_init_block(&r, T);

        // Initialize CTR mode
        let core = BeltCtrCore::inner_iv_init(&self.cipher, nonce);
        let mut enc_cipher = BeltCtr::from_core(core);

        // 3. For 𝑖 = 1, 2, . . . , 𝑚 do:
        //  3.1 𝑡 ← 𝑡 ⊕ (𝐼𝑖 ‖ 0^{128−|𝐼𝑖|})
        //  3.2 𝑡 ← 𝑡 * 𝑟.
        ghash.update_padded(associated_data);

        // 4. For 𝑖 = 1, 2, . . . , 𝑛 do:
        //  4.1 𝑠 ← 𝑠 ⊞ ⟨1⟩_128
        //  4.2 𝑌𝑖 ← 𝑋𝑖 ⊕ Lo(belt-block(𝑠, 𝐾), |𝑋𝑖|)
        //  4.3 𝑡 ← 𝑡 ⊕ (𝑌𝑖 ‖ 0^{128−|𝑌𝑖|})
        //  4.4 𝑡 ← 𝑡 * 𝑟.
        enc_cipher.apply_keystream_inout(buffer.reborrow());
        ghash.update_padded(buffer.get_out());

        // 5. 𝑡 ← 𝑡 ⊕ (⟨|𝐼|⟩_64 ‖ ⟨|𝑋|⟩_64)
        ghash.update_padded(&sizes_block);

        // 6. 𝑡 ← belt-block(𝑡 * 𝑟, 𝐾).
        let mut tag = ghash.finalize_reset();
        self.cipher.encrypt_block(&mut tag);

        let tag = &tag[..TagSize::USIZE];
        Ok(tag.try_into().expect("Tag is always 8 bytes"))
    }

    fn decrypt_inout_detached(
        &self,
        nonce: &Nonce,
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
        tag: &Tag<Self>,
    ) -> aead::Result<()> {
        let sizes_block = get_sizes_block(associated_data.len(), buffer.len());

        // 2.1. 𝑠 ← belt-block(𝑆, 𝐾);
        let mut s = *nonce;
        self.cipher.encrypt_block(&mut s);

        // 2.2. 𝑟 ← belt-block(𝑠, 𝐾);
        let mut r = s;
        self.cipher.encrypt_block(&mut r);

        // Initialize GHash
        let mut ghash = GHash::new_with_init_block(&r, T);

        // 3. For 𝑖 = 1, 2, . . . , 𝑚 do:
        //  3.1 𝑡 ← 𝑡 ⊕ (𝐼𝑖 ‖ 0^{128−|𝐼𝑖|})
        //  3.2 𝑡 ← 𝑡 * 𝑟.
        ghash.update_padded(associated_data);

        // 4. For 𝑖 = 1, 2, . . . , 𝑛 do:
        //  4.1 𝑡 ← 𝑡 ⊕ (𝑌𝑖 ‖ 0^{128−|𝑌𝑖|})
        //  4.2 𝑡 ← 𝑡 * 𝑟.
        ghash.update_padded(buffer.get_in());

        // 5. 𝑡 ← 𝑡 ⊕ (⟨|𝐼|⟩_64 ‖ ⟨|𝑋|⟩_64)
        ghash.update_padded(&sizes_block);

        // 6. 𝑡 ← belt-block(𝑡 * 𝑟, 𝐾).
        let mut tag_exact = ghash.finalize_reset();
        self.cipher.encrypt_block(&mut tag_exact);

        use subtle::ConstantTimeEq;
        // 7. If 𝑇 != Lo(𝑡, 64), return ⊥
        if tag_exact[..TagSize::USIZE].ct_eq(tag).into() {
            // 8. For 𝑖 = 1,2,...,𝑛 do:
            // 8.1. 𝑠 ← 𝑠 ⊞ ⟨1⟩128;
            // 8.2. 𝑋𝑖 ← 𝑌𝑖 ⊕ Lo(belt-block(𝑠, 𝐾), |𝑌𝑖|)
            let core = BeltCtrCore::inner_iv_init(&self.cipher, nonce);
            let mut enc_cipher = BeltCtr::from_core(core);
            enc_cipher.apply_keystream_inout(buffer);
            Ok(())
        } else {
            Err(Error)
        }
    }
}

impl<C, TagSize> AeadCore for Dwp<C, TagSize>
where
    C: BlockCipherEncrypt + BlockSizeUser<BlockSize = U16>,
    TagSize: ArraySize + NonZero + IsLessOrEqual<U16, Output = True>,
{
    type NonceSize = C::BlockSize;
    type TagSize = TagSize;
    const TAG_POSITION: TagPosition = TagPosition::Postfix;
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
impl<C, TagSize> zeroize::ZeroizeOnDrop for Dwp<C, TagSize>
where
    C: zeroize::ZeroizeOnDrop + BlockCipherEncrypt + BlockSizeUser<BlockSize = U16>,
    TagSize: ArraySize + NonZero + IsLessOrEqual<U16, Output = True>,
{
}
