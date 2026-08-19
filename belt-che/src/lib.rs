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
//! ```
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # #[cfg(feature = "os_rng")] {
//! use belt_che::{
//!     aead::{Aead, AeadCore, KeyInit}, Nonce, BeltChe
//! };
//!
//! let key = BeltChe::generate_key().unwrap();
//! let cipher = BeltChe::new(&key);
//! let nonce = BeltChe::generate_nonce().unwrap(); // 128-bits; unique per message
//! let ciphertext = cipher.encrypt(&nonce, b"plaintext message".as_ref())?;
//! let plaintext = cipher.decrypt(&nonce, ciphertext.as_ref())?;
//! assert_eq!(&plaintext, b"plaintext message");
//! # }; Ok(()) }
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
//! ```
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # #[cfg(all(feature = "os_rng", feature = "arrayvec"))] {
//! use belt_che::{
//!     aead::{AeadInOut, KeyInit, arrayvec::ArrayVec},
//!     Nonce, BeltChe
//! };
//!
//! let key = BeltChe::generate_key().unwrap();
//! let cipher = BeltChe::new(&key);
//! let nonce = Nonce::try_from(&b"unique nonce1234"[..]).unwrap(); // 128-bits; unique per message
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
//! # }; Ok(()) }
//! ```

pub use aead::{self, AeadCore, AeadInOut, Error, Key, KeyInit, KeySizeUser, Tag};
pub use belt_block::BeltBlock;

use aead::array::ArraySize;
use aead::common::{BlockSizeUser, InnerInit, InnerUser};
use aead::consts::{True, U8, U16};
use aead::{TagPosition, inout::InOutBuf};
use belt_block::cipher::{Block, BlockCipherEncrypt};
use core::marker::PhantomData;
use polyval::hazmat::FieldElement;
use universal_hash::UniversalHash;
use universal_hash::typenum::{IsLessOrEqual, NonZero};

/// Nonce type for [`Che`]
pub type Nonce = aead::Nonce<BeltChe>;

mod ghash;

use ghash::GHash;

/// Constant `T` from the STB 34.101.31-2020
const T: u128 = 0xE45D_4A58_8E00_6D36_3BF5_080A_C8BA_94B1_u128.reverse_bits();

/// `C` = `0x02 || 0^120`, represents polynomial x
const C: u128 = 0x02_u128.reverse_bits();

/// `belt-Che` authenticated encryption with associated data (AEAD) cipher,
/// defined in STB 34.101.31-2020 (scheme 2).
pub type BeltChe = Che<BeltBlock, U8>;

/// `belt-Che` authenticated encryption with associated data (AEAD) cipher
/// defined in STB 34.101.31-2020 generic over block cipher implementation
/// and tag size.
pub struct Che<C, TagSize>
where
    C: BlockCipherEncrypt + BlockSizeUser<BlockSize = U16>,
    TagSize: ArraySize + NonZero + IsLessOrEqual<U16, Output = True>,
{
    cipher: C,
    _pd: PhantomData<TagSize>,
}

impl<C, TagSize> InnerUser for Che<C, TagSize>
where
    C: BlockCipherEncrypt + BlockSizeUser<BlockSize = U16>,
    TagSize: ArraySize + NonZero + IsLessOrEqual<U16, Output = True>,
{
    type Inner = C;
}

impl<C, TagSize> InnerInit for Che<C, TagSize>
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

impl<C, TagSize> AeadInOut for Che<C, TagSize>
where
    C: BlockCipherEncrypt + BlockSizeUser<BlockSize = U16>,
    TagSize: ArraySize + NonZero + IsLessOrEqual<U16, Output = True>,
{
    fn encrypt_inout_detached(
        &self,
        nonce: &Nonce,
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
    ) -> aead::Result<Tag<Self>> {
        let buffer_len = buffer.len();
        let sizes_block = get_sizes_block(associated_data.len(), buffer_len);

        // 2.1. 𝑠 ← belt-block(𝑆, 𝐾)
        let mut s = *nonce;
        self.cipher.encrypt_block(&mut s);

        // 2.2. 𝑟 ← 𝑠
        let r = s;

        // 2.3. 𝑡 ← T
        let mut ghash = GHash::new_with_init_block(&r, T);

        // 3. For 𝑖 = 1, 2, . . . , 𝑚 do:
        //  3.1 𝑡 ← 𝑡 ⊕ (𝐼𝑖 ‖ 0^{128−|𝐼𝑖|})
        //  3.2 𝑡 ← 𝑡 * 𝑟
        ghash.update_padded(associated_data);

        // 4. For 𝑖 = 1, 2, . . . , 𝑛 do:
        let c_element = FieldElement::from(C).mulx();
        let (chunks, mut tail) = buffer.into_chunks::<U16>();

        for mut chunk in chunks {
            // 4.1 𝑠 ← (𝑠 * 𝐶) ⊕ ⟨1⟩128
            update_che_counter(&mut s, c_element);

            // 4.2 𝑌𝑖 ← 𝑋𝑖 ⊕ Lo(belt-block(𝑠, 𝐾), |𝑋𝑖|)
            let mut keystream = s;
            self.cipher.encrypt_block(&mut keystream);
            chunk.xor_in2out(&keystream);

            // 4.3 𝑡 ← 𝑡 ⊕ (𝑌𝑖 ‖ 0^{128−|𝑌𝑖|})
            // 4.4 𝑡 ← 𝑡 * 𝑟
            ghash.update_padded(chunk.get_out());
        }

        // 4.1 𝑠 ← (𝑠 * 𝐶) ⊕ ⟨1⟩128
        update_che_counter(&mut s, c_element);

        // 4.2 𝑌𝑖 ← 𝑋𝑖 ⊕ Lo(belt-block(𝑠, 𝐾), |𝑋𝑖|)
        let mut keystream = s;
        self.cipher.encrypt_block(&mut keystream);
        tail.xor_in2out(&keystream[..tail.len()]);

        // 4.3 𝑡 ← 𝑡 ⊕ (𝑌𝑖 ‖ 0^{128−|𝑌𝑖|})
        // 4.4 𝑡 ← 𝑡 * 𝑟
        ghash.update_padded(tail.get_out());

        // 5. 𝑡 ← 𝑡 ⊕ (⟨|𝐼|⟩64 ‖ ⟨|𝑋|⟩64)
        ghash.update_padded(&sizes_block);

        // 6. 𝑡 ← belt-block(𝑡 * 𝑟, 𝐾)
        let mut tag = ghash.finalize();
        self.cipher.encrypt_block(&mut tag);

        // 7. 𝑇 ← Lo(𝑡, 64)
        let tag = &tag[..TagSize::USIZE];
        Ok(tag.try_into().expect("Tag size mismatch"))
    }

    fn decrypt_inout_detached(
        &self,
        nonce: &Nonce,
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
        tag: &Tag<Self>,
    ) -> aead::Result<()> {
        let buffer_len = buffer.len();
        let sizes_block = get_sizes_block(associated_data.len(), buffer_len);

        // 2.1. 𝑠 ← belt-block(𝑆, 𝐾)
        let mut s = *nonce;
        self.cipher.encrypt_block(&mut s);

        // 2.2. 𝑟 ← 𝑠
        let r = s;

        // 2.3. 𝑡 ← T
        let mut ghash = GHash::new_with_init_block(&r, T);

        // 3. For 𝑖 = 1, 2, . . . , 𝑚 do:
        //  3.1 𝑡 ← 𝑡 ⊕ (𝐼𝑖 ‖ 0^{128−|𝐼𝑖|})
        //  3.2 𝑡 ← 𝑡 * 𝑟
        ghash.update_padded(associated_data);

        // 4. For 𝑖 = 1, 2, . . . , 𝑛 do:
        //  4.1 𝑡 ← 𝑡 ⊕ (𝑌𝑖 ‖ 0^{128−|𝑌𝑖|})
        //  4.2 𝑡 ← 𝑡 * 𝑟
        ghash.update_padded(buffer.get_in());

        // 5. 𝑡 ← 𝑡 ⊕ (⟨|𝐼|⟩64 ‖ ⟨|𝑌|⟩64)
        ghash.update_padded(&sizes_block);

        // 6. 𝑡 ← belt-block(𝑡 * 𝑟, 𝐾)
        let mut tag_exact = ghash.finalize();
        self.cipher.encrypt_block(&mut tag_exact);

        use subtle::ConstantTimeEq;

        // 7. If 𝑇 ≠ Lo(𝑡, 64), return ⊥
        if tag_exact[..TagSize::USIZE].ct_eq(tag).into() {
            // 8. For 𝑖 = 1, 2, . . . , 𝑛 do:
            let c_element = FieldElement::from(C).mulx();
            let (chunks, mut tail) = buffer.into_chunks::<U16>();

            for mut chunk in chunks {
                // 8.1 𝑠 ← (𝑠 * 𝐶) ⊕ ⟨1⟩128
                update_che_counter(&mut s, c_element);

                // 8.2 𝑋𝑖 ← 𝑌𝑖 ⊕ Lo(belt-block(𝑠, 𝐾), |𝑌𝑖|)
                let mut keystream = s;
                self.cipher.encrypt_block(&mut keystream);
                chunk.xor_in2out(&keystream);
            }

            // 8.1 𝑠 ← (𝑠 * 𝐶) ⊕ ⟨1⟩128
            update_che_counter(&mut s, c_element);

            // 8.2 𝑋𝑖 ← 𝑌𝑖 ⊕ Lo(belt-block(𝑠, 𝐾), |𝑌𝑖|)
            let mut keystream = s;
            self.cipher.encrypt_block(&mut keystream);
            tail.xor_in2out(&keystream[..tail.len()]);

            Ok(())
        } else {
            Err(Error)
        }
    }
}

impl<C, TagSize> AeadCore for Che<C, TagSize>
where
    C: BlockCipherEncrypt + BlockSizeUser<BlockSize = U16>,
    TagSize: ArraySize + NonZero + IsLessOrEqual<U16, Output = True>,
{
    type NonceSize = C::BlockSize;
    type TagSize = TagSize;
    const TAG_POSITION: TagPosition = TagPosition::Postfix;
}

/// Updates CHE counter: s ← s * c ⊕ 0x01
#[inline(always)]
fn update_che_counter(s: &mut Block<GHash>, c: FieldElement) {
    let s_elem = FieldElement::from(ghash::convert(s)) * c;
    *s = u128::from(s_elem).reverse_bits().to_le_bytes().into();
    s[0] ^= 0x01;
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
impl<C, TagSize> zeroize::ZeroizeOnDrop for Che<C, TagSize>
where
    C: zeroize::ZeroizeOnDrop + BlockCipherEncrypt + BlockSizeUser<BlockSize = U16>,
    TagSize: ArraySize + NonZero + IsLessOrEqual<U16, Output = True>,
{
}
