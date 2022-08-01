#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![warn(missing_docs, rust_2018_idioms)]

//! # Usage Example
#![cfg_attr(all(feature = "getrandom", feature = "std"), doc = "```")]
#![cfg_attr(not(all(feature = "getrandom", feature = "std")), doc = "```ignore")]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use kuznyechik::Kuznyechik;
//! use mgm::Mgm;
//! use mgm::aead::{Aead, KeyInit, OsRng, generic_array::GenericArray};
//!
//! let key = Mgm::<Kuznyechik>::generate_key(&mut OsRng);
//! let cipher = Mgm::<Kuznyechik>::new(&key);
//!
//! // 127-bit nonce value, since API has to accept 128 bits, first nonce bit
//! // MUST be equal to zero, otherwise encryption and decryption will fail
//! let nonce = GenericArray::from_slice(b"unique nonce val");
//!
//! let ciphertext = cipher.encrypt(nonce, b"plaintext message".as_ref())?;
//! let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())?;
//!
//! assert_eq!(&plaintext, b"plaintext message");
//! # Ok(())
//! # }
//! ```

use aead::{
    consts::U0, generic_array::GenericArray, AeadCore, AeadInPlace, Error, Key, KeyInit,
    KeySizeUser,
};
use cfg_if::cfg_if;
use cipher::{BlockCipher, BlockEncrypt, NewBlockCipher};

pub use aead;

mod encdec;
mod gf;
mod sealed;

use sealed::Sealed;

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
cpufeatures::new!(mul_intrinsics, "sse2", "ssse3", "pclmulqdq");

/// MGM nonces
pub type Nonce<NonceSize> = GenericArray<u8, NonceSize>;

/// MGM tags
pub type Tag<TagSize> = GenericArray<u8, TagSize>;

type Block<C> = GenericArray<u8, <C as BlockCipher>::BlockSize>;
// cipher, nonce, aad, buffer
type EncArgs<'a, C> = (&'a C, &'a Block<C>, &'a [u8], &'a mut [u8]);
// cipher, nonce, aad, buf, expected_tag
type DecArgs<'a, C> = (&'a C, &'a Block<C>, &'a [u8], &'a mut [u8], &'a Block<C>);

/// Trait implemented for block cipher sizes usable with MGM.
// ideally we would use type level set, i.e. `U8 | U16`
pub trait MgmBlockSize: sealed::Sealed {}

impl<T: Sealed> MgmBlockSize for T {}

/// Multilinear Galous Mode cipher
#[derive(Clone, Debug)]
pub struct Mgm<C>
where
    C: BlockEncrypt,
    C::BlockSize: MgmBlockSize,
{
    cipher: C,
}

impl<C> From<C> for Mgm<C>
where
    C: BlockEncrypt,
    C::BlockSize: MgmBlockSize,
{
    fn from(cipher: C) -> Self {
        Self { cipher }
    }
}

impl<C> KeySizeUser for Mgm<C>
where
    C: BlockEncrypt + NewBlockCipher,
    C::BlockSize: MgmBlockSize,
{
    type KeySize = C::KeySize;
}

impl<C> KeyInit for Mgm<C>
where
    C: BlockEncrypt + NewBlockCipher,
    C::BlockSize: MgmBlockSize,
{
    fn new(key: &Key<Self>) -> Self {
        Self::from(C::new(key))
    }
}

impl<C> AeadCore for Mgm<C>
where
    C: BlockEncrypt,
    C::BlockSize: MgmBlockSize,
{
    type NonceSize = C::BlockSize;
    type TagSize = C::BlockSize;
    type CiphertextOverhead = U0;
}

impl<C> AeadInPlace for Mgm<C>
where
    C: BlockEncrypt,
    C::BlockSize: MgmBlockSize,
{
    fn encrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self::NonceSize>,
        adata: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag<Self::TagSize>, Error> {
        // first nonce bit must be equal to zero
        if nonce[0] >> 7 != 0 {
            return Err(Error);
        }
        mgm_encrypt((&self.cipher, nonce, adata, buffer))
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self::NonceSize>,
        adata: &[u8],
        buffer: &mut [u8],
        expected_tag: &Tag<Self::TagSize>,
    ) -> Result<(), Error> {
        // first nonce bit must be equal to zero
        if nonce[0] >> 7 != 0 {
            return Err(Error);
        }
        mgm_decrypt((&self.cipher, nonce, adata, buffer, expected_tag))
    }
}

cfg_if! {
    if #[cfg(all(
        any(target_arch = "x86_64", target_arch = "x86"),
        not(feature = "force-soft")
    ))] {
        #[target_feature(enable = "pclmulqdq")]
        #[target_feature(enable = "ssse3")]
        #[target_feature(enable = "sse2")]
        unsafe fn wrapper<R: Sized>(f: impl FnOnce() -> R) -> R {
            f()
        }
        fn mgm_encrypt<C>(args: EncArgs<'_, C>) -> Result<Block<C>, Error>
        where
            C: BlockEncrypt,
            C::BlockSize: MgmBlockSize,
        {
            if mul_intrinsics::get() {
                // SAFETY: we have checked that the required target features
                // are available
                unsafe {
                    wrapper(|| {
                        encdec::encrypt::<
                            C,
                            gf::gf64_pclmul::Element,
                            gf::gf128_pclmul::Element,
                        >(args)
                    })
                }
            } else {
                encdec::encrypt::<C, gf::gf64_soft64::Element, gf::gf128_soft64::Element>(args)
            }
        }

        fn mgm_decrypt<C>(args: DecArgs<'_, C>) -> Result<(), Error>
        where
            C: BlockEncrypt,
            C::BlockSize: MgmBlockSize,
        {
            if mul_intrinsics::get() {
                // SAFETY: we have checked that the required target features
                // are available
                unsafe {
                    wrapper(|| {
                        encdec::decrypt::<
                            C,
                            gf::gf64_pclmul::Element,
                            gf::gf128_pclmul::Element,
                        >(args)
                    })
                }
            } else {
                encdec::decrypt::<C, gf::gf64_soft64::Element, gf::gf128_soft64::Element>(args)
            }
        }
    } else {
        fn mgm_encrypt<C>(args: EncArgs<'_, C>) -> Result<Block<C>, Error>
        where
            C: BlockEncrypt,
            C::BlockSize: MgmBlockSize,
        {
            encdec::encrypt::<C, gf::gf64_soft64::Element, gf::gf128_soft64::Element>(args)
        }

        fn mgm_decrypt<C>(args: DecArgs<'_, C>) -> Result<(), Error>
        where
            C: BlockEncrypt,
            C::BlockSize: MgmBlockSize,
        {
            encdec::decrypt::<C, gf::gf64_soft64::Element, gf::gf128_soft64::Element>(args)
        }
    }
}
