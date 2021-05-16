//! [`Deoxys`] TODO

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![warn(missing_docs, rust_2018_idioms)]

pub mod deoxys_bc;
pub mod modes;

mod aes_ref;

use core::marker::PhantomData;

pub use aead;

use aead::{
    consts::{U0, U16},
    generic_array::{ArrayLength, GenericArray},
    AeadCore, AeadInPlace, Error, NewAead,
};

use zeroize::Zeroize;

pub type DeoxysI128 = Deoxys<modes::DeoxysI, deoxys_bc::DeoxysBc256>;
pub type DeoxysI256 = Deoxys<modes::DeoxysI, deoxys_bc::DeoxysBc384>;
pub type DeoxysII128 = Deoxys<modes::DeoxysII, deoxys_bc::DeoxysBc256>;
pub type DeoxysII256 = Deoxys<modes::DeoxysII, deoxys_bc::DeoxysBc384>;

pub type Key<KeySize> = GenericArray<u8, KeySize>;
pub type Tag = GenericArray<u8, U16>;

pub trait DeoxysMode<B>
where
    B: DeoxysBcType,
{
    type NonceSize: ArrayLength<u8>;

    fn encrypt_in_place(
        nonce: &[u8],
        associated_data: &[u8],
        buffer: &mut [u8],
        key: &GenericArray<u8, B::KeySize>,
    ) -> [u8; 16];

    fn decrypt_in_place(
        nonce: &[u8],
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &[u8],
        key: &GenericArray<u8, B::KeySize>,
    ) -> Result<(), aead::Error>;
}

pub trait DeoxysBcType {
    type KeySize: ArrayLength<u8>;
    type TweakKeySize: ArrayLength<u8>;

    fn encrypt_in_place(block: &mut [u8], tweakey: &GenericArray<u8, Self::TweakKeySize>);
    fn decrypt_in_place(block: &mut [u8], tweakey: &GenericArray<u8, Self::TweakKeySize>);
}

pub struct Deoxys<M, B>
where
    M: DeoxysMode<B>,
    B: DeoxysBcType,
{
    key: GenericArray<u8, B::KeySize>,
    mode: PhantomData<M>,
}

impl<M, B> NewAead for Deoxys<M, B>
where
    M: DeoxysMode<B>,
    B: DeoxysBcType,
{
    type KeySize = B::KeySize;

    fn new(key: &Key<B::KeySize>) -> Self {
        Self {
            key: key.clone(),
            mode: PhantomData,
        }
    }
}

impl<M, B> AeadCore for Deoxys<M, B>
where
    M: DeoxysMode<B>,
    B: DeoxysBcType,
{
    type NonceSize = M::NonceSize;
    type TagSize = U16;
    type CiphertextOverhead = U0;
}

impl<M, B> AeadInPlace for Deoxys<M, B>
where
    M: DeoxysMode<B>,
    B: DeoxysBcType,
{
    fn encrypt_in_place_detached(
        &self,
        nonce: &GenericArray<u8, M::NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag, Error> {
        Ok(Tag::from(M::encrypt_in_place(
            nonce.as_slice(),
            associated_data,
            buffer,
            &self.key,
        )))
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &GenericArray<u8, M::NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag,
    ) -> Result<(), Error> {
        M::decrypt_in_place(nonce, associated_data, buffer, tag, &self.key)
    }
}

impl<M, B> Drop for Deoxys<M, B>
where
    M: DeoxysMode<B>,
    B: DeoxysBcType,
{
    fn drop(&mut self) {
        self.key.as_mut_slice().zeroize();
    }
}
