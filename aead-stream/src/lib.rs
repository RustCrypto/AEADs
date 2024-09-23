#![no_std]
#![doc = include_str!("../README.md")]
#![allow(clippy::upper_case_acronyms)]

#[cfg(feature = "alloc")]
extern crate alloc;

use aead::array::{
    typenum::{Unsigned, U4, U5},
    Array, ArraySize,
};
use aead::{AeadCore, AeadInPlace, Buffer, Error, Result};
use core::ops::Sub;

pub use aead;

pub use aead::{
    stream::{Decryptor, Encryptor, NewStream, StreamPrimitive},
    Key, KeyInit,
};

/// Nonce as used by a given AEAD construction and STREAM primitive.
pub type Nonce<A, S> = Array<u8, NonceSize<A, S>>;

/// Size of a nonce as used by a STREAM construction, sans the overhead of
/// the STREAM protocol itself.
pub type NonceSize<A, S> =
    <<A as AeadCore>::NonceSize as Sub<<S as StreamPrimitive<A>>::NonceOverhead>>::Output;

/// STREAM encryptor instantiated with [`StreamBE32`] as the underlying
/// STREAM primitive.
pub type EncryptorBE32<A> = Encryptor<A, StreamBE32<A>>;

/// STREAM decryptor instantiated with [`StreamBE32`] as the underlying
/// STREAM primitive.
pub type DecryptorBE32<A> = Decryptor<A, StreamBE32<A>>;

/// STREAM encryptor instantiated with [`StreamLE31`] as the underlying
/// STREAM primitive.
pub type EncryptorLE31<A> = Encryptor<A, StreamLE31<A>>;

/// STREAM decryptor instantiated with [`StreamLE31`] as the underlying
/// STREAM primitive.
pub type DecryptorLE31<A> = Decryptor<A, StreamLE31<A>>;

/// The original "Rogaway-flavored" STREAM as described in the paper
/// [Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance][1].
///
/// Uses a 32-bit big endian counter and 1-byte "last block" flag stored as
/// the last 5-bytes of the AEAD nonce.
///
/// [1]: https://eprint.iacr.org/2015/189.pdf
#[derive(Debug)]
pub struct StreamBE32<A>
where
    A: AeadInPlace,
    A::NonceSize: Sub<U5>,
    <<A as AeadCore>::NonceSize as Sub<U5>>::Output: ArraySize,
{
    /// Underlying AEAD cipher
    aead: A,

    /// Nonce (sans STREAM overhead)
    nonce: Nonce<A, Self>,
}

impl<A> NewStream<A> for StreamBE32<A>
where
    A: AeadInPlace,
    A::NonceSize: Sub<U5>,
    <<A as AeadCore>::NonceSize as Sub<U5>>::Output: ArraySize,
{
    fn from_aead(aead: A, nonce: &Nonce<A, Self>) -> Self {
        Self {
            aead,
            nonce: nonce.clone(),
        }
    }
}

impl<A> StreamPrimitive<A> for StreamBE32<A>
where
    A: AeadInPlace,
    A::NonceSize: Sub<U5>,
    <<A as AeadCore>::NonceSize as Sub<U5>>::Output: ArraySize,
{
    type NonceOverhead = U5;
    type Counter = u32;
    const COUNTER_INCR: u32 = 1;
    const COUNTER_MAX: u32 = u32::MAX;

    fn encrypt_in_place(
        &self,
        position: u32,
        last_block: bool,
        associated_data: &[u8],
        buffer: &mut dyn Buffer,
    ) -> Result<()> {
        let nonce = self.aead_nonce(position, last_block);
        self.aead.encrypt_in_place(&nonce, associated_data, buffer)
    }

    fn decrypt_in_place(
        &self,
        position: Self::Counter,
        last_block: bool,
        associated_data: &[u8],
        buffer: &mut dyn Buffer,
    ) -> Result<()> {
        let nonce = self.aead_nonce(position, last_block);
        self.aead.decrypt_in_place(&nonce, associated_data, buffer)
    }
}

impl<A> StreamBE32<A>
where
    A: AeadInPlace,
    A::NonceSize: Sub<U5>,
    <<A as AeadCore>::NonceSize as Sub<U5>>::Output: ArraySize,
{
    /// Compute the full AEAD nonce including the STREAM counter and last
    /// block flag.
    fn aead_nonce(&self, position: u32, last_block: bool) -> aead::Nonce<A> {
        let mut result = Array::default();

        // TODO(tarcieri): use `generic_array::sequence::Concat` (or const generics)
        let (prefix, tail) = result.split_at_mut(NonceSize::<A, Self>::to_usize());
        prefix.copy_from_slice(&self.nonce);

        let (counter, flag) = tail.split_at_mut(4);
        counter.copy_from_slice(&position.to_be_bytes());
        flag[0] = last_block as u8;

        result
    }
}

/// STREAM as instantiated with a 31-bit little endian counter and 1-bit
/// "last block" flag stored as the most significant bit of the counter
/// when interpreted as a 32-bit integer.
///
/// The 31-bit + 1-bit value is stored as the last 4 bytes of the AEAD nonce.
#[derive(Debug)]
pub struct StreamLE31<A>
where
    A: AeadInPlace,
    A::NonceSize: Sub<U4>,
    <<A as AeadCore>::NonceSize as Sub<U4>>::Output: ArraySize,
{
    /// Underlying AEAD cipher
    aead: A,

    /// Nonce (sans STREAM overhead)
    nonce: Nonce<A, Self>,
}

impl<A> NewStream<A> for StreamLE31<A>
where
    A: AeadInPlace,
    A::NonceSize: Sub<U4>,
    <<A as AeadCore>::NonceSize as Sub<U4>>::Output: ArraySize,
{
    fn from_aead(aead: A, nonce: &Nonce<A, Self>) -> Self {
        Self {
            aead,
            nonce: nonce.clone(),
        }
    }
}

impl<A> StreamPrimitive<A> for StreamLE31<A>
where
    A: AeadInPlace,
    A::NonceSize: Sub<U4>,
    <<A as AeadCore>::NonceSize as Sub<U4>>::Output: ArraySize,
{
    type NonceOverhead = U4;
    type Counter = u32;
    const COUNTER_INCR: u32 = 1;
    const COUNTER_MAX: u32 = 0xfff_ffff;

    fn encrypt_in_place(
        &self,
        position: u32,
        last_block: bool,
        associated_data: &[u8],
        buffer: &mut dyn Buffer,
    ) -> Result<()> {
        let nonce = self.aead_nonce(position, last_block)?;
        self.aead.encrypt_in_place(&nonce, associated_data, buffer)
    }

    fn decrypt_in_place(
        &self,
        position: Self::Counter,
        last_block: bool,
        associated_data: &[u8],
        buffer: &mut dyn Buffer,
    ) -> Result<()> {
        let nonce = self.aead_nonce(position, last_block)?;
        self.aead.decrypt_in_place(&nonce, associated_data, buffer)
    }
}

impl<A> StreamLE31<A>
where
    A: AeadInPlace,
    A::NonceSize: Sub<U4>,
    <<A as AeadCore>::NonceSize as Sub<U4>>::Output: ArraySize,
{
    /// Compute the full AEAD nonce including the STREAM counter and last
    /// block flag.
    fn aead_nonce(&self, position: u32, last_block: bool) -> Result<aead::Nonce<A>> {
        if position > Self::COUNTER_MAX {
            return Err(Error);
        }

        let mut result = Array::default();

        // TODO(tarcieri): use `generic_array::sequence::Concat` (or const generics)
        let (prefix, tail) = result.split_at_mut(NonceSize::<A, Self>::to_usize());
        prefix.copy_from_slice(&self.nonce);

        let position_with_flag = position | ((last_block as u32) << 31);
        tail.copy_from_slice(&position_with_flag.to_le_bytes());

        Ok(result)
    }
}
