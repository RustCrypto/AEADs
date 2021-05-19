use core::marker::PhantomData;

use aead::{
    consts::{U15, U16, U8},
    generic_array::typenum::Unsigned,
    generic_array::GenericArray,
};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use super::DeoxysBcType;
use super::DeoxysMode;

const TWEAK_AD: u8 = 0x20;
const TWEAK_AD_LAST: u8 = 0x60;
const TWEAK_M: u8 = 0x00;
const TWEAK_TAG: u8 = 0x10;
const TWEAK_M_LAST: u8 = 0x40;
const TWEAK_CHKSUM: u8 = 0x50;

/// Implementation of the Deoxys-I mode of operation.
pub struct DeoxysI<B> {
    _ptr: PhantomData<B>,
}

/// Implementation of the Deoxys-II mode of operation.
#[allow(clippy::upper_case_acronyms)]
pub struct DeoxysII<B> {
    _ptr: PhantomData<B>,
}

pub trait DeoxysModeInternal<B>
where
    B: DeoxysBcType,
{
    fn compute_ad_tag(
        associated_data: &[u8],
        tweakey: &mut GenericArray<u8, B::TweakKeySize>,
        tag: &mut [u8],
    ) {
        if !associated_data.is_empty() {
            tweakey[B::KeySize::to_usize()] = TWEAK_AD;

            for (index, ad) in associated_data.chunks(16).enumerate() {
                // Copy block number
                tweakey[B::KeySize::to_usize() + 8..]
                    .copy_from_slice(&(index as u64).to_be_bytes());

                if ad.len() == 16 {
                    let mut block = [0u8; 16];
                    block.copy_from_slice(ad);

                    B::encrypt_in_place(&mut block, &tweakey);

                    for (t, b) in tag.iter_mut().zip(block.iter()) {
                        *t ^= b;
                    }
                } else {
                    // Last block
                    tweakey[B::KeySize::to_usize()] = TWEAK_AD_LAST;

                    let mut block = [0u8; 16];
                    block[0..ad.len()].copy_from_slice(ad);

                    block[ad.len()] = 0x80;

                    B::encrypt_in_place(&mut block, &tweakey);

                    for (t, b) in tag.iter_mut().zip(block.iter()) {
                        *t ^= b;
                    }
                }
            }
        }
    }
}

impl<B> DeoxysModeInternal<B> for DeoxysI<B> where B: DeoxysBcType {}

impl<B> DeoxysModeInternal<B> for DeoxysII<B> where B: DeoxysBcType {}

impl<B> DeoxysMode<B> for DeoxysI<B>
where
    B: DeoxysBcType,
{
    type NonceSize = U8;

    fn encrypt_in_place(
        nonce: &GenericArray<u8, Self::NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
        key: &GenericArray<u8, B::KeySize>,
    ) -> [u8; 16] {
        let mut tag = [0u8; 16];
        let mut checksum = [0u8; 16];
        let mut tweakey = GenericArray::<u8, B::TweakKeySize>::default();

        tweakey[..B::KeySize::to_usize()].copy_from_slice(&key);

        // Associated Data
        <Self as DeoxysModeInternal<B>>::compute_ad_tag(associated_data, &mut tweakey, &mut tag);

        // Add the nonce to the tweak
        tweakey[B::KeySize::to_usize()] = nonce[0] >> 4;
        for i in 1..nonce.len() {
            tweakey[B::KeySize::to_usize() + i] = (nonce[i - 1] << 4) | (nonce[i] >> 4);
        }

        tweakey[B::KeySize::to_usize() + 8] = nonce[7] << 4;

        // Message authentication and encryption
        if !buffer.is_empty() {
            tweakey[B::KeySize::to_usize()] = (tweakey[B::KeySize::to_usize()] & 0xf) | TWEAK_M;

            for (index, data) in buffer.chunks_mut(16).enumerate() {
                // Copy block number
                let tmp = tweakey[B::KeySize::to_usize() + 8] & 0xf0;
                tweakey[B::KeySize::to_usize() + 8..]
                    .copy_from_slice(&(index as u64).to_be_bytes());
                tweakey[B::KeySize::to_usize() + 8] =
                    (tweakey[B::KeySize::to_usize() + 8] & 0xf) | tmp;

                if data.len() == 16 {
                    for (c, d) in checksum.iter_mut().zip(data.iter()) {
                        *c ^= d;
                    }

                    B::encrypt_in_place(data, &tweakey);
                } else {
                    // Last block checksum
                    tweakey[B::KeySize::to_usize()] =
                        (tweakey[B::KeySize::to_usize()] & 0xf) | TWEAK_M_LAST;

                    let mut block = [0u8; 16];
                    block[0..data.len()].copy_from_slice(data);

                    block[data.len()] = 0x80;

                    for (c, d) in checksum.iter_mut().zip(block.iter()) {
                        *c ^= d;
                    }

                    block.fill(0);

                    // Last block encryption
                    B::encrypt_in_place(&mut block, &tweakey);

                    for (d, b) in data.iter_mut().zip(block.iter()) {
                        *d ^= b;
                    }

                    // Tag computing.
                    tweakey[B::KeySize::to_usize()] =
                        (tweakey[B::KeySize::to_usize()] & 0xf) | TWEAK_CHKSUM;

                    let tmp = tweakey[B::KeySize::to_usize() + 8] & 0xf0;
                    tweakey[B::KeySize::to_usize() + 8..]
                        .copy_from_slice(&((index + 1) as u64).to_be_bytes());
                    tweakey[B::KeySize::to_usize() + 8] =
                        (tweakey[B::KeySize::to_usize() + 8] & 0xf) | tmp;

                    B::encrypt_in_place(&mut checksum, &tweakey);

                    for (t, c) in tag.iter_mut().zip(checksum.iter()) {
                        *t ^= c;
                    }
                }
            }
        }

        if buffer.len() % 16 == 0 {
            // Tag computing without last block
            tweakey[B::KeySize::to_usize()] = (tweakey[B::KeySize::to_usize()] & 0xf) | TWEAK_TAG;

            let tmp = tweakey[B::KeySize::to_usize() + 8] & 0xf0;
            tweakey[B::KeySize::to_usize() + 8..]
                .copy_from_slice(&((buffer.len() / 16) as u64).to_be_bytes());
            tweakey[B::KeySize::to_usize() + 8] = (tweakey[B::KeySize::to_usize() + 8] & 0xf) | tmp;

            B::encrypt_in_place(&mut checksum, &tweakey);

            for (t, c) in tag.iter_mut().zip(checksum.iter()) {
                *t ^= c;
            }
        }

        // Zeroize tweakey since it contains the key
        tweakey.zeroize();
        tag
    }

    fn decrypt_in_place(
        nonce: &GenericArray<u8, Self::NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &GenericArray<u8, U16>,
        key: &GenericArray<u8, B::KeySize>,
    ) -> Result<(), aead::Error> {
        let mut computed_tag = [0u8; 16];
        let mut checksum = [0u8; 16];
        let mut tweakey = GenericArray::<u8, B::TweakKeySize>::default();

        tweakey[..B::KeySize::to_usize()].copy_from_slice(&key);

        // Associated Data
        <Self as DeoxysModeInternal<B>>::compute_ad_tag(
            associated_data,
            &mut tweakey,
            &mut computed_tag,
        );

        // Add the nonce to the tweak
        tweakey[B::KeySize::to_usize()] = nonce[0] >> 4;
        for i in 1..nonce.len() {
            tweakey[B::KeySize::to_usize() + i] = (nonce[i - 1] << 4) | (nonce[i] >> 4);
        }

        tweakey[B::KeySize::to_usize() + 8] = nonce[7] << 4;

        // Message authentication and encryption
        if !buffer.is_empty() {
            tweakey[B::KeySize::to_usize()] = (tweakey[B::KeySize::to_usize()] & 0xf) | TWEAK_M;

            for (index, data) in buffer.chunks_mut(16).enumerate() {
                // Copy block number
                let tmp = tweakey[B::KeySize::to_usize() + 8] & 0xf0;
                tweakey[B::KeySize::to_usize() + 8..]
                    .copy_from_slice(&(index as u64).to_be_bytes());
                tweakey[B::KeySize::to_usize() + 8] =
                    (tweakey[B::KeySize::to_usize() + 8] & 0xf) | tmp;

                if data.len() == 16 {
                    B::decrypt_in_place(data, &tweakey);

                    for (c, d) in checksum.iter_mut().zip(data.iter()) {
                        *c ^= d;
                    }
                } else {
                    // Last block checksum
                    tweakey[B::KeySize::to_usize()] =
                        (tweakey[B::KeySize::to_usize()] & 0xf) | TWEAK_M_LAST;

                    let mut block = [0u8; 16];
                    B::encrypt_in_place(&mut block, &tweakey);

                    for (d, b) in data.iter_mut().zip(block.iter()) {
                        *d ^= b;
                    }

                    block.fill(0);

                    block[0..data.len()].copy_from_slice(data);
                    block[data.len()] = 0x80;

                    for (c, d) in checksum.iter_mut().zip(block.iter()) {
                        *c ^= d;
                    }

                    // Tag computing.
                    tweakey[B::KeySize::to_usize()] =
                        (tweakey[B::KeySize::to_usize()] & 0xf) | TWEAK_CHKSUM;

                    let tmp = tweakey[B::KeySize::to_usize() + 8] & 0xf0;
                    tweakey[B::KeySize::to_usize() + 8..]
                        .copy_from_slice(&((index + 1) as u64).to_be_bytes());
                    tweakey[B::KeySize::to_usize() + 8] =
                        (tweakey[B::KeySize::to_usize() + 8] & 0xf) | tmp;

                    B::encrypt_in_place(&mut checksum, &tweakey);

                    for (t, c) in computed_tag.iter_mut().zip(checksum.iter()) {
                        *t ^= c;
                    }
                }
            }
        }

        if buffer.len() % 16 == 0 {
            // Tag computing without last block
            tweakey[B::KeySize::to_usize()] = (tweakey[B::KeySize::to_usize()] & 0xf) | TWEAK_TAG;

            let tmp = tweakey[B::KeySize::to_usize() + 8] & 0xf0;
            tweakey[B::KeySize::to_usize() + 8..]
                .copy_from_slice(&((buffer.len() / 16) as u64).to_be_bytes());
            tweakey[B::KeySize::to_usize() + 8] = (tweakey[B::KeySize::to_usize() + 8] & 0xf) | tmp;

            B::encrypt_in_place(&mut checksum, &tweakey);

            for (t, c) in computed_tag.iter_mut().zip(checksum.iter()) {
                *t ^= c;
            }
        }

        // Zeroize tweakey since it contains the key
        tweakey.zeroize();

        if tag.ct_eq(&computed_tag).into() {
            Ok(())
        } else {
            Err(aead::Error)
        }
    }
}

impl<B> DeoxysII<B>
where
    B: DeoxysBcType,
{
    fn authenticate_message(
        buffer: &[u8],
        tweakey: &mut GenericArray<u8, B::TweakKeySize>,
        tag: &mut [u8; 16],
    ) {
        if !buffer.is_empty() {
            tweakey[B::KeySize::to_usize()] = TWEAK_M;

            for (index, data) in buffer.chunks(16).enumerate() {
                // Copy block number
                tweakey[B::KeySize::to_usize() + 8..]
                    .copy_from_slice(&(index as u64).to_be_bytes());

                if data.len() == 16 {
                    let mut block = [0u8; 16];
                    block.copy_from_slice(data);

                    B::encrypt_in_place(&mut block, &tweakey);

                    for (t, b) in tag.iter_mut().zip(block.iter()) {
                        *t ^= b;
                    }
                } else {
                    // Last block
                    tweakey[B::KeySize::to_usize()] = TWEAK_M_LAST;

                    let mut block = [0u8; 16];
                    block[0..data.len()].copy_from_slice(data);

                    block[data.len()] = 0x80;

                    B::encrypt_in_place(&mut block, &tweakey);

                    for (t, b) in tag.iter_mut().zip(block.iter()) {
                        *t ^= b;
                    }
                }
            }
        }
    }

    fn encrypt_decrypt_message(
        buffer: &mut [u8],
        tweakey: &mut GenericArray<u8, B::TweakKeySize>,
        tag: &GenericArray<u8, U16>,
        nonce: &GenericArray<u8, U15>,
    ) {
        if !buffer.is_empty() {
            tweakey[B::KeySize::to_usize()..].copy_from_slice(tag);
            tweakey[B::KeySize::to_usize()] |= 0x80;

            for (index, data) in buffer.chunks_mut(16).enumerate() {
                let index_array = (index as u64).to_be_bytes();

                // XOR in block numbers
                for (t, i) in tweakey[B::KeySize::to_usize() + 8..]
                    .iter_mut()
                    .zip(&index_array)
                {
                    *t ^= i
                }

                let mut block = [0u8; 16];
                block[1..].copy_from_slice(nonce);

                B::encrypt_in_place(&mut block, &tweakey);

                for (t, b) in data.iter_mut().zip(block.iter()) {
                    *t ^= b;
                }

                // XOR out block numbers
                for (t, i) in tweakey[B::KeySize::to_usize() + 8..]
                    .iter_mut()
                    .zip(&index_array)
                {
                    *t ^= i
                }
            }
        }
    }
}

impl<B> DeoxysMode<B> for DeoxysII<B>
where
    B: DeoxysBcType,
{
    type NonceSize = U15;

    fn encrypt_in_place(
        nonce: &GenericArray<u8, Self::NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
        key: &GenericArray<u8, B::KeySize>,
    ) -> [u8; 16] {
        let mut tag = [0u8; 16];
        let mut tweakey = GenericArray::<u8, B::TweakKeySize>::default();

        tweakey[..B::KeySize::to_usize()].copy_from_slice(&key);

        // Associated Data
        <Self as DeoxysModeInternal<B>>::compute_ad_tag(associated_data, &mut tweakey, &mut tag);

        // Message authentication
        Self::authenticate_message(buffer, &mut tweakey, &mut tag);

        tweakey[B::KeySize::to_usize()] = TWEAK_TAG;
        tweakey[B::KeySize::to_usize() + 1..].copy_from_slice(&nonce[0..15]);
        B::encrypt_in_place(&mut tag, &tweakey);

        // Message encryption
        Self::encrypt_decrypt_message(buffer, &mut tweakey, &tag.into(), nonce);

        // Zeroize tweakey since it contains the key
        tweakey.zeroize();
        tag
    }

    fn decrypt_in_place(
        nonce: &GenericArray<u8, Self::NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &GenericArray<u8, U16>,
        key: &GenericArray<u8, B::KeySize>,
    ) -> Result<(), aead::Error> {
        let mut computed_tag = [0u8; 16];
        let mut tweakey = GenericArray::<u8, B::TweakKeySize>::default();

        tweakey[..B::KeySize::to_usize()].copy_from_slice(&key);

        // Associated Data
        <Self as DeoxysModeInternal<B>>::compute_ad_tag(
            associated_data,
            &mut tweakey,
            &mut computed_tag,
        );

        // Message decryption
        Self::encrypt_decrypt_message(buffer, &mut tweakey, tag, nonce);

        tweakey[B::KeySize::to_usize()..].fill(0);

        // Message authentication
        Self::authenticate_message(buffer, &mut tweakey, &mut computed_tag);

        tweakey[B::KeySize::to_usize()] = TWEAK_TAG;
        tweakey[B::KeySize::to_usize() + 1..].copy_from_slice(&nonce[0..15]);
        B::encrypt_in_place(&mut computed_tag, &tweakey);

        // Zeroize tweakey since it contains the key
        tweakey.zeroize();

        if tag.ct_eq(&computed_tag).into() {
            Ok(())
        } else {
            Err(aead::Error)
        }
    }
}
