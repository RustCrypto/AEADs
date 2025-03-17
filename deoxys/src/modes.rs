use super::{Block, DeoxysBcType, DeoxysKey, DeoxysMode, Tag, Tweak};
use aead::{
    array::Array,
    consts::{U8, U15, U16},
};
use core::marker::PhantomData;
use inout::InOutBuf;
use subtle::ConstantTimeEq;

const TWEAK_AD: u8 = 0x20;
const TWEAK_AD_LAST: u8 = 0x60;
const TWEAK_M: u8 = 0x00;
const TWEAK_TAG: u8 = 0x10;
const TWEAK_M_LAST: u8 = 0x40;
const TWEAK_CHKSUM: u8 = 0x50;

type Checksum = Array<u8, U16>;

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
        tweak: &mut Tweak,
        subkeys: &Array<DeoxysKey, B::SubkeysSize>,
        tag: &mut Tag,
    ) {
        if !associated_data.is_empty() {
            tweak[0] = TWEAK_AD;

            for (index, ad) in associated_data.chunks(16).enumerate() {
                // Copy block number
                tweak[8..].copy_from_slice(&(index as u64).to_be_bytes());

                if ad.len() == 16 {
                    let mut block = Block::default();
                    block.copy_from_slice(ad);

                    B::encrypt_in_place((&mut block).into(), tweak, subkeys);

                    for (t, b) in tag.iter_mut().zip(block.iter()) {
                        *t ^= b;
                    }
                } else {
                    // Last block
                    tweak[0] = TWEAK_AD_LAST;

                    let mut block = Block::default();
                    block[0..ad.len()].copy_from_slice(ad);

                    block[ad.len()] = 0x80;

                    B::encrypt_in_place((&mut block).into(), tweak, subkeys);

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
        nonce: &Array<u8, Self::NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
        subkeys: &Array<DeoxysKey, B::SubkeysSize>,
    ) -> Tag {
        let mut tag = Tag::default();
        let mut checksum = Checksum::default();
        let mut tweak = Tweak::default();
        let buffer: InOutBuf<'_, '_, u8> = buffer.into();
        let buffer_len = buffer.len();

        // Associated Data
        <Self as DeoxysModeInternal<B>>::compute_ad_tag(
            associated_data,
            &mut tweak,
            subkeys,
            &mut tag,
        );

        // Add the nonce to the tweak
        tweak[0] = nonce[0] >> 4;
        for i in 1..nonce.len() {
            tweak[i] = (nonce[i - 1] << 4) | (nonce[i] >> 4);
        }

        tweak[8] = nonce[7] << 4;

        // Message authentication and encryption
        if !buffer.is_empty() {
            tweak[0] = (tweak[0] & 0xf) | TWEAK_M;

            let (data_blocks, tail) = buffer.into_chunks();
            let data_blocks_len = data_blocks.len();

            for (index, data) in data_blocks.into_iter().enumerate() {
                // Copy block number
                let tmp = tweak[8] & 0xf0;
                tweak[8..].copy_from_slice(&(index as u64).to_be_bytes());
                tweak[8] = (tweak[8] & 0xf) | tmp;

                for (c, d) in checksum.iter_mut().zip(data.get_in().iter()) {
                    *c ^= d;
                }

                B::encrypt_in_place(data, tweak.as_ref(), subkeys);
            }

            let mut data = tail;
            let index = data_blocks_len;
            if !data.is_empty() {
                // Last block, incomplete

                // Copy block number
                let tmp = tweak[8] & 0xf0;
                tweak[8..].copy_from_slice(&(index as u64).to_be_bytes());
                tweak[8] = (tweak[8] & 0xf) | tmp;

                // Last block checksum
                tweak[0] = (tweak[0] & 0xf) | TWEAK_M_LAST;

                let mut block = Block::default();
                block[0..data.len()].copy_from_slice(data.get_in());

                block[data.len()] = 0x80;

                for (c, d) in checksum.iter_mut().zip(block.iter()) {
                    *c ^= d;
                }

                block.fill(0);

                // Last block encryption
                B::encrypt_in_place((&mut block).into(), tweak.as_ref(), subkeys);

                data.xor_in2out((block[..data.len()]).into());

                // Tag computing.
                tweak[0] = (tweak[0] & 0xf) | TWEAK_CHKSUM;

                let tmp = tweak[8] & 0xf0;
                tweak[8..].copy_from_slice(&((index + 1) as u64).to_be_bytes());
                tweak[8] = (tweak[8] & 0xf) | tmp;

                B::encrypt_in_place((&mut checksum).into(), tweak.as_ref(), subkeys);

                for (t, c) in tag.iter_mut().zip(checksum.iter()) {
                    *t ^= c;
                }
            }
        }

        if buffer_len % 16 == 0 {
            // Tag computing without last block
            tweak[0] = (tweak[0] & 0xf) | TWEAK_TAG;

            let tmp = tweak[8] & 0xf0;
            tweak[8..].copy_from_slice(&((buffer_len / 16) as u64).to_be_bytes());
            tweak[8] = (tweak[8] & 0xf) | tmp;

            B::encrypt_in_place((&mut checksum).into(), tweak.as_ref(), subkeys);

            for (t, c) in tag.iter_mut().zip(checksum.iter()) {
                *t ^= c;
            }
        }

        tag
    }

    fn decrypt_in_place(
        nonce: &Array<u8, Self::NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag,
        subkeys: &Array<DeoxysKey, B::SubkeysSize>,
    ) -> Result<(), aead::Error> {
        let mut computed_tag = Tag::default();
        let mut checksum = Checksum::default();
        let mut tweak = Tweak::default();

        // Associated Data
        <Self as DeoxysModeInternal<B>>::compute_ad_tag(
            associated_data,
            &mut tweak,
            subkeys,
            &mut computed_tag,
        );

        // Add the nonce to the tweak
        tweak[0] = nonce[0] >> 4;
        for i in 1..nonce.len() {
            tweak[i] = (nonce[i - 1] << 4) | (nonce[i] >> 4);
        }

        tweak[8] = nonce[7] << 4;

        // Message authentication and encryption
        if !buffer.is_empty() {
            tweak[0] = (tweak[0] & 0xf) | TWEAK_M;

            for (index, data) in buffer.chunks_mut(16).enumerate() {
                // Copy block number
                let tmp = tweak[8] & 0xf0;
                tweak[8..].copy_from_slice(&(index as u64).to_be_bytes());
                tweak[8] = (tweak[8] & 0xf) | tmp;

                if data.len() == 16 {
                    let data: &mut Block = data.try_into().unwrap();
                    B::decrypt_in_place(data.into(), tweak.as_ref(), subkeys);

                    for (c, d) in checksum.iter_mut().zip(data.iter()) {
                        *c ^= d;
                    }
                } else {
                    // Last block checksum
                    tweak[0] = (tweak[0] & 0xf) | TWEAK_M_LAST;

                    let mut block = Block::default();
                    B::encrypt_in_place((&mut block).into(), tweak.as_ref(), subkeys);

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
                    tweak[0] = (tweak[0] & 0xf) | TWEAK_CHKSUM;

                    let tmp = tweak[8] & 0xf0;
                    tweak[8..].copy_from_slice(&((index + 1) as u64).to_be_bytes());
                    tweak[8] = (tweak[8] & 0xf) | tmp;

                    B::encrypt_in_place((&mut checksum).into(), tweak.as_ref(), subkeys);

                    for (t, c) in computed_tag.iter_mut().zip(checksum.iter()) {
                        *t ^= c;
                    }
                }
            }
        }

        if buffer.len() % 16 == 0 {
            // Tag computing without last block
            tweak[0] = (tweak[0] & 0xf) | TWEAK_TAG;

            let tmp = tweak[8] & 0xf0;
            tweak[8..].copy_from_slice(&((buffer.len() / 16) as u64).to_be_bytes());
            tweak[8] = (tweak[8] & 0xf) | tmp;

            B::encrypt_in_place((&mut checksum).into(), tweak.as_ref(), subkeys);

            for (t, c) in computed_tag.iter_mut().zip(checksum.iter()) {
                *t ^= c;
            }
        }

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
        tweak: &mut Tweak,
        subkeys: &Array<DeoxysKey, B::SubkeysSize>,
        tag: &mut Tag,
    ) {
        if buffer.is_empty() {
            return;
        }
        tweak[0] = TWEAK_M;

        let (chunks, tail) = Block::slice_as_chunks(buffer);

        for (index, data) in chunks.iter().enumerate() {
            // Copy block number
            tweak[8..].copy_from_slice(&(index as u64).to_be_bytes());

            let mut block = *data;

            B::encrypt_in_place((&mut block).into(), tweak, subkeys);

            for (t, b) in tag.iter_mut().zip(block.iter()) {
                *t ^= b;
            }
        }

        let index = chunks.len();
        let data = tail;
        if data.is_empty() {
            return;
        }

        // Copy block number
        tweak[8..].copy_from_slice(&(index as u64).to_be_bytes());

        // Last block
        tweak[0] = TWEAK_M_LAST;

        let mut block = Block::default();
        block[0..data.len()].copy_from_slice(data);

        block[data.len()] = 0x80;

        B::encrypt_in_place((&mut block).into(), tweak, subkeys);

        for (t, b) in tag.iter_mut().zip(block.iter()) {
            *t ^= b;
        }
    }

    fn encrypt_decrypt_message(
        buffer: InOutBuf<'_, '_, u8>,
        tweak: &mut Tweak,
        subkeys: &Array<DeoxysKey, B::SubkeysSize>,
        tag: &Tag,
        nonce: &Array<u8, U15>,
    ) {
        #[inline]
        fn encrypt_decrypt_block<B: DeoxysBcType, F: FnOnce(&Block)>(
            index: usize,
            tweak: &mut Tweak,
            subkeys: &Array<DeoxysKey, B::SubkeysSize>,
            nonce: &Array<u8, U15>,
            xor: F,
        ) {
            let index_array = (index as u64).to_be_bytes();

            // XOR in block numbers
            for (t, i) in tweak[8..].iter_mut().zip(&index_array) {
                *t ^= i
            }

            let mut block = Block::default();
            block[1..].copy_from_slice(nonce);

            B::encrypt_in_place((&mut block).into(), tweak, subkeys);

            xor(&block);

            // XOR out block numbers
            for (t, i) in tweak[8..].iter_mut().zip(&index_array) {
                *t ^= i
            }
        }

        if buffer.is_empty() {
            return;
        }

        tweak.copy_from_slice(tag);
        tweak[0] |= 0x80;

        let (blocks, tail) = buffer.into_chunks::<U16>();
        let blocks_len = blocks.len();
        for (index, mut data) in blocks.into_iter().enumerate() {
            encrypt_decrypt_block::<B, _>(index, tweak, subkeys, nonce, |block| {
                data.xor_in2out(block)
            });
        }
        let mut data = tail;
        let index = blocks_len;

        encrypt_decrypt_block::<B, _>(index, tweak, subkeys, nonce, |block| {
            data.xor_in2out((block[..data.len()]).into())
        });
    }
}

impl<B> DeoxysMode<B> for DeoxysII<B>
where
    B: DeoxysBcType,
{
    type NonceSize = U15;

    fn encrypt_in_place(
        nonce: &Array<u8, Self::NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
        subkeys: &Array<DeoxysKey, B::SubkeysSize>,
    ) -> Tag {
        let mut tag = Tag::default();
        let mut tweak = Tweak::default();

        // Associated Data
        <Self as DeoxysModeInternal<B>>::compute_ad_tag(
            associated_data,
            &mut tweak,
            subkeys,
            &mut tag,
        );

        // Message authentication
        Self::authenticate_message(buffer, &mut tweak, subkeys, &mut tag);

        tweak[0] = TWEAK_TAG;
        tweak[1..].copy_from_slice(nonce);
        B::encrypt_in_place((&mut tag).into(), &tweak, subkeys);

        // Message encryption
        Self::encrypt_decrypt_message(buffer.into(), &mut tweak, subkeys, &tag, nonce);

        tag
    }

    fn decrypt_in_place(
        nonce: &Array<u8, Self::NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag,
        subkeys: &Array<DeoxysKey, B::SubkeysSize>,
    ) -> Result<(), aead::Error> {
        let mut computed_tag = Tag::default();
        let mut tweak = Tweak::default();

        // Associated Data
        <Self as DeoxysModeInternal<B>>::compute_ad_tag(
            associated_data,
            &mut tweak,
            subkeys,
            &mut computed_tag,
        );

        // Message decryption
        Self::encrypt_decrypt_message(buffer.into(), &mut tweak, subkeys, tag, nonce);

        tweak.fill(0);

        // Message authentication
        Self::authenticate_message(buffer, &mut tweak, subkeys, &mut computed_tag);

        tweak[0] = TWEAK_TAG;
        tweak[1..].copy_from_slice(nonce);
        B::encrypt_in_place((&mut computed_tag).into(), &tweak, subkeys);

        if tag.ct_eq(&computed_tag).into() {
            Ok(())
        } else {
            Err(aead::Error)
        }
    }
}
