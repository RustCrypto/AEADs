use aead::{
    consts::{U15, U8},
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

pub struct DeoxysI;

pub struct DeoxysII;

impl<B> DeoxysMode<B> for DeoxysI
where
    B: DeoxysBcType,
{
    type NonceSize = U8;

    fn encrypt_in_place(
        nonce: &[u8],
        associated_data: &[u8],
        buffer: &mut [u8],
        key: &GenericArray<u8, B::KeySize>,
    ) -> [u8; 16] {
        let mut tag = [0u8; 16];
        let mut checksum = [0u8; 16];
        let mut tweakey = GenericArray::<u8, B::TweakKeySize>::default();

        tweakey[..key.len()].copy_from_slice(&key);

        // Associated Data
        if associated_data.len() > 0 {
            tweakey[key.len()] = TWEAK_AD;

            for (index, ad) in associated_data.chunks(16).enumerate() {
                // Copy block number
                tweakey[key.len() + 8..].copy_from_slice(&(index as u64).to_be_bytes());

                if ad.len() == 16 {
                    let mut block = [0u8; 16];
                    block.copy_from_slice(ad);

                    B::encrypt_in_place(&mut block, &tweakey);

                    for (t, b) in tag.iter_mut().zip(block.iter()) {
                        *t = *t ^ b;
                    }
                } else {
                    // Last block
                    tweakey[key.len()] = TWEAK_AD_LAST;

                    let mut block = [0u8; 16];
                    block[0..ad.len()].copy_from_slice(ad);

                    block[ad.len()] = 0x80;

                    B::encrypt_in_place(&mut block, &tweakey);

                    for (t, b) in tag.iter_mut().zip(block.iter()) {
                        *t = *t ^ b;
                    }
                }
            }
        }

        // Add the nonce to the tweak
        tweakey[key.len()] = nonce[0] >> 4;
        for i in 1..nonce.len() {
            tweakey[key.len() + i] = (nonce[i - 1] << 4) | (nonce[i] >> 4);
        }

        tweakey[key.len() + 8] = nonce[7] << 4;

        // Message authentication and encryption
        if buffer.len() > 0 {
            tweakey[key.len()] = (tweakey[key.len()] & 0xf) | TWEAK_M;

            for (index, data) in buffer.chunks_mut(16).enumerate() {
                // Copy block number
                let tmp = tweakey[key.len() + 8] & 0xf0;
                tweakey[key.len() + 8..].copy_from_slice(&(index as u64).to_be_bytes());
                tweakey[key.len() + 8] = (tweakey[key.len() + 8] & 0xf) | tmp;

                if data.len() == 16 {
                    for (c, d) in checksum.iter_mut().zip(data.iter()) {
                        *c = *c ^ d;
                    }

                    B::encrypt_in_place(data, &tweakey);
                } else {
                    // Last block checksum
                    tweakey[key.len()] = (tweakey[key.len()] & 0xf) | TWEAK_M_LAST;

                    let mut block = [0u8; 16];
                    block[0..data.len()].copy_from_slice(data);

                    block[data.len()] = 0x80;

                    for (c, d) in checksum.iter_mut().zip(block.iter()) {
                        *c = *c ^ d;
                    }

                    block.fill(0);

                    // Last block encryption
                    B::encrypt_in_place(&mut block, &tweakey);

                    for (d, b) in data.iter_mut().zip(block.iter()) {
                        *d = *d ^ b;
                    }

                    // Tag computing.
                    tweakey[key.len()] = (tweakey[key.len()] & 0xf) | TWEAK_CHKSUM;

                    let tmp = tweakey[key.len() + 8] & 0xf0;
                    tweakey[key.len() + 8..].copy_from_slice(&((index + 1) as u64).to_be_bytes());
                    tweakey[key.len() + 8] = (tweakey[key.len() + 8] & 0xf) | tmp;

                    B::encrypt_in_place(&mut checksum, &tweakey);

                    for (t, c) in tag.iter_mut().zip(checksum.iter()) {
                        *t = *t ^ c;
                    }
                }
            }
        }

        if buffer.len() % 16 == 0 {
            // Tag computing without last block
            tweakey[key.len()] = (tweakey[key.len()] & 0xf) | TWEAK_TAG;

            let tmp = tweakey[key.len() + 8] & 0xf0;
            tweakey[key.len() + 8..].copy_from_slice(&((buffer.len() / 16) as u64).to_be_bytes());
            tweakey[key.len() + 8] = (tweakey[key.len() + 8] & 0xf) | tmp;

            B::encrypt_in_place(&mut checksum, &tweakey);

            for (t, c) in tag.iter_mut().zip(checksum.iter()) {
                *t = *t ^ c;
            }
        }

        // Zeroize tweakey since it contains the key
        tweakey.zeroize();
        tag
    }

    fn decrypt_in_place(
        nonce: &[u8],
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &[u8],
        key: &GenericArray<u8, B::KeySize>,
    ) -> Result<(), aead::Error> {
        let mut computed_tag = [0u8; 16];
        let mut checksum = [0u8; 16];
        let mut tweakey = GenericArray::<u8, B::TweakKeySize>::default();

        tweakey[..key.len()].copy_from_slice(&key);

        // Associated Data
        if associated_data.len() > 0 {
            tweakey[key.len()] = TWEAK_AD;

            for (index, ad) in associated_data.chunks(16).enumerate() {
                // Copy block number
                tweakey[key.len() + 8..].copy_from_slice(&(index as u64).to_be_bytes());

                if ad.len() == 16 {
                    let mut block = [0u8; 16];
                    block.copy_from_slice(ad);

                    B::encrypt_in_place(&mut block, &tweakey);

                    for (t, b) in computed_tag.iter_mut().zip(block.iter()) {
                        *t = *t ^ b;
                    }
                } else {
                    // Last block
                    tweakey[key.len()] = TWEAK_AD_LAST;

                    let mut block = [0u8; 16];
                    block[0..ad.len()].copy_from_slice(ad);

                    block[ad.len()] = 0x80;

                    B::encrypt_in_place(&mut block, &tweakey);

                    for (t, b) in computed_tag.iter_mut().zip(block.iter()) {
                        *t = *t ^ b;
                    }
                }
            }
        }

        // Add the nonce to the tweak
        tweakey[key.len()] = nonce[0] >> 4;
        for i in 1..nonce.len() {
            tweakey[key.len() + i] = (nonce[i - 1] << 4) | (nonce[i] >> 4);
        }

        tweakey[key.len() + 8] = nonce[7] << 4;

        // Message authentication and encryption
        if buffer.len() > 0 {
            tweakey[key.len()] = (tweakey[key.len()] & 0xf) | TWEAK_M;

            for (index, data) in buffer.chunks_mut(16).enumerate() {
                // Copy block number
                let tmp = tweakey[key.len() + 8] & 0xf0;
                tweakey[key.len() + 8..].copy_from_slice(&(index as u64).to_be_bytes());
                tweakey[key.len() + 8] = (tweakey[key.len() + 8] & 0xf) | tmp;

                if data.len() == 16 {
                    B::decrypt_in_place(data, &tweakey);

                    for (c, d) in checksum.iter_mut().zip(data.iter()) {
                        *c = *c ^ d;
                    }
                } else {
                    // Last block checksum
                    tweakey[key.len()] = (tweakey[key.len()] & 0xf) | TWEAK_M_LAST;

                    let mut block = [0u8; 16];
                    B::encrypt_in_place(&mut block, &tweakey);

                    for (d, b) in data.iter_mut().zip(block.iter()) {
                        *d = *d ^ b;
                    }

                    block.fill(0);

                    block[0..data.len()].copy_from_slice(data);
                    block[data.len()] = 0x80;

                    for (c, d) in checksum.iter_mut().zip(block.iter()) {
                        *c = *c ^ d;
                    }

                    // Tag computing.
                    tweakey[key.len()] = (tweakey[key.len()] & 0xf) | TWEAK_CHKSUM;

                    let tmp = tweakey[key.len() + 8] & 0xf0;
                    tweakey[key.len() + 8..].copy_from_slice(&((index + 1) as u64).to_be_bytes());
                    tweakey[key.len() + 8] = (tweakey[key.len() + 8] & 0xf) | tmp;

                    B::encrypt_in_place(&mut checksum, &tweakey);

                    for (t, c) in computed_tag.iter_mut().zip(checksum.iter()) {
                        *t = *t ^ c;
                    }
                }
            }
        }

        if buffer.len() % 16 == 0 {
            // Tag computing without last block
            tweakey[key.len()] = (tweakey[key.len()] & 0xf) | TWEAK_TAG;

            let tmp = tweakey[key.len() + 8] & 0xf0;
            tweakey[key.len() + 8..].copy_from_slice(&((buffer.len() / 16) as u64).to_be_bytes());
            tweakey[key.len() + 8] = (tweakey[key.len() + 8] & 0xf) | tmp;

            B::encrypt_in_place(&mut checksum, &tweakey);

            for (t, c) in computed_tag.iter_mut().zip(checksum.iter()) {
                *t = *t ^ c;
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

impl<B> DeoxysMode<B> for DeoxysII
where
    B: DeoxysBcType,
{
    type NonceSize = U15;

    fn encrypt_in_place(
        nonce: &[u8],
        associated_data: &[u8],
        buffer: &mut [u8],
        key: &GenericArray<u8, B::KeySize>,
    ) -> [u8; 16] {
        let mut tag = [0u8; 16];
        let mut tweakey = GenericArray::<u8, B::TweakKeySize>::default();

        tweakey[..key.len()].copy_from_slice(&key);

        // Associated Data
        if associated_data.len() > 0 {
            tweakey[key.len()] = TWEAK_AD;

            for (index, ad) in associated_data.chunks(16).enumerate() {
                // Copy block number
                tweakey[key.len() + 8..].copy_from_slice(&(index as u64).to_be_bytes());

                if ad.len() == 16 {
                    let mut block = [0u8; 16];
                    block.copy_from_slice(ad);

                    B::encrypt_in_place(&mut block, &tweakey);

                    for (t, b) in tag.iter_mut().zip(block.iter()) {
                        *t = *t ^ b;
                    }
                } else {
                    // Last block
                    tweakey[key.len()] = TWEAK_AD_LAST;

                    let mut block = [0u8; 16];
                    block[0..ad.len()].copy_from_slice(ad);

                    block[ad.len()] = 0x80;

                    B::encrypt_in_place(&mut block, &tweakey);

                    for (t, b) in tag.iter_mut().zip(block.iter()) {
                        *t = *t ^ b;
                    }
                }
            }
        }

        tweakey[key.len()..].fill(0);
        // Message authentication
        if buffer.len() > 0 {
            tweakey[key.len()] = TWEAK_M;

            for (index, data) in buffer.chunks(16).enumerate() {
                // Copy block number
                tweakey[key.len() + 8..].copy_from_slice(&(index as u64).to_be_bytes());

                if data.len() == 16 {
                    let mut block = [0u8; 16];
                    block.copy_from_slice(data);

                    B::encrypt_in_place(&mut block, &tweakey);

                    for (t, b) in tag.iter_mut().zip(block.iter()) {
                        *t = *t ^ b;
                    }
                } else {
                    // Last block
                    tweakey[key.len()] = TWEAK_M_LAST;

                    let mut block = [0u8; 16];
                    block[0..data.len()].copy_from_slice(data);

                    block[data.len()] = 0x80;

                    B::encrypt_in_place(&mut block, &tweakey);

                    for (t, b) in tag.iter_mut().zip(block.iter()) {
                        *t = *t ^ b;
                    }
                }
            }
        }

        tweakey[key.len()] = TWEAK_TAG;
        tweakey[key.len() + 1..].copy_from_slice(&nonce[0..15]);
        B::encrypt_in_place(&mut tag, &tweakey);

        // Message encryption
        if buffer.len() > 0 {
            tweakey[key.len()..].copy_from_slice(&tag);
            tweakey[key.len()] |= 0x80;

            for (index, data) in buffer.chunks_mut(16).enumerate() {
                let index_array = (index as u64).to_be_bytes();

                // XOR in block numbers
                for (t, i) in tweakey[key.len() + 8..].iter_mut().zip(&index_array) {
                    *t = *t ^ i
                }

                if data.len() == 16 {
                    let mut block = [0u8; 16];
                    block[1..].copy_from_slice(&nonce[0..15]);

                    B::encrypt_in_place(&mut block, &tweakey);

                    for (t, b) in data.iter_mut().zip(block.iter()) {
                        *t = *t ^ b;
                    }
                } else {
                    // Last block
                    let mut block = [0u8; 16];
                    block[1..].copy_from_slice(&nonce[0..15]);

                    B::encrypt_in_place(&mut block, &tweakey);

                    for (d, b) in data.iter_mut().zip(block.iter()) {
                        *d = *d ^ b;
                    }
                }

                // XOR out block numbers
                for (t, i) in tweakey[key.len() + 8..].iter_mut().zip(&index_array) {
                    *t = *t ^ i
                }
            }
        }

        // Zeroize tweakey since it contains the key
        tweakey.zeroize();
        tag
    }

    fn decrypt_in_place(
        nonce: &[u8],
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &[u8],
        key: &GenericArray<u8, B::KeySize>,
    ) -> Result<(), aead::Error> {
        let mut computed_tag = [0u8; 16];
        let mut tweakey = GenericArray::<u8, B::TweakKeySize>::default();

        tweakey[..key.len()].copy_from_slice(&key);

        // Message decryption
        if buffer.len() > 0 {
            tweakey[key.len()..].copy_from_slice(&tag);
            tweakey[key.len()] |= 0x80;

            for (index, data) in buffer.chunks_mut(16).enumerate() {
                let index_array = (index as u64).to_be_bytes();

                // XOR in block numbers
                for (t, i) in tweakey[key.len() + 8..].iter_mut().zip(&index_array) {
                    *t = *t ^ i
                }

                if data.len() == 16 {
                    let mut block = [0u8; 16];
                    block[1..].copy_from_slice(&nonce[0..15]);

                    B::encrypt_in_place(&mut block, &tweakey);

                    for (t, b) in data.iter_mut().zip(block.iter()) {
                        *t = *t ^ b;
                    }
                } else {
                    // Last block
                    let mut block = [0u8; 16];
                    block[1..].copy_from_slice(&nonce[0..15]);

                    B::encrypt_in_place(&mut block, &tweakey);

                    for (d, b) in data.iter_mut().zip(block.iter()) {
                        *d = *d ^ b;
                    }
                }

                // XOR out block numbers
                for (t, i) in tweakey[key.len() + 8..].iter_mut().zip(&index_array) {
                    *t = *t ^ i
                }
            }
        }

        tweakey[key.len()..].fill(0);
        // Associated Data
        if associated_data.len() > 0 {
            tweakey[key.len()] = TWEAK_AD;

            for (index, ad) in associated_data.chunks(16).enumerate() {
                // Copy block number
                tweakey[key.len() + 8..].copy_from_slice(&(index as u64).to_be_bytes());

                if ad.len() == 16 {
                    let mut block = [0u8; 16];
                    block.copy_from_slice(ad);

                    B::encrypt_in_place(&mut block, &tweakey);

                    for (t, b) in computed_tag.iter_mut().zip(block.iter()) {
                        *t = *t ^ b;
                    }
                } else {
                    // Last block
                    tweakey[key.len()] = TWEAK_AD_LAST;

                    let mut block = [0u8; 16];
                    block[0..ad.len()].copy_from_slice(ad);

                    block[ad.len()] = 0x80;

                    B::encrypt_in_place(&mut block, &tweakey);

                    for (t, b) in computed_tag.iter_mut().zip(block.iter()) {
                        *t = *t ^ b;
                    }
                }
            }
        }

        tweakey[key.len()..].fill(0);
        // Message authentication
        if buffer.len() > 0 {
            tweakey[key.len()] = TWEAK_M;

            for (index, data) in buffer.chunks(16).enumerate() {
                // Copy block number
                tweakey[key.len() + 8..].copy_from_slice(&(index as u64).to_be_bytes());

                if data.len() == 16 {
                    let mut block = [0u8; 16];
                    block.copy_from_slice(data);

                    B::encrypt_in_place(&mut block, &tweakey);

                    for (t, b) in computed_tag.iter_mut().zip(block.iter()) {
                        *t = *t ^ b;
                    }
                } else {
                    // Last block
                    tweakey[key.len()] = TWEAK_M_LAST;

                    let mut block = [0u8; 16];
                    block[0..data.len()].copy_from_slice(data);

                    block[data.len()] = 0x80;

                    B::encrypt_in_place(&mut block, &tweakey);

                    for (t, b) in computed_tag.iter_mut().zip(block.iter()) {
                        *t = *t ^ b;
                    }
                }
            }
        }

        tweakey[key.len()] = TWEAK_TAG;
        tweakey[key.len() + 1..].copy_from_slice(&nonce[0..15]);
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
