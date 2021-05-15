use aead::{
    consts::{U16, U32, U48},
    generic_array::GenericArray,
};

use crate::aes_ref;

use crate::DeoxysBcType;

const H_PERM: [u8; 16] = [1, 6, 11, 12, 5, 10, 15, 0, 9, 14, 3, 4, 13, 2, 7, 8];

const RCON: [u8; 17] = [
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
    0x72,
];

pub struct DeoxysBc256;
pub struct DeoxysBc384;

impl DeoxysBc256 {
    fn key_schedule(tweakey: &[u8]) -> [[u8; 16]; 15] {
        let mut subkeys: [[u8; 16]; 15] = Default::default();
        let mut tk1 = [0u8; 16];
        let mut tk2 = [0u8; 16];

        tk2.copy_from_slice(&tweakey[..16]);
        tk1.copy_from_slice(&tweakey[16..32]);

        // First key
        let rcon = [
            1, 2, 4, 8, RCON[0], RCON[0], RCON[0], RCON[0], 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        for i in 0..16 {
            subkeys[0][i] = tk1[i] ^ tk2[i] ^ rcon[i];
        }

        // Other keys
        for (index, subkey) in subkeys[1..].iter_mut().enumerate() {
            let rcon = [
                1,
                2,
                4,
                8,
                RCON[index + 1],
                RCON[index + 1],
                RCON[index + 1],
                RCON[index + 1],
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ];
            h_substitution(&mut tk1);
            lfsr2(&mut tk2);
            h_substitution(&mut tk2);

            for i in 0..16 {
                subkey[i] = tk1[i] ^ tk2[i] ^ rcon[i];
            }
        }

        subkeys
    }
}

impl DeoxysBcType for DeoxysBc256 {
    type KeySize = U16;
    type TweakKeySize = U32;

    fn encrypt_in_place(block: &mut [u8], tweakey: &GenericArray<u8, Self::TweakKeySize>) {
        let keys: [[u8; 16]; 15] = Self::key_schedule(tweakey);

        aes_ref::add_round_key(block, &keys[0]);

        for k in &keys[1..15] {
            aes_ref::encrypt_round(block, k)
        }
    }

    fn decrypt_in_place(block: &mut [u8], tweakey: &GenericArray<u8, Self::TweakKeySize>) {
        let keys: [[u8; 16]; 15] = Self::key_schedule(tweakey);

        for k in keys[1..15].iter().rev() {
            aes_ref::decrypt_round(block, k)
        }

        aes_ref::add_round_key(block, &keys[0]);
    }
}

impl DeoxysBc384 {
    fn key_schedule(tweakey: &[u8]) -> [[u8; 16]; 17] {
        let mut subkeys: [[u8; 16]; 17] = Default::default();
        let mut tk1 = [0u8; 16];
        let mut tk2 = [0u8; 16];
        let mut tk3 = [0u8; 16];

        tk3.copy_from_slice(&tweakey[..16]);
        tk2.copy_from_slice(&tweakey[16..32]);
        tk1.copy_from_slice(&tweakey[32..]);

        // First key
        let rcon = [
            1, 2, 4, 8, RCON[0], RCON[0], RCON[0], RCON[0], 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        for i in 0..16 {
            subkeys[0][i] = tk1[i] ^ tk2[i] ^ tk3[i] ^ rcon[i];
        }

        // Other keys
        for (index, subkey) in subkeys[1..].iter_mut().enumerate() {
            let rcon = [
                1,
                2,
                4,
                8,
                RCON[index + 1],
                RCON[index + 1],
                RCON[index + 1],
                RCON[index + 1],
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ];
            h_substitution(&mut tk1);
            lfsr2(&mut tk2);
            h_substitution(&mut tk2);
            lfsr3(&mut tk3);
            h_substitution(&mut tk3);

            for i in 0..16 {
                subkey[i] = tk1[i] ^ tk2[i] ^ tk3[i] ^ rcon[i];
            }
        }

        subkeys
    }
}

impl DeoxysBcType for DeoxysBc384 {
    type KeySize = U32;
    type TweakKeySize = U48;

    fn encrypt_in_place(block: &mut [u8], tweakey: &GenericArray<u8, Self::TweakKeySize>) {
        let keys: [[u8; 16]; 17] = Self::key_schedule(tweakey);

        aes_ref::add_round_key(block, &keys[0]);

        for k in &keys[1..17] {
            aes_ref::encrypt_round(block, k)
        }
    }

    fn decrypt_in_place(block: &mut [u8], tweakey: &GenericArray<u8, Self::TweakKeySize>) {
        let keys: [[u8; 16]; 17] = Self::key_schedule(tweakey);

        for k in keys[1..17].iter().rev() {
            aes_ref::decrypt_round(block, k)
        }

        aes_ref::add_round_key(block, &keys[0]);
    }
}

fn h_substitution(tk: &mut [u8]) {
    let mut result = [0u8; 16];

    for i in 0..16 {
        result[i] = tk[H_PERM[i] as usize];
    }

    tk.copy_from_slice(&result[..16]);
}

fn lfsr2(tk: &mut [u8]) {
    for x in tk {
        let feedback = (*x >> 5) & 1;
        *x = x.rotate_left(1);
        *x ^= feedback;
    }
}

fn lfsr3(tk: &mut [u8]) {
    for x in tk {
        let feedback = (*x << 1) & 0x80;
        *x = x.rotate_right(1);
        *x ^= feedback;
    }
}
