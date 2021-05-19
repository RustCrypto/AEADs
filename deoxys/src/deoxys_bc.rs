use aead::{
    consts::{U15, U16, U17, U32, U48},
    generic_array::{ArrayLength, GenericArray},
};

use crate::DeoxysBcType;

const H_PERM: [u8; 16] = [1, 6, 11, 12, 5, 10, 15, 0, 9, 14, 3, 4, 13, 2, 7, 8];

const RCON: [u8; 17] = [
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
    0x72,
];

/// Implementation of the Deoxys-BC256 block cipher
pub struct DeoxysBc256;

/// Implementation of the Deoxys-BC384 block cipher
pub struct DeoxysBc384;

pub trait DeoxysBcInternal {
    type SubkeysSize: ArrayLength<[u8; 16]>;
    type TweakKeySize: ArrayLength<u8>;

    fn generate_subkey(
        subkey: &mut [u8; 16],
        tweakey: &GenericArray<u8, Self::TweakKeySize>,
        index: usize,
    );

    fn shuffle_tweakey(tweakey: &mut GenericArray<u8, Self::TweakKeySize>);

    fn key_schedule(tweakey: &[u8]) -> GenericArray<[u8; 16], Self::SubkeysSize> {
        let mut subkeys: GenericArray<[u8; 16], Self::SubkeysSize> = Default::default();

        let mut tk: GenericArray<u8, Self::TweakKeySize> = Default::default();

        tk.copy_from_slice(tweakey);

        // First key
        Self::generate_subkey(&mut subkeys[0], &tk, 0);

        // Other keys
        for (index, subkey) in subkeys[1..].iter_mut().enumerate() {
            Self::shuffle_tweakey(&mut tk);
            Self::generate_subkey(subkey, &tk, index + 1);
        }

        subkeys
    }
}

impl DeoxysBcInternal for DeoxysBc256 {
    type SubkeysSize = U15;
    type TweakKeySize = U32;

    fn generate_subkey(
        subkey: &mut [u8; 16],
        tweakey: &GenericArray<u8, Self::TweakKeySize>,
        index: usize,
    ) {
        let rcon = [
            1,
            2,
            4,
            8,
            RCON[index],
            RCON[index],
            RCON[index],
            RCON[index],
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];

        for i in 0..16 {
            subkey[i] = tweakey[i] ^ tweakey[i + 16] ^ rcon[i];
        }
    }

    fn shuffle_tweakey(tweakey: &mut GenericArray<u8, Self::TweakKeySize>) {
        h_substitution(&mut tweakey[16..32]);
        lfsr2(&mut tweakey[..16]);
        h_substitution(&mut tweakey[..16]);
    }
}

impl DeoxysBcType for DeoxysBc256 {
    type KeySize = U16;
}

impl DeoxysBcInternal for DeoxysBc384 {
    type SubkeysSize = U17;
    type TweakKeySize = U48;

    fn generate_subkey(
        subkey: &mut [u8; 16],
        tweakey: &GenericArray<u8, Self::TweakKeySize>,
        index: usize,
    ) {
        let rcon = [
            1,
            2,
            4,
            8,
            RCON[index],
            RCON[index],
            RCON[index],
            RCON[index],
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];

        for i in 0..16 {
            subkey[i] = tweakey[i] ^ tweakey[i + 16] ^ tweakey[i + 32] ^ rcon[i];
        }
    }

    fn shuffle_tweakey(tweakey: &mut GenericArray<u8, Self::TweakKeySize>) {
        h_substitution(&mut tweakey[32..]);
        lfsr2(&mut tweakey[16..32]);
        h_substitution(&mut tweakey[16..32]);
        lfsr3(&mut tweakey[..16]);
        h_substitution(&mut tweakey[..16]);
    }
}

impl DeoxysBcType for DeoxysBc384 {
    type KeySize = U32;
}

fn h_substitution(tk: &mut [u8]) {
    let mut result = [0u8; 16];

    for i in 0..16 {
        result[i] = tk[H_PERM[i] as usize];
    }

    tk.copy_from_slice(&result[..16]);
}

// TODO: This operation is very slow
// On Deoxys-II-256, shuffle_tweakey(),
//   which consists of h_substitution and lfsr2 and lfsr3, takes up 65% of the encryption time
fn lfsr2(tk: &mut [u8]) {
    for x in tk {
        let feedback = (*x >> 5) & 1;
        *x = x.rotate_left(1);
        *x ^= feedback;
    }
}

// TODO: This operation is very slow
// On Deoxys-II-256, shuffle_tweakey(),
//   which consists of h_substitution and lfsr2 and lfsr3, takes up 65% of the encryption time
fn lfsr3(tk: &mut [u8]) {
    for x in tk {
        let feedback = (*x << 1) & 0x80;
        *x = x.rotate_right(1);
        *x ^= feedback;
    }
}
