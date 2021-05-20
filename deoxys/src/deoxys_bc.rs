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

    fn key_schedule(
        tweak: &[u8; 16],
        subkeys: &GenericArray<[u8; 16], Self::SubkeysSize>,
    ) -> GenericArray<[u8; 16], Self::SubkeysSize> {
        let mut subtweakeys: GenericArray<[u8; 16], Self::SubkeysSize> = Default::default();
        let mut tweak = *tweak;

        // First key
        for (i, (s, t)) in tweak.iter().zip(subkeys[0].iter()).enumerate() {
            subtweakeys[0][i] = s ^ t
        }

        // Other keys
        for (stk, sk) in subtweakeys[1..].iter_mut().zip(subkeys[1..].iter()) {
            h_substitution(&mut tweak);

            for i in 0..16 {
                stk[i] = sk[i] ^ tweak[i];
            }
        }

        subtweakeys
    }
}

impl DeoxysBcInternal for DeoxysBc256 {
    type SubkeysSize = U15;
    type TweakKeySize = U32;
}

impl DeoxysBcType for DeoxysBc256 {
    type KeySize = U16;

    fn precompute_subkeys(
        key: &GenericArray<u8, Self::KeySize>,
    ) -> GenericArray<[u8; 16], Self::SubkeysSize> {
        let mut subkeys: GenericArray<[u8; 16], Self::SubkeysSize> = Default::default();

        let mut buffer: GenericArray<u8, Self::KeySize> = Default::default();

        buffer.copy_from_slice(key);

        // First key
        let rcon = [
            1, 2, 4, 8, RCON[0], RCON[0], RCON[0], RCON[0], 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        for i in 0..16 {
            subkeys[0][i] = buffer[i] ^ rcon[i];
        }

        // Other keys
        for (index, subkey) in subkeys[1..].iter_mut().enumerate() {
            h_substitution(&mut buffer);
            lfsr2(&mut buffer);

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

            for i in 0..16 {
                subkey[i] = buffer[i] ^ rcon[i];
            }
        }

        subkeys
    }
}

impl DeoxysBcInternal for DeoxysBc384 {
    type SubkeysSize = U17;
    type TweakKeySize = U48;
}

impl DeoxysBcType for DeoxysBc384 {
    type KeySize = U32;

    fn precompute_subkeys(
        key: &GenericArray<u8, Self::KeySize>,
    ) -> GenericArray<[u8; 16], Self::SubkeysSize> {
        let mut subkeys: GenericArray<[u8; 16], Self::SubkeysSize> = Default::default();

        let mut buffer: GenericArray<u8, Self::KeySize> = Default::default();

        buffer.copy_from_slice(key);

        // First key
        let rcon = [
            1, 2, 4, 8, RCON[0], RCON[0], RCON[0], RCON[0], 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        for i in 0..16 {
            subkeys[0][i] = buffer[i] ^ buffer[i + 16] ^ rcon[i];
        }

        // Other keys
        for (index, subkey) in subkeys[1..].iter_mut().enumerate() {
            h_substitution(&mut buffer[16..]);
            lfsr2(&mut buffer[16..]);
            h_substitution(&mut buffer[..16]);
            lfsr3(&mut buffer[..16]);

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

            for i in 0..16 {
                subkey[i] = buffer[i] ^ buffer[i + 16] ^ rcon[i];
            }
        }

        subkeys
    }
}

fn h_substitution(tk: &mut [u8]) {
    let mut result = [0u8; 16];

    for i in 0..16 {
        result[i] = tk[H_PERM[i] as usize];
    }

    tk.copy_from_slice(&result);
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
