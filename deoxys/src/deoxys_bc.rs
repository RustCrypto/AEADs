use aead::{
    consts::{U15, U16, U17, U32, U48},
    generic_array::{ArrayLength, GenericArray},
};

use crate::DeoxysBcType;

const H_PERM: [u8; 16] = [1, 6, 11, 12, 5, 10, 15, 0, 9, 14, 3, 4, 13, 2, 7, 8];

macro_rules! gen_rcon {
    ($value:expr) => {
        [
            1, 2, 4, 8, $value, $value, $value, $value, 0, 0, 0, 0, 0, 0, 0, 0,
        ]
    };
}

const RCON: [[u8; 16]; 17] = [
    gen_rcon!(0x2f),
    gen_rcon!(0x5e),
    gen_rcon!(0xbc),
    gen_rcon!(0x63),
    gen_rcon!(0xc6),
    gen_rcon!(0x97),
    gen_rcon!(0x35),
    gen_rcon!(0x6a),
    gen_rcon!(0xd4),
    gen_rcon!(0xb3),
    gen_rcon!(0x7d),
    gen_rcon!(0xfa),
    gen_rcon!(0xef),
    gen_rcon!(0xc5),
    gen_rcon!(0x91),
    gen_rcon!(0x39),
    gen_rcon!(0x72),
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

        let mut tk2 = [0u8; 16];

        tk2.copy_from_slice(key);

        // First key
        let rcon = RCON[0];

        for i in 0..16 {
            subkeys[0][i] = tk2[i] ^ rcon[i];
        }

        // Other keys
        for (index, subkey) in subkeys[1..].iter_mut().enumerate() {
            h_substitution(&mut tk2);
            lfsr2(&mut tk2);

            let rcon = RCON[index + 1];

            for i in 0..16 {
                subkey[i] = tk2[i] ^ rcon[i];
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

        let mut tk3 = [0u8; 16];
        let mut tk2 = [0u8; 16];

        tk3.copy_from_slice(&key[..16]);
        tk2.copy_from_slice(&key[16..]);

        // First key
        let rcon = RCON[0];

        for i in 0..16 {
            subkeys[0][i] = tk3[i] ^ tk2[i] ^ rcon[i];
        }

        // Other keys
        for (index, subkey) in subkeys[1..].iter_mut().enumerate() {
            h_substitution(&mut tk2);
            lfsr2(&mut tk2);
            h_substitution(&mut tk3);
            lfsr3(&mut tk3);

            let rcon = RCON[index + 1];

            for i in 0..16 {
                subkey[i] = tk3[i] ^ tk2[i] ^ rcon[i];
            }
        }

        subkeys
    }
}

fn h_substitution(tk: &mut [u8; 16]) {
    let mut result = [0u8; 16];

    for i in 0..16 {
        result[i] = tk[H_PERM[i] as usize];
    }

    tk.copy_from_slice(&result);
}

fn lfsr2(tk: &mut [u8; 16]) {
    let mut data = u128::from_ne_bytes(*tk);
    data = ((data << 1) & 0xFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE)
        | (((data >> 7) ^ (data >> 5)) & 0x01010101010101010101010101010101);

    tk.copy_from_slice(&data.to_ne_bytes())
}

fn lfsr3(tk: &mut [u8; 16]) {
    let mut data = u128::from_ne_bytes(*tk);
    data = ((data >> 1) & 0x7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F)
        | (((data << 7) ^ (data << 1)) & 0x80808080808080808080808080808080);

    tk.copy_from_slice(&data.to_ne_bytes())
}
