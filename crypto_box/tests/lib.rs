//! `crypto_box` test vectors
//!
//! Adapted from PHP Sodium Compat's test vectors:
//! <https://www.phpclasses.org/browse/file/122796.html>

use crypto_box::aead::{generic_array::GenericArray, Aead, AeadInPlace};
use crypto_box::{ChaChaBox, PublicKey, SalsaBox, SecretKey};
use std::any::TypeId;

const SALSABOX_TYPE: TypeId = TypeId::of::<SalsaBox>();

// Alice's keypair
const ALICE_SECRET_KEY: [u8; 32] = [
    0x68, 0xf2, 0x8, 0x41, 0x2d, 0x8d, 0xd5, 0xdb, 0x9d, 0xc, 0x6d, 0x18, 0x51, 0x2e, 0x86, 0xf0,
    0xec, 0x75, 0x66, 0x5a, 0xb8, 0x41, 0x37, 0x2d, 0x57, 0xb0, 0x42, 0xb2, 0x7e, 0xf8, 0x9d, 0x4c,
];
const ALICE_PUBLIC_KEY: [u8; 32] = [
    0xac, 0x3a, 0x70, 0xba, 0x35, 0xdf, 0x3c, 0x3f, 0xae, 0x42, 0x7a, 0x7c, 0x72, 0x2, 0x1d, 0x68,
    0xf2, 0xc1, 0xe0, 0x44, 0x4, 0xb, 0x75, 0xf1, 0x73, 0x13, 0xc0, 0xc8, 0xb5, 0xd4, 0x24, 0x1d,
];

// Bob's keypair
const BOB_SECRET_KEY: [u8; 32] = [
    0xb5, 0x81, 0xfb, 0x5a, 0xe1, 0x82, 0xa1, 0x6f, 0x60, 0x3f, 0x39, 0x27, 0xd, 0x4e, 0x3b, 0x95,
    0xbc, 0x0, 0x83, 0x10, 0xb7, 0x27, 0xa1, 0x1d, 0xd4, 0xe7, 0x84, 0xa0, 0x4, 0x4d, 0x46, 0x1b,
];
const BOB_PUBLIC_KEY: [u8; 32] = [
    0xe8, 0x98, 0xc, 0x86, 0xe0, 0x32, 0xf1, 0xeb, 0x29, 0x75, 0x5, 0x2e, 0x8d, 0x65, 0xbd, 0xdd,
    0x15, 0xc3, 0xb5, 0x96, 0x41, 0x17, 0x4e, 0xc9, 0x67, 0x8a, 0x53, 0x78, 0x9d, 0x92, 0xc7, 0x54,
];

const NONCE: &[u8; 24] = &[
    0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73, 0xcd, 0x62, 0xbd, 0xa8, 0x75, 0xfc, 0x73, 0xd6,
    0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37,
];

const PLAINTEXT: &[u8] = &[
    0xbe, 0x07, 0x5f, 0xc5, 0x3c, 0x81, 0xf2, 0xd5, 0xcf, 0x14, 0x13, 0x16, 0xeb, 0xeb, 0x0c, 0x7b,
    0x52, 0x28, 0xc5, 0x2a, 0x4c, 0x62, 0xcb, 0xd4, 0x4b, 0x66, 0x84, 0x9b, 0x64, 0x24, 0x4f, 0xfc,
    0xe5, 0xec, 0xba, 0xaf, 0x33, 0xbd, 0x75, 0x1a, 0x1a, 0xc7, 0x28, 0xd4, 0x5e, 0x6c, 0x61, 0x29,
    0x6c, 0xdc, 0x3c, 0x01, 0x23, 0x35, 0x61, 0xf4, 0x1d, 0xb6, 0x6c, 0xce, 0x31, 0x4a, 0xdb, 0x31,
    0x0e, 0x3b, 0xe8, 0x25, 0x0c, 0x46, 0xf0, 0x6d, 0xce, 0xea, 0x3a, 0x7f, 0xa1, 0x34, 0x80, 0x57,
    0xe2, 0xf6, 0x55, 0x6a, 0xd6, 0xb1, 0x31, 0x8a, 0x02, 0x4a, 0x83, 0x8f, 0x21, 0xaf, 0x1f, 0xde,
    0x04, 0x89, 0x77, 0xeb, 0x48, 0xf5, 0x9f, 0xfd, 0x49, 0x24, 0xca, 0x1c, 0x60, 0x90, 0x2e, 0x52,
    0xf0, 0xa0, 0x89, 0xbc, 0x76, 0x89, 0x70, 0x40, 0xe0, 0x82, 0xf9, 0x37, 0x76, 0x38, 0x48, 0x64,
    0x5e, 0x07, 0x05,
];

#[test]
fn generate_secret_key() {
    let mut rng = rand::thread_rng();
    SecretKey::generate(&mut rng);
}

#[test]
fn secret_and_public_keys() {
    let secret_key = SecretKey::from(ALICE_SECRET_KEY);
    assert_eq!(&secret_key.to_bytes(), &ALICE_SECRET_KEY);

    // Ensure `Debug` impl on `SecretKey` is covered in tests
    dbg!(&secret_key);

    assert_eq!(secret_key.public_key().as_bytes(), &ALICE_PUBLIC_KEY);
}

macro_rules! impl_tests {
    ($box:ty, $plaintext:expr, $ciphertext:expr) => {
        #[test]
        fn encrypt() {
            let secret_key = SecretKey::from(ALICE_SECRET_KEY);
            let public_key = PublicKey::from(BOB_PUBLIC_KEY);
            let nonce = GenericArray::from_slice(NONCE);

            let ciphertext = <$box>::new(&public_key, &secret_key)
                .encrypt(nonce, $plaintext)
                .unwrap();

            assert_eq!($ciphertext, &ciphertext[..]);
        }

        #[test]
        fn encrypt_in_place_detached() {
            let secret_key = SecretKey::from(ALICE_SECRET_KEY);
            let public_key = PublicKey::from(BOB_PUBLIC_KEY);
            let nonce = GenericArray::from_slice(NONCE);
            let mut buffer = $plaintext.to_vec();

            let tag = <$box>::new(&public_key, &secret_key)
                .encrypt_in_place_detached(nonce, b"", &mut buffer)
                .unwrap();

            let (expected_tag, expected_ciphertext) = match TypeId::of::<$box>() {
                SALSABOX_TYPE => $ciphertext.split_at(16), // xsalsa20poly1035 use prefix tag
                _ => {
                    // for xchacha20poly1035 and others use standard postfix tag
                    let (ct, tag) = $ciphertext.split_at($ciphertext.len() - 16);
                    (tag, ct)
                }
            };
            assert_eq!(expected_tag, &tag[..]);
            assert_eq!(expected_ciphertext, &buffer[..]);
        }

        #[test]
        fn decrypt() {
            let secret_key = SecretKey::from(BOB_SECRET_KEY);
            let public_key = PublicKey::from(ALICE_PUBLIC_KEY);
            let nonce = GenericArray::from_slice(NONCE);

            let plaintext = <$box>::new(&public_key, &secret_key)
                .decrypt(nonce, $ciphertext)
                .unwrap();

            assert_eq!($plaintext, &plaintext[..]);
        }

        #[test]
        fn decrypt_in_place_detached() {
            let secret_key = SecretKey::from(BOB_SECRET_KEY);
            let public_key = PublicKey::from(ALICE_PUBLIC_KEY);
            let nonce = GenericArray::from_slice(NONCE);
            let (tag, mut buffer) = match TypeId::of::<$box>() {
                SALSABOX_TYPE => {
                    // xsalsa20poly1035 use prefix tag
                    (
                        GenericArray::clone_from_slice(&$ciphertext[..16]),
                        $ciphertext[16..].to_vec(),
                    )
                }
                _ => (
                    // for xchacha20poly1035 and others use standard postfix tag
                    GenericArray::clone_from_slice(&$ciphertext[$ciphertext.len() - 16..]),
                    $ciphertext[..$ciphertext.len() - 16].to_vec(),
                ),
            };

            <$box>::new(&public_key, &secret_key)
                .decrypt_in_place_detached(nonce, b"", &mut buffer, &tag)
                .unwrap();

            assert_eq!($plaintext, &buffer[..]);
        }
    };
}

mod salsa20poly1305 {
    use super::*;
    const CIPHERTEXT: &[u8] = &[
        0xc0, 0x3f, 0x27, 0xd1, 0x88, 0xef, 0x65, 0xc, 0xd1, 0x29, 0x36, 0x91, 0x31, 0x37, 0xbb,
        0x17, 0xed, 0x4c, 0x98, 0xc2, 0x64, 0x89, 0x39, 0xe2, 0xe1, 0xd2, 0xe8, 0x55, 0x47, 0xa,
        0x7b, 0x8c, 0x63, 0x2c, 0xab, 0xfd, 0x5a, 0xb3, 0xb3, 0xc2, 0xd3, 0x13, 0xdc, 0x8c, 0x9e,
        0xcf, 0x5d, 0xa1, 0x73, 0xe1, 0xf9, 0xc3, 0x18, 0xcd, 0xef, 0x1d, 0xce, 0xd6, 0xd2, 0x51,
        0x9e, 0x69, 0x50, 0x85, 0xe6, 0xb5, 0xc4, 0x1, 0xa2, 0xbd, 0x53, 0x31, 0x44, 0x29, 0x86,
        0xc7, 0x7, 0x6d, 0x41, 0x26, 0x25, 0x49, 0x7c, 0x4c, 0xb2, 0xfd, 0x94, 0xc6, 0xf1, 0x3,
        0x96, 0x10, 0x33, 0xb2, 0xc9, 0x30, 0xd7, 0xe8, 0x2e, 0x3, 0x41, 0xf2, 0x9d, 0x38, 0x79,
        0xbd, 0x6a, 0xb9, 0xd8, 0x81, 0xea, 0x3a, 0x1f, 0x36, 0x5d, 0x63, 0x4e, 0x65, 0x3c, 0x6e,
        0x17, 0x1a, 0xac, 0x7f, 0xc1, 0xe7, 0x69, 0x34, 0xd2, 0x3b, 0xe6, 0xf0, 0x4a, 0x54, 0x1,
        0x8, 0x8, 0xdb, 0xf0, 0xf9, 0xbd, 0x30, 0xf6, 0x3b, 0x68, 0xd0, 0x26,
    ];

    impl_tests!(SalsaBox, PLAINTEXT, CIPHERTEXT);
}

mod xchacha20poly1305 {
    use super::*;
    const CIPHERTEXT: &[u8] = &[
        0xe0, 0xba, 0xd6, 0xe5, 0x26, 0x2e, 0xe9, 0x87, 0x27, 0xa, 0xe, 0x9f, 0x78, 0xd9, 0x10,
        0x85, 0x1e, 0xd8, 0x9c, 0xe6, 0x6e, 0xfb, 0x46, 0x59, 0x10, 0x4e, 0x4c, 0xbf, 0x74, 0x6,
        0x2d, 0xd0, 0x82, 0x9d, 0x54, 0x27, 0x3b, 0xd1, 0x4e, 0x58, 0x97, 0xcc, 0xa4, 0xba, 0x98,
        0x8f, 0xe2, 0x5, 0xf5, 0x95, 0xf0, 0x29, 0x34, 0xb0, 0xc5, 0x4, 0x74, 0xf4, 0x18, 0x55,
        0xda, 0xf8, 0xf3, 0x7d, 0xa0, 0x16, 0x14, 0xdb, 0x49, 0xf3, 0x89, 0x16, 0x87, 0x95, 0xb1,
        0xeb, 0x67, 0x23, 0x21, 0xe5, 0xe, 0x7f, 0xba, 0xc1, 0xec, 0x65, 0xc7, 0xf8, 0x22, 0x36,
        0x2d, 0x6c, 0xa7, 0xb6, 0xcd, 0x51, 0x4b, 0xb, 0x3d, 0xb1, 0x81, 0x30, 0x6f, 0x23, 0x7d,
        0xc3, 0x44, 0xba, 0x12, 0xa4, 0x1b, 0x3c, 0x65, 0x69, 0xe9, 0xfd, 0x9d, 0xcf, 0xce, 0x68,
        0x8, 0xcc, 0xf4, 0xef, 0x6a, 0x27, 0xc2, 0x1b, 0x7c, 0xce, 0x2a, 0x3, 0xd8, 0xd4, 0x3b,
        0x8f, 0xa6, 0x4b, 0x29, 0x6, 0x2a, 0x46, 0x99, 0xa7, 0xad, 0x88, 0x52,
    ];

    impl_tests!(ChaChaBox, PLAINTEXT, CIPHERTEXT);
    // TODO: (alex) add test for non-empty associated data field
}
