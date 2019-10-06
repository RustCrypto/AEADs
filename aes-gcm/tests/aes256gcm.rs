//! AES-256-GCM tests

#[macro_use]
extern crate hex_literal;

#[macro_use]
mod common;

use self::common::TestVector;
use aes_gcm::aead::{generic_array::GenericArray, Aead, NewAead, Payload};
use aes_gcm::Aes256Gcm;

/// NIST CAVS vectors
///
/// <https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/CAVP-TESTING-BLOCK-CIPHER-MODES>
///
/// From: `gcmEncryptExtIV256.rsp`
const TEST_VECTORS: &[TestVector<[u8; 32]>] = &[
    TestVector {
        key: &hex!("b52c505a37d78eda5dd34f20c22540ea1b58963cf8e5bf8ffa85f9f2492505b4"),
        nonce: &hex!("516c33929df5a3284ff463d7"),
        aad: b"",
        plaintext: b"",
        ciphertext: &hex!("bdc1ac884d332457a1d2664f168c76f0"),
    },
    TestVector {
        key: &hex!("460fc864972261c2560e1eb88761ff1c992b982497bd2ac36c04071cbb8e5d99"),
        nonce: &hex!("8a4a16b9e210eb68bcb6f58d"),
        plaintext: &hex!("99e4e926ffe927f691893fb79a96b067"),
        aad: b"",
        ciphertext: &hex!("133fc15751621b5f325c7ff71ce08324ec4e87e0cf74a13618d0b68636ba9fa7"),
    },
    TestVector {
        key: &hex!("31bdadd96698c204aa9ce1448ea94ae1fb4a9a0b3c9d773b51bb1822666b8f22"),
        nonce: &hex!("0d18e06c7c725ac9e362e1ce"),
        aad: b"",
        plaintext: &hex!("2db5168e932556f8089a0622981d017d"),
        ciphertext: &hex!("fa4362189661d163fcd6a56d8bf0405ad636ac1bbedd5cc3ee727dc2ab4a9489"),
    },
    TestVector {
        key: &hex!("92e11dcdaa866f5ce790fd24501f92509aacf4cb8b1339d50c9c1240935dd08b"),
        nonce: &hex!("ac93a1a6145299bde902f21a"),
        aad: &hex!("1e0889016f67601c8ebea4943bc23ad6"),
        plaintext: &hex!("2d71bcfa914e4ac045b2aa60955fad24"),
        ciphertext: &hex!("8995ae2e6df3dbf96fac7b7137bae67feca5aa77d51d4a0a14d9c51e1da474ab"),
    },
];

tests!(Aes256Gcm, TEST_VECTORS);
