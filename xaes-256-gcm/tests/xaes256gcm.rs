//! XAES-256-GCM test vectors

#[macro_use]
#[path = "../../aes-gcm/tests/common/mod.rs"]
mod common;

use aes_gcm::aead::{Aead, AeadInOut, KeyInit, Payload, array::Array};
use common::TestVector;
use hex_literal::hex;
use xaes_256_gcm::Xaes256Gcm;

/// C2SP XAES-256-GCM test vectors
///
/// <https://github.com/C2SP/C2SP/blob/main/XAES-256-GCM.md>
const TEST_VECTORS: &[TestVector<[u8; 32], [u8; 24]>] = &[
    TestVector {
        key: &hex!("0101010101010101010101010101010101010101010101010101010101010101"),
        nonce: b"ABCDEFGHIJKLMNOPQRSTUVWX",
        plaintext: b"XAES-256-GCM",
        aad: b"",
        ciphertext: &hex!("ce546ef63c9cc60765923609"),
        tag: &hex!("b33a9a1974e96e52daf2fcf7075e2271"),
    },
    TestVector {
        key: &hex!("0303030303030303030303030303030303030303030303030303030303030303"),
        nonce: b"ABCDEFGHIJKLMNOPQRSTUVWX",
        plaintext: b"XAES-256-GCM",
        aad: b"c2sp.org/XAES-256-GCM",
        ciphertext: &hex!("986ec1832593df5443a17943"),
        tag: &hex!("7fd083bf3fdb41abd740a21f71eb769d"),
    },
];

tests!(Xaes256Gcm, TEST_VECTORS);
