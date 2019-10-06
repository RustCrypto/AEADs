//! AES-128-GCM tests

#[macro_use]
extern crate hex_literal;

#[macro_use]
mod common;

use self::common::TestVector;
use aes_gcm::aead::{generic_array::GenericArray, Aead, NewAead, Payload};
use aes_gcm::Aes128Gcm;

/// NIST CAVS vectors
///
/// <https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/CAVP-TESTING-BLOCK-CIPHER-MODES>
///
/// From: `gcmEncryptExtIV128.rsp`
const TEST_VECTORS: &[TestVector<[u8; 16]>] = &[
    TestVector {
        key: &hex!("11754cd72aec309bf52f7687212e8957"),
        nonce: &hex!("3c819d9a9bed087615030b65"),
        aad: b"",
        plaintext: b"",
        ciphertext: &hex!("250327c674aaf477aef2675748cf6971"),
    },
    TestVector {
        key: &hex!("7fddb57453c241d03efbed3ac44e371c"),
        nonce: &hex!("ee283a3fc75575e33efd4887"),
        aad: b"",
        plaintext: &hex!("d5de42b461646c255c87bd2962d3b9a2"),
        ciphertext: &hex!("2ccda4a5415cb91e135c2a0f78c9b2fdb36d1df9b9d5e596f83e8b7f52971cb3"),
    },
    TestVector {
        key: &hex!("c939cc13397c1d37de6ae0e1cb7c423c"),
        nonce: &hex!("b3d8cc017cbb89b39e0f67e2"),
        plaintext: &hex!("c3b3c41f113a31b73d9a5cd432103069"),
        aad: &hex!("24825602bd12a984e0092d3e448eda5f"),
        ciphertext: &hex!("93fe7d9e9bfd10348a5606e5cafa73540032a1dc85f1c9786925a2e71d8272dd"),
    },
];

tests!(Aes128Gcm, TEST_VECTORS);
