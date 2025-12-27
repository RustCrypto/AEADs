//! DNDK-GCM test vectors (KC_Choice = 0)

#[macro_use]
#[path = "../../aes-gcm/tests/common/mod.rs"]
mod common;

use aes_gcm::aead::{Aead, AeadInOut, KeyInit, Payload, array::Array};
use common::TestVector;
use dndk_gcm::{DndkGcm12, DndkGcm24};
use hex_literal::hex;

/// DNDK-GCM test vectors (draft-gueron-cfrg-dndkgcm-03, Appendix A)
const TEST_VECTORS_24: &[TestVector<[u8; 32], [u8; 24]>] = &[
    TestVector {
        key: &hex!("0100000000000000000000000000000000000000000000000000000000000000"),
        nonce: &hex!("000102030405060708090a0b0c0d0e0f1011121314151617"),
        plaintext: &hex!("11000001"),
        aad: &hex!("0100000011"),
        ciphertext: &hex!("7f6e39cc"),
        tag: &hex!("b61df0a502c167164e99fa23b7d12b9d"),
    },
];

/// DNDK-GCM test vectors (draft-gueron-cfrg-dndkgcm-03, Appendix A)
const TEST_VECTORS_12: &[TestVector<[u8; 32], [u8; 12]>] = &[
    TestVector {
        key: &hex!("0100000000000000000000000000000000000000000000000000000000000000"),
        nonce: &hex!("000102030405060708090a0b"),
        plaintext: &hex!("11000001"),
        aad: &hex!("0100000011"),
        ciphertext: &hex!("b95cf258"),
        tag: &hex!("39e74511d997eaafd0f567d13758305b"),
    },
];

tests!(DndkGcm24, TEST_VECTORS_24);

mod dndk_gcm12 {
    use super::*;
    tests!(DndkGcm12, TEST_VECTORS_12);
}
