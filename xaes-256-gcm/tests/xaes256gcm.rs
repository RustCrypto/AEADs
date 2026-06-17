//! XAES-256-GCM test vectors

#[macro_use]
#[path = "../../aes-gcm/tests/common/mod.rs"]
mod common;

use aes_gcm::aead::{Aead, AeadInOut, KeyInit, Payload, array::Array};
use common::TestVector;
use hex_literal::hex;
use shake::{ExtendableOutput, Shake128, Update, XofReader};
use xaes_256_gcm::{Key, Nonce, Xaes256Gcm};

/// C2SP XAES-256-GCM test vectors
///
/// <https://c2sp.org/XAES-256-GCM#test-vectors>
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

/// C2SP XAES-256-GCM accumulated randomized tests.
///
/// <https://c2sp.org/XAES-256-GCM#accumulated-randomized-tests>
fn run_accumulated_test(iterations: usize, expected: [u8; 32]) {
    let mut seed = Shake128::default().finalize_xof();
    let mut digest = Shake128::default();

    for _ in 0..iterations {
        let mut key = Key::<Xaes256Gcm>::default();
        seed.read(&mut key);
        let mut nonce = Nonce::default();
        seed.read(&mut nonce);
        let mut length = [0u8; 1];
        seed.read(&mut length);
        let mut plaintext = vec![0u8; length[0] as usize];
        seed.read(&mut plaintext);
        seed.read(&mut length);
        let mut aad = vec![0u8; length[0] as usize];
        seed.read(&mut aad);

        let cipher = Xaes256Gcm::new(&key);
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .unwrap();

        let decrypted = cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .unwrap();

        assert_eq!(plaintext, decrypted);

        digest.update(&ciphertext);
    }

    let mut reader = digest.finalize_xof();
    let mut buf = [0u8; 32];
    reader.read(&mut buf);
    assert_eq!(expected, buf);
}

#[test]
fn accumulated_randomized_10_000_iterations() {
    run_accumulated_test(
        10_000,
        hex!("e6b9edf2df6cec60c8cbd864e2211b597fb69a529160cd040d56c0c210081939"),
    );
}

#[test]
#[ignore = "slow in debug; run with `cargo test --release -- --include-ignored`"]
fn accumulated_randomized_1_000_000_iterations() {
    run_accumulated_test(
        1_000_000,
        hex!("2163ae1445985a30b60585ee67daa55674df06901b890593e824b8a7c885ab15"),
    );
}
