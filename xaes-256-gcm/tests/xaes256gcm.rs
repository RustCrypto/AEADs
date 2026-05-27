//! XAES-256-GCM test vectors

use aes_gcm::aead::{Aead, AeadCore, KeyInit, Payload, array::Array};
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

/// Test vectors
#[derive(Debug)]
pub struct TestVector<K: 'static, N: 'static> {
    pub key: &'static K,
    pub nonce: &'static N,
    pub aad: &'static [u8],
    pub plaintext: &'static [u8],
    pub ciphertext: &'static [u8],
    pub tag: &'static [u8; 16],
}

#[macro_export]
macro_rules! tests {
    ($aead:ty, $vectors:expr) => {
        #[test]
        fn encrypt() {
            for vector in $vectors {
                let key = Array(*vector.key);
                let nonce = Array(*vector.nonce);
                let payload = Payload {
                    msg: vector.plaintext,
                    aad: vector.aad,
                };

                let cipher = <$aead>::new(&key);
                let ciphertext = cipher.encrypt(&nonce, payload).unwrap();
                let (ct, tag) = ciphertext.split_at(ciphertext.len() - 16);
                assert_eq!(
                    vector.ciphertext, ct,
                    "ciphertext mismatch (expected != actual)"
                );
                assert_eq!(vector.tag, tag, "tag mismatch (expected != actual)");
            }
        }

        #[test]
        fn decrypt() {
            for vector in $vectors {
                let key = Array(*vector.key);
                let nonce = Array(*vector.nonce);
                let mut ciphertext = Vec::from(vector.ciphertext);
                ciphertext.extend_from_slice(vector.tag);

                let payload = Payload {
                    msg: &ciphertext,
                    aad: vector.aad,
                };

                let cipher = <$aead>::new(&key);
                let plaintext = cipher.decrypt(&nonce, payload).unwrap();

                assert_eq!(vector.plaintext, plaintext.as_slice(), "plaintext mismatch");
            }
        }

        #[test]
        fn decrypt_modified() {
            let vector = &$vectors[0];
            let key = Array(*vector.key);
            let nonce = Array(*vector.nonce);

            let mut ciphertext = Vec::from(vector.ciphertext);
            ciphertext.extend_from_slice(vector.tag);

            // Tweak the first byte
            ciphertext[0] ^= 0xaa;

            let payload = Payload {
                msg: &ciphertext,
                aad: vector.aad,
            };

            let cipher = <$aead>::new(&key);
            assert!(cipher.decrypt(&nonce, payload).is_err());
        }

        #[test]
        fn decrypt_in_place_detached_modified() {
            let vector = &$vectors.iter().last().unwrap();
            let key = Array(*vector.key);
            let nonce = Array(*vector.nonce);

            let mut buffer = Vec::from(vector.ciphertext);
            assert!(!buffer.is_empty());

            // Tweak the first byte
            let mut tag = Array(*vector.tag);
            tag[0] ^= 0xaa;

            let cipher = <$aead>::new(&key);
            assert!(
                cipher
                    .decrypt_inout_detached(&nonce, &[], buffer.as_mut_slice().into(), &tag)
                    .is_err()
            );

            assert_eq!(vector.ciphertext, buffer);
        }
    };
}

tests!(Xaes256Gcm, TEST_VECTORS);
