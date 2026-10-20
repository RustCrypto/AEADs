//! Common functionality shared by tests

/// AEAD test vector.
#[derive(Debug)]
pub struct TestVector<K: 'static, N: 'static, T: 'static> {
    pub key: &'static K,
    pub nonce: &'static N,
    pub aad: &'static [u8],
    pub plaintext: &'static [u8],
    pub ciphertext: &'static [u8],
    pub tag: &'static T,
}

/// Generate encryption, decryption and tampering tests for an AEAD.
#[macro_export]
macro_rules! tests {
    ($aead:ty, $vectors:expr) => {
        use bash_prg_ae::aead::{Aead, AeadInOut, KeyInit, Payload, array::Array};

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
                let (ct, tag) = ciphertext.split_at(ciphertext.len() - vector.tag.len());
                assert_eq!(vector.ciphertext, ct);
                assert_eq!(vector.tag, tag);
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

                assert_eq!(vector.plaintext, plaintext.as_slice());
            }
        }

        #[test]
        fn decrypt_modified() {
            let vector = &$vectors[0];
            let key = Array(*vector.key);
            let nonce = Array(*vector.nonce);

            let mut ciphertext = Vec::from(vector.ciphertext);
            ciphertext.extend_from_slice(vector.tag);
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
            let vector = &$vectors[$vectors.len() - 1];
            let key = Array(*vector.key);
            let nonce = Array(*vector.nonce);

            let mut buffer = Vec::from(vector.ciphertext);
            let mut tag = Array(*vector.tag);
            tag[0] ^= 0xaa;

            let cipher = <$aead>::new(&key);
            assert!(
                cipher
                    .decrypt_inout_detached(&nonce, vector.aad, buffer.as_mut_slice().into(), &tag)
                    .is_err()
            );
            assert_eq!(vector.ciphertext, buffer);
        }
    };
}
