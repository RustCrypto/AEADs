//! Common functionality shared by tests

/// Test vectors
#[derive(Debug)]
pub struct TestVector<K: 'static> {
    pub key: &'static K,
    pub nonce: &'static [u8; 12],
    pub aad: &'static [u8],
    pub plaintext: &'static [u8],
    pub ciphertext: &'static [u8],
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

                assert_eq!(vector.ciphertext, ciphertext.as_slice());
            }
        }

        #[test]
        fn decrypt() {
            for vector in $vectors {
                let key = Array(*vector.key);
                let nonce = Array(*vector.nonce);

                let payload = Payload {
                    msg: vector.ciphertext,
                    aad: vector.aad,
                };

                let cipher = <$aead>::new(&key);
                let plaintext = cipher.decrypt(&nonce, payload).unwrap();

                assert_eq!(vector.plaintext, plaintext.as_slice());
            }
        }

        #[test]
        fn decrypt_modified() {
            let vector = &$vectors[1];
            let key = Array(*vector.key);
            let nonce = Array(*vector.nonce);

            let mut ciphertext = Vec::from(vector.ciphertext);

            // Tweak the first byte
            ciphertext[0] ^= 0xaa;

            let payload = Payload {
                msg: &ciphertext,
                aad: vector.aad,
            };

            let cipher = <$aead>::new(&key);
            assert!(cipher.decrypt(&nonce, payload).is_err());

            // TODO(tarcieri): test ciphertext is unmodified in in-place API
        }
    };
}
