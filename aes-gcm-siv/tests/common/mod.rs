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
                let key = GenericArray::from_slice(vector.key);
                let nonce = GenericArray::from_slice(vector.nonce);
                let payload = Payload {
                    msg: vector.plaintext,
                    aad: vector.aad,
                };

                let cipher = <$aead>::new(*key);
                let ciphertext = cipher.encrypt(nonce, payload).unwrap();

                assert_eq!(vector.ciphertext, ciphertext.as_slice());
            }
        }

        #[test]
        fn decrypt() {
            for vector in $vectors {
                let key = GenericArray::from_slice(vector.key);
                let nonce = GenericArray::from_slice(vector.nonce);

                let payload = Payload {
                    msg: vector.ciphertext,
                    aad: vector.aad,
                };

                let cipher = <$aead>::new(*key);
                let plaintext = cipher.decrypt(nonce, payload).unwrap();

                assert_eq!(vector.plaintext, plaintext.as_slice());
            }
        }
    };
}
