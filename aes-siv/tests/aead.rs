#[macro_use]
extern crate hex_literal;

/// Test vectors
#[derive(Debug)]
pub struct TestVector<K: 'static> {
    pub key: &'static K,
    pub nonce: &'static [u8; 16],
    pub aad: &'static [u8],
    pub plaintext: &'static [u8],
    pub ciphertext: &'static [u8],
}

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

                let cipher = <$aead>::new(key);
                let ciphertext = cipher.encrypt(nonce, payload).unwrap();
                assert_eq!(vector.ciphertext, ciphertext.as_slice());
            }
        }

        #[test]
        fn encrypt_in_place_detached() {
            for vector in $vectors {
                let key = GenericArray::from_slice(vector.key);
                let nonce = GenericArray::from_slice(vector.nonce);
                let mut buffer = vector.plaintext.to_vec();

                let cipher = <$aead>::new(key);
                let tag = cipher
                    .encrypt_in_place_detached(nonce, vector.aad, &mut buffer)
                    .unwrap();
                let (expected_tag, expected_ciphertext) = vector.ciphertext.split_at(16);
                assert_eq!(expected_tag, &tag[..]);
                assert_eq!(expected_ciphertext, &buffer[..]);
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

                let cipher = <$aead>::new(key);
                let plaintext = cipher.decrypt(nonce, payload).unwrap();

                assert_eq!(vector.plaintext, plaintext.as_slice());
            }
        }

        #[test]
        fn decrypt_in_place_detached() {
            for vector in $vectors {
                let key = GenericArray::from_slice(vector.key);
                let nonce = GenericArray::from_slice(vector.nonce);
                let tag = GenericArray::clone_from_slice(&vector.ciphertext[..16]);
                let mut buffer = vector.ciphertext[16..].to_vec();

                <$aead>::new(key)
                    .decrypt_in_place_detached(nonce, vector.aad, &mut buffer, &tag)
                    .unwrap();

                assert_eq!(vector.plaintext, buffer.as_slice());
            }
        }

        #[test]
        fn decrypt_modified() {
            let vector = &$vectors[0];
            let key = GenericArray::from_slice(vector.key);
            let nonce = GenericArray::from_slice(vector.nonce);
            let mut ciphertext = Vec::from(vector.ciphertext);

            // Tweak the first byte
            ciphertext[0] ^= 0xaa;

            let payload = Payload {
                msg: &ciphertext,
                aad: vector.aad,
            };

            let cipher = <$aead>::new(key);
            assert!(cipher.decrypt(nonce, payload).is_err());

            // TODO(tarcieri): test ciphertext is unmodified in in-place API
        }
    };
}

mod aes128cmacsivaead {
    use super::TestVector;
    use aes_siv::aead::{generic_array::GenericArray, Aead, AeadInPlace, KeyInit, Payload};
    use aes_siv::Aes128SivAead;

    /// AES-128-CMAC-SIV test vectors
    const TEST_VECTORS: &[TestVector<[u8; 32]>] = &[
        TestVector {
            key: &hex!("7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f"),
            nonce: &hex!("09f911029d74e35bd84156c5635688c0"),
            aad: &hex!("00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100"),
            plaintext: &hex!("7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553"),
            ciphertext: &hex!("85825e22e90cf2ddda2c548dc7c1b6310dcdaca0cebf9dc6cb90583f5bf1506e02cd48832b00e4e598b2b22a53e6199d4df0c1666a35a0433b250dc134d776"),
        },
    ];

    tests!(Aes128SivAead, TEST_VECTORS);
}

#[cfg(feature = "pmac")]
mod aes128pmacsivaead {
    use super::TestVector;
    use aes_siv::aead::{generic_array::GenericArray, Aead, AeadInPlace, KeyInit, Payload};
    use aes_siv::Aes128PmacSivAead;

    /// AES-128-PMAC-SIV test vectors
    const AES_128_PMAC_SIV_TEST_VECTORS: &[TestVector<[u8; 32]>] = &[
        TestVector {
            key: &hex!("7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f"),
            nonce: &hex!("09f911029d74e35bd84156c5635688c0"),
            aad: &hex!("00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100"),
            plaintext: &hex!("7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553"),
            ciphertext: &hex!("1463d1119b2a2797241bb1674633dff13b9de11e5e2f526048b36c40c7722667b2957018023bf0e52792b703a01e88aacd49898cecfce943d7f61a2337a097"),
        },
    ];

    tests!(Aes128PmacSivAead, AES_128_PMAC_SIV_TEST_VECTORS);
}
