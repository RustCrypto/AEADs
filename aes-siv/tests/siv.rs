//! AES-SIV tests for the raw SIV interface

use aes_siv::aead::generic_array::GenericArray;

/// Test vectors
#[derive(Debug)]
pub struct TestVector<K: 'static> {
    pub key: &'static K,
    pub aad: &'static [&'static [u8]],
    pub plaintext: &'static [u8],
    pub ciphertext: &'static [u8],
}

macro_rules! tests {
    ($siv:ty, $vectors:expr) => {
        #[test]
        fn encrypt() {
            for vector in $vectors {
                let mut cipher = <$siv>::new(GenericArray::from_slice(vector.key));
                let ciphertext = cipher.encrypt(vector.aad, vector.plaintext).unwrap();
                assert_eq!(vector.ciphertext, ciphertext.as_slice());
            }
        }

        #[test]
        fn decrypt() {
            for vector in $vectors {
                let mut cipher = <$siv>::new(GenericArray::from_slice(vector.key));
                let plaintext = cipher.decrypt(vector.aad, vector.ciphertext).unwrap();
                assert_eq!(vector.plaintext, plaintext.as_slice());
            }
        }

        #[test]
        fn decrypt_modified() {
            let vector = &$vectors[0];
            let mut ciphertext = Vec::from(vector.ciphertext);

            // Tweak the first byte
            ciphertext[0] ^= 0xaa;

            let mut cipher = <$siv>::new(GenericArray::from_slice(vector.key));
            assert!(cipher.decrypt(vector.aad, &ciphertext).is_err());

            // TODO(tarcieri): test ciphertext is unmodified in in-place API
        }
    };
}

macro_rules! wycheproof_tests {
    ($siv:ty, $name:ident, $test_name:expr) => {
        #[test]
        fn $name() {
            use blobby::Blob5Iterator;

            let data = include_bytes!(concat!("data/", $test_name, ".blb"));
            fn run_test(
                key: &[u8],
                aad: &[u8],
                pt: &[u8],
                ct: &[u8],
                pass: bool,
            ) -> Option<&'static str> {
                let mut cipher = <$siv>::new(GenericArray::from_slice(key));
                let ciphertext = cipher.encrypt(&[aad], pt).unwrap();
                if pass && ct != ciphertext.as_slice() {
                    return Some("encryption mismatch");
                }
                if !pass && ct == ciphertext.as_slice() {
                    return Some("unexpected encryption match");
                }

                match cipher.decrypt(&[aad], ct) {
                    Ok(_plaintext) if !pass => Some("unexpected decryption success"),
                    Ok(plaintext) => {
                        if pt == plaintext.as_slice() {
                            None
                        } else {
                            Some("decryption mismatch")
                        }
                    }
                    Err(_) if pass => Some("decryption failure"),
                    Err(_) => None,
                }
            }

            for (i, row) in Blob5Iterator::new(data).unwrap().enumerate() {
                let [key, aad, pt, ct, status] = row.unwrap();
                let pass = match status[0] {
                    0 => false,
                    1 => true,
                    _ => panic!("invalid value for pass flag"),
                };
                if let Some(desc) = run_test(key, aad, pt, ct, pass) {
                    panic!(
                        "\n\
                         Failed test №{}: {}\n\
                         key:\t{:?}\n\
                         aad:\t{:?}\n\
                         pt:\t{:?}\n\
                         ct:\t{:?}\n\
                         pass:\t{:?}\n",
                        i, desc, key, aad, pt, ct, pass,
                    );
                }
            }
        }
    };
}

mod aes128cmacsiv {
    use super::{GenericArray, TestVector};
    use aes_siv::{siv::Aes128Siv, KeyInit};
    use hex_literal::hex;

    /// AES-128-CMAC-SIV test vectors
    const TEST_VECTORS: &[TestVector<[u8; 32]>] = &[
        TestVector {
            key: &hex!("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
            aad: &[&hex!("101112131415161718191a1b1c1d1e1f2021222324252627")],
            plaintext: &hex!("112233445566778899aabbccddee"),
            ciphertext: &hex!("85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c")
        },
        TestVector {
            key: &hex!("7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f"),
            aad: &[
                &hex!("00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100"),
                &hex!("102030405060708090a0"),
                &hex!("09f911029d74e35bd84156c5635688c0")
            ],
            plaintext: &hex!("7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553"),
            ciphertext: &hex!("7bdb6e3b432667eb06f4d14bff2fbd0fcb900f2fddbe404326601965c889bf17dba77ceb094fa663b7a3f748ba8af829ea64ad544a272e9c485b62a3fd5c0d")
        },
        TestVector {
            key: &hex!("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
            aad: &[],
            plaintext: b"",
            ciphertext: &hex!("f2007a5beb2b8900c588a7adf599f172")
        },
        TestVector {
            key: &hex!("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
            aad: &[],
            plaintext: &hex!("00112233445566778899aabbccddeeff"),
            ciphertext: &hex!("f304f912863e303d5b540e5057c7010c942ffaf45b0e5ca5fb9a56a5263bb065")
        }
    ];

    tests!(Aes128Siv, TEST_VECTORS);

    wycheproof_tests!(Aes128Siv, wycheproof, "wycheproof-256");
}

mod aes256cmacsiv {
    use super::{GenericArray, TestVector};
    use aes_siv::{siv::Aes256Siv, KeyInit};
    use hex_literal::hex;

    /// AES-256-CMAC-SIV test vectors
    const TEST_VECTORS: &[TestVector<[u8; 64]>] = &[
        TestVector {
            key: &hex!("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f06f6e6d6c6b6a69686766656463626160f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f"),
            aad: &[&hex!("101112131415161718191a1b1c1d1e1f2021222324252627")],
            plaintext:&hex!("112233445566778899aabbccddee"),
            ciphertext:&hex!("f125274c598065cfc26b0e71575029088b035217e380cac8919ee800c126")
        },
        TestVector {
            key:&hex!("7f7e7d7c7b7a797877767574737271706f6e6d6c6b6a69686766656463626160404142434445464748494a4b4c4d4e4f505152535455565758595a5b5b5d5e5f"),
            aad: &[
                &hex!("00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100"),
                &hex!("102030405060708090a0"),
                &hex!("09f911029d74e35bd84156c5635688c0")
            ],
            plaintext: &hex!("7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553"),
            ciphertext: &hex!("85b8167310038db7dc4692c0281ca35868181b2762f3c24f2efa5fb80cb143516ce6c434b898a6fd8eb98a418842f51f66fc67de43ac185a66dd72475bbb08")
        },
    ];

    tests!(Aes256Siv, TEST_VECTORS);

    wycheproof_tests!(Aes256Siv, wycheproof, "wycheproof-512");
}

#[cfg(feature = "pmac")]
mod aes128pmaccsiv {
    use super::{GenericArray, TestVector};
    use aes_siv::{siv::Aes128PmacSiv, KeyInit};
    use hex_literal::hex;

    /// AES-128-PMAC-SIV test vectors
    const TEST_VECTORS: &[TestVector<[u8; 32]>] = &[
        TestVector {
            key: &hex!("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
            aad: &[&hex!("101112131415161718191a1b1c1d1e1f2021222324252627")],
            plaintext: &hex!("112233445566778899aabbccddee"),
            ciphertext: &hex!("8c4b814216140fc9b34a41716aa61633ea66abe16b2f6e4bceeda6e9077f")
        },
        TestVector {
            key: &hex!("7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f"),
            aad: &[
                &hex!("00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100"),
                &hex!("102030405060708090a0"),
                &hex!("09f911029d74e35bd84156c5635688c0")
            ],
            plaintext: &hex!("7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553"),
            ciphertext: &hex!("acb9cbc95dbed8e766d25ad59deb65bcda7aff9214153273f88e89ebe580c77defc15d28448f420e0a17d42722e6d42776849aa3bec375c5a05e54f519e9fd")
        },
        TestVector {
            key: &hex!("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
            aad: &[],
            plaintext: &hex!(""),
            ciphertext: &hex!("19f25e5ea8a96ef27067d4626fdd3677")
        },
        TestVector {
            key: &hex!("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
            aad: &[&hex!("101112131415161718191a1b1c1d1e1f2021222324252627")],
            plaintext: &hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f70"),
            ciphertext: &hex!("34cbb315120924e6ad05240a1582018b3dc965941308e0535680344cf9cf40cb5aa00b449548f9a4d9718fd22057d19f5ea89450d2d3bf905e858aaec4fc594aa27948ea205ca90102fc463f5c1cbbfb171d296d727ec77f892fb192a4eb9897b7d48d50e474a1238f02a82b122a7b16aa5cc1c04b10b839e478662ff1cec7cabc")
        },
    ];

    tests!(Aes128PmacSiv, TEST_VECTORS);
}

#[cfg(feature = "pmac")]
mod aes256pmaccsiv {
    use super::{GenericArray, TestVector};
    use aes_siv::{siv::Aes256PmacSiv, KeyInit};
    use hex_literal::hex;

    /// AES-256-PMAC-SIV test vectors
    const TEST_VECTORS: &[TestVector<[u8; 64]>] = &[
        TestVector {
            key: &hex!("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f06f6e6d6c6b6a69686766656463626160f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f"),
            aad: &[&hex!("101112131415161718191a1b1c1d1e1f2021222324252627")],
            plaintext: &hex!("112233445566778899aabbccddee"),
            ciphertext: &hex!("77097bb3e160988e8b262c1942f983885f826d0d7e047e975e2fc4ea6776")
        },
        TestVector {
            key: &hex!("7f7e7d7c7b7a797877767574737271706f6e6d6c6b6a69686766656463626160404142434445464748494a4b4c4d4e4f505152535455565758595a5b5b5d5e5f"),
            aad: &[
                &hex!("00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100"),
                &hex!("102030405060708090a0"),
                &hex!("09f911029d74e35bd84156c5635688c0")
            ],
            plaintext: &hex!("7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553"),
            ciphertext: &hex!("cd07d56dca0fe1569b8ecb3cf2346604290726e12529fc5948546b6be39fed9cd8652256c594c8f56208c7496789de8dfb4f161627c91482f9ecf809652a9e")
        },
        TestVector {
            key: &hex!("7f7e7d7c7b7a797877767574737271706f6e6d6c6b6a69686766656463626160404142434445464748494a4b4c4d4e4f505152535455565758595a5b5b5d5e5f"),
            aad: &[&hex!("101112131415161718191a1b1c1d1e1f2021222324252627")],
            plaintext: &hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f70"),
            ciphertext: &hex!("045ba64522c5c980835674d1c5a9264eca3e9f7aceafe9b5485b33f7d2c9114fe5c4b24f9c814d88e78b6150028d630289d023015b8569af338de0af8534827732b365ace1ac99d278431b22eafe31b94297b1c6a2de41383ed8b39f17e748aea128a8bd7d0ee80ec899f1b940c9c0463f22fc2b5a145cb6e90a32801dd1950f92")
        }
    ];

    tests!(Aes256PmacSiv, TEST_VECTORS);
}
