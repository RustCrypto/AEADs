#[cfg(any(feature = "arrayvec", feature = "alloc"))]
pub fn to_test_vector(test_vec: u128, size: usize) -> u128 {
    let mut output = 0u128;

    for i in 0..size {
        let byte = (test_vec >> i * 8) & 0xff;
        output += byte << ((size - 1) * 8 - (i * 8));
    }

    output
}

#[cfg(any(feature = "arrayvec", feature = "alloc"))]
macro_rules! test_encrypt_for {
    ($name:tt, $type: ty) => {
        #[test]
        fn $name() {
            // Init and load keys into the cipher
            let key = [0u8; 16];
            let nonce = [0u8; 12];

            let mut buffer = <$type>::new();
            for i in 0..7 {
                buffer.push(i);
            }

            let cipher = Grain128::new(&key.into());

            cipher
                .encrypt_in_place(&nonce.into(), b"this is authenticated data", &mut buffer)
                .expect("Unable to encrypt");
            cipher
                .decrypt_in_place(&nonce.into(), b"this is authenticated data", &mut buffer)
                .expect("Unable to decrypt");
        }
    };
}

#[cfg(any(feature = "arrayvec", feature = "alloc"))]
macro_rules! test_encrypt_test_vectors_for {
    ($name:tt, $type: ty) => {
        #[test]
        fn $name() {
            // First set of pt/ad test vectors
            let tag = 0x7137d5998c2de4a5u128;
            // Init and load keys into the cipher
            let key = [0u8; 16];
            let nonce = [0u8; 12];

            let mut buffer = <$type>::new();
            let cipher = Grain128::new(&key.into());

            cipher
                .encrypt_in_place(&nonce.into(), b"", &mut buffer)
                .expect("Unable to encrypt");

            assert_eq!(
                tag,
                to_test_vector(
                    u64::from_le_bytes(buffer[..8].try_into().expect("Unable to get the tag"))
                        as u128,
                    8
                )
            );

            // First set of pt/ad test vectors
            let tag = 0x22b0c12039a20e28u128;
            let ct = 0x96d1bda7ae11f0bau128;

            // Init and load keys into the cipher
            let key: [u8; 16] = core::array::from_fn(|i| i as u8);
            let nonce: [u8; 12] = core::array::from_fn(|i| i as u8);
            let ad: [u8; 8] = [0, 1, 2, 3, 4, 5, 6, 7];

            let mut buffer = <$type>::new();
            for i in 0..8 {
                buffer.push(i);
            }

            let cipher = Grain128::new(&key.into());
            cipher
                .encrypt_in_place(&nonce.into(), &ad, &mut buffer)
                .expect("Unable to encrypt");

            let computed_ct = to_test_vector(
                u64::from_le_bytes(buffer[..8].try_into().expect("Unable to get the tag")) as u128,
                8,
            );
            let computed_tag = to_test_vector(
                u64::from_le_bytes(buffer[8..].try_into().expect("Unable to get the tag")) as u128,
                8,
            );

            assert_eq!(tag, computed_tag);
            assert_eq!(ct, computed_ct);
        }
    };
}

#[cfg(any(feature = "arrayvec", feature = "alloc"))]
macro_rules! test_bad_ct_for {
    ($name:tt, $type: ty) => {
        #[test]
        #[should_panic(expected = "Unable to decrypt")]
        fn $name() {
            // Init and load keys into the cipher
            let key = [0u8; 16];
            let nonce = [0u8; 12];

            let mut buffer = <$type>::new();
            for i in 0..8 {
                buffer.push(i);
            }

            let cipher = Grain128::new(&key.into());

            cipher
                .encrypt_in_place(&nonce.into(), b"", &mut buffer)
                .expect("Unable to encrypt");

            // Change the ciphertext
            buffer[0] = 0;

            match cipher.decrypt_in_place(&nonce.into(), b"", &mut buffer) {
                Ok(_) => {
                    panic!("Encryption should fail");
                }
                Err(_) => {
                    // Ensure that the buffer is filled with zeroes
                    // in case of a tag verification failure
                    for i in 0..8 {
                        assert_eq!(buffer[i], 0);
                    }

                    panic!("Unable to decrypt");
                }
            }
        }
    };
}

#[cfg(any(feature = "arrayvec", feature = "alloc"))]
macro_rules! test_bad_tag_for {
    ($name:tt, $type: ty) => {
        #[test]
        #[should_panic(expected = "Unable to decrypt")]
        fn $name() {
            // Init and load keys into the cipher
            let key = [0u8; 16];
            let nonce = [0u8; 12];

            let mut buffer = <$type>::new();
            for i in 0..8 {
                buffer.push(i);
            }

            let cipher = Grain128::new(&key.into());

            cipher
                .encrypt_in_place(&nonce.into(), b"", &mut buffer)
                .expect("Unable to encrypt");

            // Change tag
            buffer[10] = 0;

            match cipher.decrypt_in_place(&nonce.into(), b"", &mut buffer) {
                Ok(_) => {
                    panic!("Encryption should fail");
                }
                Err(_) => {
                    // Ensure that the buffer is filled with zeroes
                    // in case of a tag verification failure
                    for i in 0..8 {
                        assert_eq!(buffer[i], 0);
                    }

                    panic!("Unable to decrypt");
                }
            }
        }
    };
}

#[cfg(feature = "alloc")]
mod test_alloc {
    use super::*;

    use grain_128aeadv2::Grain128;
    use grain_128aeadv2::KeyInit;
    use grain_128aeadv2::aead::AeadInOut;

    test_encrypt_for!(test_encrypt_vec, Vec<u8>);
    test_encrypt_test_vectors_for!(test_encrypt_test_vectors_vec, Vec<u8>);
    test_bad_ct_for!(test_bad_ct_vec, Vec<u8>);
    test_bad_tag_for!(test_bad_tag_vec, Vec<u8>);
}

#[cfg(feature = "arrayvec")]
mod test_arrayvec {
    use super::*;

    use grain_128aeadv2::Grain128;
    use grain_128aeadv2::KeyInit;
    use grain_128aeadv2::aead::AeadInOut;
    use grain_128aeadv2::aead::arrayvec::ArrayVec;

    test_encrypt_for!(test_encrypt_arrayvec, ArrayVec<u8, 16>);
    test_encrypt_test_vectors_for!(test_encrypt_test_vectors_arrayvec, ArrayVec<u8, 16>);
    test_bad_ct_for!(test_bad_ct_arrayvec, ArrayVec<u8, 16>);
    test_bad_tag_for!(test_bad_tag_arrayvec, ArrayVec<u8, 16>);
}
