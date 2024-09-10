use aes_gcm::aead::{ Aead, AeadInto, Payload };
use aes_gcm::{ Aes256Gcm, KeyInit };


/// Confirm that the [AeadInto] implementation produces exactly the same output as the [Aead]
/// implementation.
#[test]
fn test_aeadinto() {
    let key = [0x60, 0xaf, 0x5d, 0xe1, 0x8b, 0x63, 0xf8, 0xe3, 0xe9, 0xbc, 0xff, 0x93, 0xa1, 0xab, 0x69, 0x1c, 0x8c, 0x2a, 0x87, 0xb5, 0x35, 0xac, 0x2a, 0xa1, 0x4e, 0xba, 0xd1, 0xf1, 0x7d, 0x02, 0xff, 0x92];
    let aad = [0xbc, 0xf7, 0x7c, 0x42, 0x96, 0xf4, 0x96, 0x63, 0x16, 0x70, 0x02, 0x4e, 0xb2, 0x70, 0xd5, 0x0d, 0x6d, 0xef, 0xa2, 0x82, 0x59, 0xf7, 0x74, 0x60, 0xfc, 0x15, 0x05, 0xa1, 0x4c, 0x97, 0x4d, 0x4c];
    let data = [0xf6, 0xef, 0x21, 0x88, 0x8c, 0xfa, 0x75, 0x82, 0xda, 0x73, 0x7c, 0xad, 0x6a, 0x08, 0x64, 0x9b, 0xa3, 0x11, 0xfa, 0x27, 0x90, 0xdb, 0x74, 0x6f, 0xf0, 0x70, 0x57, 0xca, 0x15, 0xf8, 0xc8, 0x0a];

    let mut trait_aeadinto_encrypted_output = [0u8; 32 + 16];
    Aes256Gcm::new((&key).try_into().unwrap())
        .encrypt_into(
            (&[0u8; 12]).try_into().unwrap(),
            &data,
            &aad,
            &mut trait_aeadinto_encrypted_output
        ).unwrap();

    let trait_aead_encrypted_output = Aes256Gcm::new((&key).try_into().unwrap())
        .encrypt(
            (&[0u8; 12]).try_into().unwrap(),
            Payload {
                msg: &data,
                aad: &aad
            }
        ).unwrap();

    assert_eq!(trait_aead_encrypted_output, trait_aeadinto_encrypted_output);

    let mut trait_aeadinto_decrypted_output = [0u8; 32];
    Aes256Gcm::new((&key).try_into().unwrap())
        .decrypt_into(
            (&[0u8; 12]).try_into().unwrap(),
            &trait_aeadinto_encrypted_output,
            &aad,
            &mut trait_aeadinto_decrypted_output
        ).unwrap();

    let trait_aead_decrypted_output = Aes256Gcm::new((&key).try_into().unwrap())
        .decrypt(
            (&[0u8; 12]).try_into().unwrap(),
            Payload {
                msg: &trait_aeadinto_encrypted_output,
                aad: &aad
            }
        ).unwrap();

    assert_eq!(trait_aead_decrypted_output, trait_aeadinto_decrypted_output);
}
