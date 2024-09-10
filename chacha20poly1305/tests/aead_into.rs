use chacha20poly1305::aead::{ Aead, AeadInto, Payload };
use chacha20poly1305::{ ChaCha20Poly1305, KeyInit };


/// Confirm that the [AeadInto] implementation produces exactly the same output as the [Aead]
/// implementation.
#[test]
fn test_aeadinto() {
    let key = [0xfe, 0x14, 0xbc, 0x65, 0x16, 0xd6, 0x4a, 0x80, 0x8d, 0x58, 0xa3, 0x09, 0x8b, 0x0d, 0xa1, 0xc3, 0x2d, 0xf4, 0x62, 0xc0, 0x4d, 0x9e, 0x85, 0x55, 0x70, 0xc6, 0x83, 0xc2, 0x0f, 0xd7, 0xf4, 0x88];
    let aad = [0xfe, 0xa6, 0xa3, 0xc3, 0xae, 0x1a, 0xab, 0x0f, 0x80, 0xe7, 0xa9, 0xcb, 0x9a, 0x9e, 0x5f, 0x06, 0x16, 0x4d, 0x85, 0x46, 0x43, 0xbf, 0x74, 0xd4, 0x38, 0x19, 0xf6, 0xd3, 0x38, 0xa0, 0x5e, 0xaf];
    let data = [0xae, 0xfb, 0x8c, 0x8c, 0x38, 0xc9, 0x12, 0x04, 0x0f, 0x1d, 0xc0, 0x10, 0xf1, 0x94, 0xb0, 0x31, 0xcc, 0x00, 0xd8, 0xe4, 0xae, 0x5d, 0x04, 0x70, 0xb3, 0x6b, 0xfa, 0xb8, 0xe1, 0x23, 0x0c, 0x8c];

    let mut trait_aeadinto_encrypted_output = [0u8; 32 + 16];
    ChaCha20Poly1305::new((&key).try_into().unwrap())
        .encrypt_into(
            (&[0u8; 12]).try_into().unwrap(),
            &data,
            &aad,
            &mut trait_aeadinto_encrypted_output
        ).unwrap();

    let trait_aead_encrypted_output = ChaCha20Poly1305::new((&key).try_into().unwrap())
        .encrypt(
            (&[0u8; 12]).try_into().unwrap(),
            Payload {
                msg: &data,
                aad: &aad
            }
        ).unwrap();

    assert_eq!(trait_aead_encrypted_output, trait_aeadinto_encrypted_output);

    let mut trait_aeadinto_decrypted_output = [0u8; 32];
    ChaCha20Poly1305::new((&key).try_into().unwrap())
        .decrypt_into(
            (&[0u8; 12]).try_into().unwrap(),
            &trait_aeadinto_encrypted_output,
            &aad,
            &mut trait_aeadinto_decrypted_output
        ).unwrap();

    let trait_aead_decrypted_output = ChaCha20Poly1305::new((&key).try_into().unwrap())
        .decrypt(
            (&[0u8; 12]).try_into().unwrap(),
            Payload {
                msg: &trait_aeadinto_encrypted_output,
                aad: &aad
            }
        ).unwrap();

    assert_eq!(trait_aead_decrypted_output, trait_aeadinto_decrypted_output);
}
