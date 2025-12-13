#![cfg(feature = "vec")]

use grain_128aeadv2::Grain128;
use grain_128aeadv2::KeyInit;

#[test]
fn test_encrypt_decrypt_aead() {
    // Init and load keys into the cipher
    let key = [0u8; 16];
    let nonce = [0u8; 12];
    let pt = [0u8; 32];

    let cipher = Grain128::new(&key.into());

    let (encrypted, tag) = cipher.encrypt_aead(&nonce.into(), b"this is authenticated data", &pt);
    cipher
        .decrypt_aead(
            &nonce.into(),
            b"this is authenticated data",
            &encrypted,
            &tag,
        )
        .expect("Unable to decrypt");
}
