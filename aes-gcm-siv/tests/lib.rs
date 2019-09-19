//! AES-GCM-SIV tests

use aes_gcm_siv::aead::{generic_array::GenericArray, Aead, NewAead, Payload};
use aes_gcm_siv::Aes128GcmSiv;

const KEY: &[u8] = b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
const NONCE: &[u8] = b"\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
const AAD: &[u8] = b"";
const PLAINTEXT: &[u8] = b"\x01\x00\x00\x00\x00\x00\x00\x00";
const CIPHERTEXT: &[u8] = b"\xb5\xd8\x39\x33\x0a\xc7\xb7\x86\x57\x87\x82\xff\xf6\x01\x3b\x81\x5b\x28\x7c\x22\x49\x3a\x36\x4c";

#[test]
fn encrypt() {
    let key = GenericArray::from_slice(KEY);
    let nonce = GenericArray::from_slice(NONCE);
    let payload = Payload {
        msg: PLAINTEXT,
        aad: AAD,
    };

    let cipher = Aes128GcmSiv::new(*key);
    let ciphertext = cipher.encrypt(nonce, payload).unwrap();

    assert_eq!(CIPHERTEXT, ciphertext.as_slice());
}

#[test]
fn decrypt() {
    let key = GenericArray::from_slice(KEY);
    let nonce = GenericArray::from_slice(NONCE);

    let payload = Payload {
        msg: CIPHERTEXT,
        aad: AAD,
    };

    let cipher = Aes128GcmSiv::new(*key);
    let plaintext = cipher.decrypt(nonce, payload).unwrap();

    assert_eq!(PLAINTEXT, plaintext.as_slice());
}
