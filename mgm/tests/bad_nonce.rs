//! Tests for nonce validity checks
use aead::{generic_array::GenericArray, Aead, KeyInit};
use mgm::Mgm;

#[test]
fn kuznyechik_bad_nonce() {
    let key = GenericArray::from_slice(&[0u8; 32]);
    let mut nonce = GenericArray::clone_from_slice(&[0u8; 16]);
    let cipher = Mgm::<kuznyechik::Kuznyechik>::new(key);
    let mut enc_data = cipher.encrypt(&nonce, &[][..]).unwrap();
    let res = cipher.decrypt(&nonce, &enc_data[..]);
    assert!(res.is_ok());
    enc_data[0] ^= 0x80;
    let res = cipher.decrypt(&nonce, &enc_data[..]);
    assert!(res.is_err());

    nonce[0] ^= 0x80;
    let res = cipher.encrypt(&nonce, &[][..]);
    assert!(res.is_err());
    let res = cipher.decrypt(&nonce, &enc_data[..]);
    assert!(res.is_err());
}
