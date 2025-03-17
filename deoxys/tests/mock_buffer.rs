//! this module is here to test the inout behavior which is not currently exposed.
//! it will be once we port over to the API made in RustCrypto/traits#1793.
//!
//! This is to drop once https://github.com/RustCrypto/traits/pull/1797 is made available.
//!
//! It duplicates test vectors from `tests/deoxys_i_128.rs` and provides a mock buffer backing
//! for InOut.

use aead::{AeadInOut, array::Array, dev::MockBuffer};
use hex_literal::hex;

use deoxys::*;

#[test]
fn test_deoxys_i_128_5() {
    let plaintext = hex!("5a4c652cb880808707230679224b11799b5883431292973215e9bd03cf3bc32fe4");
    let mut buffer = MockBuffer::from(&plaintext[..]);

    let aad = Vec::new();

    let key = hex!("101112131415161718191a1b1c1d1e1f");
    let key = Array(key);

    let nonce = hex!("202122232425262728292a2b2c2d2e2f");
    let nonce = Array::try_from(&nonce[..8]).unwrap();

    let ciphertext_expected =
        hex!("cded5a43d3c76e942277c2a1517530ad66037897c985305ede345903ed7585a626");

    let tag_expected: [u8; 16] = hex!("cbf5faa6b8398c47f4278d2019161776");

    let cipher = DeoxysI128::new(&key);
    let tag: Tag = cipher
        .encrypt_inout_detached(&nonce, &aad, buffer.to_in_out_buf())
        .expect("encryption failed");

    let ciphertext = buffer.as_ref();
    assert_eq!(ciphertext, ciphertext_expected);
    assert_eq!(tag, tag_expected);

    let mut buffer = MockBuffer::from(buffer.as_ref());
    cipher
        .decrypt_inout_detached(&nonce, &aad, buffer.to_in_out_buf(), &tag)
        .expect("decryption failed");

    assert_eq!(&plaintext[..], buffer.as_ref());
}

#[test]
fn test_deoxys_ii_128_5() {
    let plaintext = hex!("06ac1756eccece62bd743fa80c299f7baa3872b556130f52265919494bdc136db3");
    let mut buffer = MockBuffer::from(&plaintext[..]);

    let aad = Vec::new();

    let key = hex!("101112131415161718191a1b1c1d1e1f");
    let key = Array(key);

    let nonce = hex!("202122232425262728292a2b2c2d2e2f");
    let nonce = Array::try_from(&nonce[..15]).unwrap();

    let ciphertext_expected =
        hex!("82bf241958b324ed053555d23315d3cc20935527fc970ff34a9f521a95e302136d");

    let tag_expected: [u8; 16] = hex!("0eadc8612d5208c491e93005195e9769");

    let cipher = DeoxysII128::new(&key);
    let tag: Tag = cipher
        .encrypt_inout_detached(&nonce, &aad, buffer.to_in_out_buf())
        .expect("encryption failed");

    let ciphertext = buffer.as_ref();
    assert_eq!(ciphertext, ciphertext_expected);
    assert_eq!(tag, tag_expected);

    let mut buffer = MockBuffer::from(buffer.as_ref());
    cipher
        .decrypt_inout_detached(&nonce, &aad, buffer.to_in_out_buf(), &tag)
        .expect("decryption failed");

    assert_eq!(&plaintext[..], buffer.as_ref());
}
