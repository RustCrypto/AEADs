//! Regression tests for clearing unauthenticated plaintext.

use deoxys::aead::{AeadInOut, Key, KeyInit, Nonce, inout::InOutBuf};
use deoxys::{DeoxysI128, DeoxysI256, DeoxysII128, DeoxysII256};

fn assert_failed_decrypt_clears<C>()
where
    C: AeadInOut + KeyInit,
{
    let key = Key::<C>::default();
    let nonce = Nonce::<C>::default();
    let cipher = C::new(&key);
    let mut ciphertext = b"plaintext that must not be exposed".to_vec();
    let mut tag = cipher
        .encrypt_inout_detached(&nonce, &[], (&mut ciphertext[..]).into())
        .expect("encryption failed");
    tag[0] ^= 1;

    let mut output = vec![0xa5; ciphertext.len()];
    let buffer = InOutBuf::new(&ciphertext, &mut output).expect("input and output lengths differ");

    cipher
        .decrypt_inout_detached(&nonce, &[], buffer, &tag)
        .expect_err("tampered tag was accepted");

    assert_eq!(output, vec![0; ciphertext.len()]);
}

#[test]
fn deoxys_i_128_failed_decrypt_clears_output() {
    assert_failed_decrypt_clears::<DeoxysI128>();
}

#[test]
fn deoxys_i_256_failed_decrypt_clears_output() {
    assert_failed_decrypt_clears::<DeoxysI256>();
}

#[test]
fn deoxys_ii_128_failed_decrypt_clears_output() {
    assert_failed_decrypt_clears::<DeoxysII128>();
}

#[test]
fn deoxys_ii_256_failed_decrypt_clears_output() {
    assert_failed_decrypt_clears::<DeoxysII256>();
}
