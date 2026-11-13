//! Test vectors from: https://datatracker.ietf.org/doc/html/rfc9058

#![cfg(feature = "alloc")]

aead::new_pass_test!(kuznyechik, "kuznyechik", mgm::Mgm<kuznyechik::Kuznyechik>);
aead::new_pass_test!(magma, "magma", mgm::Mgm<magma::Magma>);

#[test]
fn authentication_failure() {
    use aead::dev::{TestVector, fail_test};

    let vector = TestVector {
        key: &[0; 32],
        nonce: &[0; 16],
        aad: b"aad",
        plaintext: &[],
        ciphertext: &[0x42; 33],
    };
    fail_test::<mgm::Mgm<kuznyechik::Kuznyechik>>(&vector).unwrap();
    fail_test::<mgm::Mgm<magma::Magma>>(&TestVector {
        nonce: &[0; 8],
        ..vector
    })
    .unwrap();
}
