//! Test vectors from: https://datatracker.ietf.org/doc/html/rfc9058

#![cfg(feature = "alloc")]

aead::new_pass_test!(kuznyechik, "kuznyechik", mgm::Mgm<kuznyechik::Kuznyechik>);
aead::new_pass_test!(magma, "magma", mgm::Mgm<magma::Magma>);
