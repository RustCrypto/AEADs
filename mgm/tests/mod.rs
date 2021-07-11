//! Test vectors from: https://datatracker.ietf.org/doc/html/rfc9058

aead::new_test!(kuznyechik, "kuznyechik", mgm::Mgm<kuznyechik::Kuznyechik>);
