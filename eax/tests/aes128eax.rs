//! Test vectors from Appendix G:
//! https://web.cs.ucdavis.edu/~rogaway/papers/eax.pdf
#![cfg(feature = "alloc")]

use aes::Aes128;
use eax::Eax;

aead::new_pass_test!(aes128eax_pass, "aes128eax_pass", Eax<Aes128>);
aead::new_fail_test!(aes128eax_fail, "aes128eax_fail", Eax<Aes128>);
