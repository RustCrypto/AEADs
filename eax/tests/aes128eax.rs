use aes::Aes128;
use eax::Eax;

aead::new_test!(aes128eax, "aes128eax", Eax<Aes128>);
