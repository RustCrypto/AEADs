#![feature(test)]
extern crate test;

use aead::{generic_array::GenericArray, AeadInPlace, NewAead};
use hex_literal::hex;
use kuznyechik::Kuznyechik;
use mgm::Mgm;
use test::Bencher;

const KEY: [u8; 32] = hex!("
    8899AABBCCDDEEFF0011223344556677
    FEDCBA98765432100123456789ABCDEF
");
const NONCE: [u8; 16] = hex!("
    1122334455667700FFEEDDCCBBAA9988
");

#[bench]
fn encrypt_aad_only_16kb(b: &mut Bencher) {
    let c = Mgm::<Kuznyechik>::new(GenericArray::from_slice(&KEY));
    let nonce = GenericArray::from_slice(&NONCE);
    let aad = vec![0; 16*1024];
    let mut buf = [];

    b.iter(|| {
        let res = c.encrypt_in_place_detached(nonce, &aad, &mut buf).unwrap();
        test::black_box(res);
    });

    b.bytes = 16*1024;
}

#[bench]
fn encrypt_msg_only_16kb(b: &mut Bencher) {
    let c = Mgm::<Kuznyechik>::new(GenericArray::from_slice(&KEY));
    let nonce = GenericArray::from_slice(&NONCE);
    let aad = [];
    let mut buf = vec![0; 16*1024];

    b.iter(|| {
        let res = c.encrypt_in_place_detached(nonce, &aad, &mut buf).unwrap();
        test::black_box(res);
    });

    b.bytes = 16*1024;
}

#[bench]
fn decrypt_aad_only_16kb(b: &mut Bencher) {
    let c = Mgm::<Kuznyechik>::new(GenericArray::from_slice(&KEY));
    let nonce = GenericArray::from_slice(&NONCE);
    let tag = GenericArray::default();
    let aad = vec![0; 16*1024];
    let mut buf = [];

    #[allow(unused_must_use)]
    b.iter(|| {
        let res = c.decrypt_in_place_detached(nonce, &aad, &mut buf, &tag);
        test::black_box(res);
    });

    b.bytes = 16*1024;
}

#[bench]
fn decrypt_msg_only_16kb(b: &mut Bencher) {
    let c = Mgm::<Kuznyechik>::new(GenericArray::from_slice(&KEY));
    let nonce = GenericArray::from_slice(&NONCE);
    let tag = GenericArray::default();
    let aad = [];
    let mut buf = vec![0; 16*1024];

    #[allow(unused_must_use)]
    b.iter(|| {
        let res = c.decrypt_in_place_detached(nonce, &aad, &mut buf, &tag);
        test::black_box(res);
    });

    b.bytes = 16*1024;
}
