#![feature(test)]
extern crate test;

use aead::{generic_array::GenericArray, AeadInPlace, KeyInit};
use hex_literal::hex;
use kuznyechik::Kuznyechik;
use mgm::Mgm;
use test::Bencher;

#[rustfmt::skip]
const KEY: [u8; 32] = hex!("
    8899AABBCCDDEEFF0011223344556677
    FEDCBA98765432100123456789ABCDEF
");
#[rustfmt::skip]
const NONCE: [u8; 16] = hex!("
    1122334455667700FFEEDDCCBBAA9988
");

#[bench]
fn encrypt_aad_only_16kb(b: &mut Bencher) {
    let c = Mgm::<Kuznyechik>::new(GenericArray::from_slice(&KEY));
    let nonce = GenericArray::from_slice(&NONCE);
    let aad = vec![0; 16 * 1024];
    let mut buf = [];

    b.iter(|| {
        let (aad, buf) = test::black_box((&aad, &mut buf));
        let res = c.encrypt_in_place_detached(nonce, aad, buf).unwrap();
        test::black_box(res);
    });

    b.bytes = 16 * 1024;
}

#[bench]
fn encrypt_msg_only_16kb(b: &mut Bencher) {
    let c = Mgm::<Kuznyechik>::new(GenericArray::from_slice(&KEY));
    let nonce = GenericArray::from_slice(&NONCE);
    let aad = [];
    let mut buf = vec![0; 16 * 1024];

    b.iter(|| {
        let (aad, buf) = test::black_box((&aad, &mut buf));
        let res = c.encrypt_in_place_detached(nonce, aad, buf).unwrap();
        test::black_box(res);
    });

    b.bytes = 16 * 1024;
}

#[bench]
fn decrypt_aad_only_16kb(b: &mut Bencher) {
    let c = Mgm::<Kuznyechik>::new(GenericArray::from_slice(&KEY));
    let nonce = GenericArray::from_slice(&NONCE);
    let aad = vec![0; 16 * 1024];
    let mut buf = [];
    let tag = c.encrypt_in_place_detached(nonce, &aad, &mut []).unwrap();

    #[allow(unused_must_use)]
    b.iter(|| {
        let (aad, buf, tag) = test::black_box((&aad, &mut buf, &tag));
        let res = c.decrypt_in_place_detached(nonce, aad, buf, tag);
        test::black_box(res);
    });

    b.bytes = 16 * 1024;
}

#[bench]
fn decrypt_msg_only_16kb(b: &mut Bencher) {
    let c = Mgm::<Kuznyechik>::new(GenericArray::from_slice(&KEY));
    let nonce = GenericArray::from_slice(&NONCE);
    let aad = [];
    let mut buf = vec![0u8; 16 * 1024];
    let tag = c.encrypt_in_place_detached(nonce, &aad, &mut buf).unwrap();

    #[allow(unused_must_use)]
    b.iter(|| {
        let mut buf_cpy = buf.clone();
        let (aad, buf, tag) = test::black_box((&aad, &mut buf_cpy, &tag));
        let res = c.decrypt_in_place_detached(nonce, aad, buf, tag);
        test::black_box(res);
    });

    b.bytes = 16 * 1024;
}
