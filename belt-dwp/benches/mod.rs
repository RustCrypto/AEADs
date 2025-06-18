#![feature(test)]
extern crate test;

use aead::{
    AeadInOut, KeyInit,
    array::Array,
    consts::{U16, U32},
};
use belt_dwp::BeltDwp;
use hex_literal::hex;
use test::Bencher;

const KEY: Array<u8, U32> = Array(hex!(
    "8899AABBCCDDEEFF0011223344556677"
    "FEDCBA98765432100123456789ABCDEF"
));
const NONCE: Array<u8, U16> = Array(hex!("1122334455667700FFEEDDCCBBAA9988"));

#[bench]
fn encrypt_aad_only_16kb(b: &mut Bencher) {
    let c = BeltDwp::new(&KEY);
    let aad = vec![0; 16 * 1024];
    let mut buf = [];

    b.iter(|| {
        let (aad, buf, nonce) = test::black_box((&aad, &mut buf[..], &NONCE));
        let res = c.encrypt_inout_detached(nonce, aad, buf.into()).unwrap();
        test::black_box(res);
    });

    b.bytes = 16 * 1024;
}

#[bench]
fn encrypt_msg_only_16kb(b: &mut Bencher) {
    let c = BeltDwp::new(&KEY);
    let aad = [];
    let mut buf = vec![0; 16 * 1024];

    b.iter(|| {
        let (aad, buf, nonce) = test::black_box((&aad, &mut buf[..], &NONCE));
        let res = c.encrypt_inout_detached(nonce, aad, buf.into()).unwrap();
        test::black_box(res);
    });

    b.bytes = 16 * 1024;
}

#[bench]
fn decrypt_aad_only_16kb(b: &mut Bencher) {
    let c = BeltDwp::new(&KEY);
    let aad = vec![0; 16 * 1024];
    let mut buf = [];
    let tag = c
        .encrypt_inout_detached(&NONCE, &aad, (&mut buf[..]).into())
        .unwrap();

    b.iter(|| {
        let (aad, buf, nonce, tag) = test::black_box((&aad, &mut buf[..], &NONCE, &tag));
        let res = c.decrypt_inout_detached(nonce, aad, buf.into(), tag);
        let _ = test::black_box(res);
    });

    b.bytes = 16 * 1024;
}

#[bench]
fn decrypt_msg_only_16kb(b: &mut Bencher) {
    let c = BeltDwp::new(&KEY);
    let aad = [];
    let mut ct_buf = vec![0u8; 16 * 1024];
    let tag = c
        .encrypt_inout_detached(&NONCE, &aad, (&mut ct_buf[..]).into())
        .unwrap();

    let mut buf = ct_buf.clone();
    b.iter(|| {
        let (aad, buf, nonce, tag) = test::black_box((&aad, &mut buf[..], &NONCE, &tag));
        let res = c.decrypt_inout_detached(nonce, aad, buf.into(), tag);
        let _ = test::black_box(res);
        buf.copy_from_slice(&ct_buf);
    });

    b.bytes = 16 * 1024;
}
