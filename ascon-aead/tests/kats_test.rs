// Copyright 2022 Sebastian Ramacher
// SPDX-License-Identifier: MIT

use ascon_aead::{
    aead::{Aead, AeadInPlace, KeyInit, Payload},
    Ascon128, Ascon128a, Ascon80pq, Key, Nonce,
};
use spectral::prelude::{asserting, OrderedAssertions, ResultAssertions};
use std::collections::HashMap;
use std::include_str;

#[derive(Debug)]
struct TestVector {
    count: u32,
    key: Vec<u8>,
    nonce: Vec<u8>,
    plaintext: Vec<u8>,
    associated_data: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl TestVector {
    fn new(
        count: &str,
        key: &str,
        nonce: &str,
        plaintext: &str,
        associated_data: &str,
        ciphertext: &str,
    ) -> Self {
        Self {
            count: count.parse().unwrap(),
            key: hex::decode(key).unwrap(),
            nonce: hex::decode(nonce).unwrap(),
            plaintext: hex::decode(plaintext).unwrap(),
            associated_data: hex::decode(associated_data).unwrap(),
            ciphertext: hex::decode(ciphertext).unwrap(),
        }
    }
}

fn run_tv<A: KeyInit + AeadInPlace>(tv: TestVector) {
    let core = A::new(Key::<A>::from_slice(&tv.key));
    asserting(format!("Test Vector {} encryption", tv.count).as_str())
        .that(&core.encrypt(
            Nonce::<A>::from_slice(&tv.nonce),
            Payload {
                msg: &tv.plaintext,
                aad: &tv.associated_data,
            },
        ))
        .is_ok()
        .is_equal_to(&tv.ciphertext);

    asserting(format!("Test Vector {} decryption", tv.count).as_str())
        .that(&core.decrypt(
            Nonce::<A>::from_slice(&tv.nonce),
            Payload {
                msg: &tv.ciphertext,
                aad: &tv.associated_data,
            },
        ))
        .is_ok()
        .is_equal_to(&tv.plaintext);
}

fn parse_tvs(tvs: &str) -> Vec<TestVector> {
    let mut fields: HashMap<String, String> = HashMap::new();
    let mut ret = Vec::new();

    for line in tvs.lines() {
        if line.is_empty() && !fields.is_empty() {
            ret.push(TestVector::new(
                &fields["Count"],
                &fields["Key"],
                &fields["Nonce"],
                &fields["PT"],
                &fields["AD"],
                &fields["CT"],
            ));
            fields.clear();
            continue;
        }

        let mut values = line.split(" = ");
        fields.insert(
            values.next().unwrap().to_string(),
            values.next().unwrap().to_string(),
        );
    }

    asserting!("Test Vectors available")
        .that(&ret.len())
        .is_greater_than(0);
    ret
}

#[test]
fn test_vectors_ascon128() {
    let tvs = parse_tvs(include_str!("data/ascon128.txt"));
    for tv in tvs {
        run_tv::<Ascon128>(tv);
    }
}

#[test]
fn test_vectors_ascon128a() {
    let tvs = parse_tvs(include_str!("data/ascon128a.txt"));
    for tv in tvs {
        run_tv::<Ascon128a>(tv);
    }
}

#[test]
fn test_vectors_ascon80pq() {
    let tvs = parse_tvs(include_str!("data/ascon80pq.txt"));
    for tv in tvs {
        run_tv::<Ascon80pq>(tv);
    }
}
