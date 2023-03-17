// Copyright 2022 Sebastian Ramacher
// SPDX-License-Identifier: MIT

use ascon_aead::{
    aead::{generic_array::typenum::Unsigned, Aead, AeadInPlace, KeyInit},
    Ascon128, Ascon128a, Ascon80pq,
};
use criterion::{
    black_box, criterion_group, criterion_main, Bencher, BenchmarkId, Criterion, Throughput,
};
use rand::{rngs::StdRng, RngCore, SeedableRng};

const KB: usize = 1024;

fn bench_for_size<A: KeyInit + Aead>(b: &mut Bencher, rng: &mut dyn RngCore, size: usize) {
    let mut key = vec![0u8; A::KeySize::USIZE];
    rng.fill_bytes(key.as_mut_slice());
    let mut nonce = vec![0u8; A::NonceSize::USIZE];
    rng.fill_bytes(nonce.as_mut_slice());
    let mut plaintext = vec![0u8; size];
    rng.fill_bytes(plaintext.as_mut_slice());

    let cipher = A::new(key.as_slice().into());
    let nonce = nonce.as_slice().into();

    b.iter(|| black_box(cipher.encrypt(nonce, plaintext.as_slice())));
}

fn bench_for_size_inplace<A: KeyInit + AeadInPlace>(
    b: &mut Bencher,
    rng: &mut dyn RngCore,
    size: usize,
) {
    let mut key = vec![0u8; A::KeySize::USIZE];
    rng.fill_bytes(key.as_mut_slice());
    let mut nonce = vec![0u8; A::NonceSize::USIZE];
    rng.fill_bytes(nonce.as_mut_slice());
    let mut buffer = vec![0u8; size + 16];
    rng.fill_bytes(buffer.as_mut_slice());

    let cipher = A::new(key.as_slice().into());
    let nonce = nonce.as_slice().into();

    b.iter(|| black_box(cipher.encrypt_in_place(nonce, b"", &mut buffer)));
}

fn criterion_benchmark<A: KeyInit + Aead>(c: &mut Criterion, name: &str) {
    let mut rng = StdRng::from_entropy();
    let mut group = c.benchmark_group(name);
    for size in [KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB, 32 * KB, 64 * KB].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            bench_for_size::<A>(b, &mut rng, size)
        });
    }
    group.finish();
}

fn criterion_benchmark_inplace<A: KeyInit + AeadInPlace>(c: &mut Criterion, name: &str) {
    let mut rng = StdRng::from_entropy();
    let mut group = c.benchmark_group(name);
    for size in [KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB, 32 * KB, 64 * KB].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            bench_for_size_inplace::<A>(b, &mut rng, size)
        });
    }
    group.finish();
}

fn criterion_bench_ascon128(c: &mut Criterion) {
    criterion_benchmark::<Ascon128>(c, "Ascon-128");
}

fn criterion_bench_ascon128a(c: &mut Criterion) {
    criterion_benchmark::<Ascon128a>(c, "Ascon-128a");
}

fn criterion_bench_ascon80pq(c: &mut Criterion) {
    criterion_benchmark::<Ascon80pq>(c, "Ascon-80pq");
}

fn criterion_bench_ascon128_inplace(c: &mut Criterion) {
    criterion_benchmark_inplace::<Ascon128>(c, "Ascon-128 (inplace)");
}

fn criterion_bench_ascon128a_inplace(c: &mut Criterion) {
    criterion_benchmark_inplace::<Ascon128a>(c, "Ascon-128a (inplace)");
}

fn criterion_bench_ascon80pq_inplace(c: &mut Criterion) {
    criterion_benchmark_inplace::<Ascon80pq>(c, "Ascon-80pq (inplace)");
}

criterion_group!(
    bench_ascon128,
    criterion_bench_ascon128,
    criterion_bench_ascon128_inplace,
);
criterion_group!(
    bench_ascon128a,
    criterion_bench_ascon128a,
    criterion_bench_ascon128a_inplace
);
criterion_group!(
    bench_ascon80pq,
    criterion_bench_ascon80pq,
    criterion_bench_ascon80pq_inplace
);
criterion_main!(bench_ascon128, bench_ascon128a, bench_ascon80pq);
