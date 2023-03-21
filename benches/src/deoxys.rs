use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use deoxys::aead::{Aead, KeyInit};
use deoxys::{DeoxysI128, DeoxysI256, DeoxysII128, DeoxysII256};

const KB: usize = 1024;

#[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
type Benchmarker = Criterion;
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
type Benchmarker = Criterion<criterion_cycles_per_byte::CyclesPerByte>;

fn bench(c: &mut Benchmarker) {
    let mut group = c.benchmark_group("deoxys");

    for size in &[KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB] {
        let buf = vec![0u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_function(BenchmarkId::new("encrypt-I-128", size), |b| {
            let cipher = DeoxysI128::new(&Default::default());
            b.iter(|| cipher.encrypt(&Default::default(), &*buf))
        });
        group.bench_function(BenchmarkId::new("decrypt-I-128", size), |b| {
            let cipher = DeoxysI128::new(&Default::default());
            b.iter(|| cipher.decrypt(&Default::default(), &*buf))
        });

        group.bench_function(BenchmarkId::new("encrypt-I-256", size), |b| {
            let cipher = DeoxysI256::new(&Default::default());
            b.iter(|| cipher.encrypt(&Default::default(), &*buf))
        });
        group.bench_function(BenchmarkId::new("decrypt-I-256", size), |b| {
            let cipher = DeoxysI256::new(&Default::default());
            b.iter(|| cipher.decrypt(&Default::default(), &*buf))
        });

        group.bench_function(BenchmarkId::new("encrypt-II-128", size), |b| {
            let cipher = DeoxysII128::new(&Default::default());
            b.iter(|| cipher.encrypt(&Default::default(), &*buf))
        });
        group.bench_function(BenchmarkId::new("decrypt-II-128", size), |b| {
            let cipher = DeoxysII128::new(&Default::default());
            b.iter(|| cipher.decrypt(&Default::default(), &*buf))
        });

        group.bench_function(BenchmarkId::new("encrypt-II-256", size), |b| {
            let cipher = DeoxysII256::new(&Default::default());
            b.iter(|| cipher.encrypt(&Default::default(), &*buf))
        });
        group.bench_function(BenchmarkId::new("decrypt-II-256", size), |b| {
            let cipher = DeoxysII256::new(&Default::default());
            b.iter(|| cipher.decrypt(&Default::default(), &*buf))
        });
    }

    group.finish();
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = bench
);

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
criterion_group!(
    name = benches;
    config = Criterion::default().with_measurement(criterion_cycles_per_byte::CyclesPerByte);
    targets = bench
);

criterion_main!(benches);
