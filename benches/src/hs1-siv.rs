use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use hs1_siv::aead::{Aead, KeyInit};
use hs1_siv::{Hs1SivLo, Hs1SivMe, Hs1SivHi};

const KB: usize = 1024;

#[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
type Benchmarker = Criterion;
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
type Benchmarker = Criterion<criterion_cycles_per_byte::CyclesPerByte>;

fn bench(c: &mut Benchmarker) {
    let mut group = c.benchmark_group("hs1-siv");

    for size in &[KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB] {
        let buf = vec![0u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_function(BenchmarkId::new("encrypt-lo", size), |b| {
            let cipher = Hs1SivLo::new(&Default::default());
            b.iter(|| cipher.encrypt(&Default::default(), &*buf))
        });
        group.bench_function(BenchmarkId::new("decrypt-lo", size), |b| {
            let cipher = Hs1SivLo::new(&Default::default());
            b.iter(|| cipher.decrypt(&Default::default(), &*buf))
        });

        group.bench_function(BenchmarkId::new("encrypt-me", size), |b| {
            let cipher = Hs1SivMe::new(&Default::default());
            b.iter(|| cipher.encrypt(&Default::default(), &*buf))
        });
        group.bench_function(BenchmarkId::new("decrypt-me", size), |b| {
            let cipher = Hs1SivMe::new(&Default::default());
            b.iter(|| cipher.decrypt(&Default::default(), &*buf))
        });

        group.bench_function(BenchmarkId::new("encrypt-hi", size), |b| {
            let cipher = Hs1SivHi::new(&Default::default());
            b.iter(|| cipher.encrypt(&Default::default(), &*buf))
        });
        group.bench_function(BenchmarkId::new("decrypt-hi", size), |b| {
            let cipher = Hs1SivHi::new(&Default::default());
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
