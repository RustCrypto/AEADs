use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;

const KB: usize = 1024;

#[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
type Benchmarker = Criterion;
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
type Benchmarker = Criterion<criterion_cycles_per_byte::CyclesPerByte>;

fn bench(c: &mut Benchmarker) {
    let mut group = c.benchmark_group("chacha20poly1305");

    for size in &[KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB] {
        let buf = vec![0u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_function(BenchmarkId::new("encrypt", size), |b| {
            let cipher = ChaCha20Poly1305::new(&Default::default());
            b.iter(|| cipher.encrypt(&Default::default(), &*buf))
        });
        group.bench_function(BenchmarkId::new("decrypt", size), |b| {
            let cipher = ChaCha20Poly1305::new(&Default::default());
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
    config = Criterion::default().with_measurement(CyclesPerByte);
    targets = bench
);

criterion_main!(benches);
