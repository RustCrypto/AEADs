use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use criterion_cycles_per_byte::CyclesPerByte;

use aead::{Aead, NewAead};
use aes_gcm::{Aes128Gcm, Aes256Gcm};

const KB: usize = 1024;

fn bench(c: &mut Criterion<CyclesPerByte>) {
    let mut group = c.benchmark_group("aes-gcm");

    for size in &[KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB] {
        let buf = vec![0u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_function(BenchmarkId::new("encrypt-128", size), |b| {
            let cipher = Aes128Gcm::new(Default::default());
            b.iter(|| cipher.encrypt(&Default::default(), &*buf))
        });
        group.bench_function(BenchmarkId::new("decrypt-128", size), |b| {
            let cipher = Aes128Gcm::new(Default::default());
            b.iter(|| cipher.decrypt(&Default::default(), &*buf))
        });

        group.bench_function(BenchmarkId::new("encrypt-256", size), |b| {
            let cipher = Aes256Gcm::new(Default::default());
            b.iter(|| cipher.encrypt(&Default::default(), &*buf))
        });
        group.bench_function(BenchmarkId::new("decrypt-256", size), |b| {
            let cipher = Aes256Gcm::new(Default::default());
            b.iter(|| cipher.decrypt(&Default::default(), &*buf))
        });
    }

    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default().with_measurement(CyclesPerByte);
    targets = bench
);
criterion_main!(benches);
