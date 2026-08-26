use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use mrs_auth_pqc::sampler::sample_three_layers;
use mrs_auth_pqc::core::{MyU64, MyU256};
use rand::rngs::OsRng;

fn bench_sampler_u64(c: &mut Criterion) {
    let mut group = c.benchmark_group("sample_three_layers_u64");
    let scales: [(&str, u64); 4] = [
        ("small_1e6", 1_000_003),
        ("moderate_1e9", 1_000_000_003),
        ("large_1e12", 1_000_000_000_003),
        ("max_u64_range_1e18", 1_000_000_000_000_000_003),
    ];
    for (label, n) in scales {
        let root = MyU64::from(n);
        group.bench_with_input(BenchmarkId::from_parameter(label), &root, |b, root| {
            let mut rng = OsRng;
            b.iter(|| black_box(sample_three_layers(black_box(root), &mut rng)));
        });
    }
    group.finish();
}

fn bench_sampler_u256(c: &mut Criterion) {
    let mut group = c.benchmark_group("sample_three_layers_u256");
    // Cryptographic-scale N ~ 10^42 (well beyond u64)
    let scales: [(&str, &str); 3] = [
        ("crypto_10p36", "0000000000000000000000000000000000000000000000000000E8D4A51000"),
        ("crypto_10p42", "000000000000000000000000000000000000000000000000000000E8D4A51000"),
        ("crypto_10p48", "00000000000000000000000000000000000000000000000000000000E8D4A51000"),
    ];
    for (label, hex) in scales {
        let root = MyU256::from_be_hex(hex);
        group.bench_with_input(BenchmarkId::from_parameter(label), &root, |b, root| {
            let mut rng = OsRng;
            b.iter(|| black_box(sample_three_layers(black_box(root), &mut rng)));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_sampler_u64, bench_sampler_u256);
criterion_main!(benches);
