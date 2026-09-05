use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use mrs_auth_pqc::sampler::sample_three_layers_safe;
use rand::rngs::OsRng;

fn bench_sampler(c: &mut Criterion) {
    let mut group = c.benchmark_group("sample_three_layers_safe");
    let scales: [(&str, u64); 4] = [
        ("small_1e6", 1_000_003),
        ("moderate_1e9", 1_000_000_003),
        ("large_1e12", 1_000_000_000_003),
        ("max_u64_range_1e18", 1_000_000_000_000_000_003),
    ];
    for (label, n) in scales {
        group.bench_with_input(BenchmarkId::from_parameter(label), &n, |b, root| {
            let mut rng = OsRng;
            b.iter(|| black_box(sample_three_layers_safe(black_box(*root), &mut rng)));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_sampler);
criterion_main!(benches);
