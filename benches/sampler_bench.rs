// benches/sampler_bench.rs
//
// Run: cargo bench
// Output: target/criterion/*/report/index.html (local), plus a
// summary table in stdout / the CI log.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use mrs_auth_pqc::sampler::sample_three_layers;

fn bench_sampler_across_scales(c: &mut Criterion) {
    let mut group = c.benchmark_group("sample_three_layers");

    // Four scales within the u64 range (max ~1.8 x 10^19).
    // Cryptographic scale (N ~ 10^42, as used in the paper) requires
    // converting the sampler itself to a big-integer type -- see the
    // note at the bottom.
    let scales: [(&str, u64); 4] = [
        ("small_1e6", 1_000_003),
        ("moderate_1e9", 1_000_000_003),
        ("large_1e12", 1_000_000_000_003),
        ("max_u64_range_1e18", 1_000_000_000_000_000_003),
    ];

    for (label, n) in scales {
        group.bench_with_input(BenchmarkId::from_parameter(label), &n, |b, &n| {
            b.iter(|| {
                let result = sample_three_layers(black_box(n));
                black_box(result)
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_sampler_across_scales);
criterion_main!(benches);

// Note: N on the order of 10^42 (the scale the paper's entropy claims
// refer to) exceeds the range of u64. Benchmarking at that same order
// of magnitude would require first converting the sampler to a
// big-integer type (e.g. the `num-bigint` crate) -- a separate change,
// outside the scope of this benchmark harness. Call this out explicitly
// as a caveat if you cite these results in the paper.
