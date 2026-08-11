// benches/sampler_bench.rs
//
// Draaien: cargo bench
// Output: target/criterion/*/report/index.html (lokaal), en een
// samenvattende tabel in stdout / CI-log.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use mrs_auth_pqc::sampler::sample_three_layers;

fn bench_sampler_across_scales(c: &mut Criterion) {
    let mut group = c.benchmark_group("sample_three_layers");

    // Vier schalen binnen het u64-bereik (max ~1.8 x 10^19).
    // Cryptografische schaal (N ~ 10^42, zoals in de paper) vereist een
    // big-integer-omzetting van de sampler zelf -- zie opmerking onderaan.
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

// Opmerking: N in de buurt van 10^42 (waar de paper entropie-uitspraken
// over doet) overschrijdt het bereik van u64. Voor een benchmark die
// dezelfde ordes van grootte dekt, moet de sampler eerst omgezet worden
// naar een big-integer type (bijv. de `num-bigint` crate) -- een aparte
// aanpassing, los van deze benchmark-harness. Vermeld dit expliciet als
// kanttekening als je deze resultaten in de paper opneemt.
</parameter>
