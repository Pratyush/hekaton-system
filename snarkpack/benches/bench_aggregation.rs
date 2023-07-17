use criterion::{criterion_group, criterion_main, Criterion};
mod aggregation;
use aggregation::groth16_aggregation;

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("groth16 aggregation", |b| b.iter(|| groth16_aggregation()));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
