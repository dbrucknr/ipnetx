//! Benchmarks for `IpSet` operations.
//!
//! Each benchmark group runs at three set sizes — 100, 1 000, and 10 000
//! stored ranges — so the results show how each operation scales in practice.
//!
//! Run with:
//!   cargo bench
//!
//! For an HTML report:
//!   cargo bench --bench ipset
//! (output lands in target/criterion/report/index.html)

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::hint::black_box;
use ipnetx::ipset::{IpSet, IpSetBuilder};
use ipnetx::range::IpRange;
use std::net::Ipv4Addr;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Builds an `IpSet` of `count` non-overlapping /24 blocks, offset by `start`.
///
/// Ranges are laid out across the `10.x.y.0/24` space:
///   start=0,   count=3 → [10.0.0.0/24, 10.0.1.0/24, 10.0.2.0/24]
///   start=100, count=3 → [10.0.100.0/24, 10.0.101.0/24, 10.0.102.0/24]
///
/// Using a non-zero `start` lets two calls produce sets that partially overlap,
/// which is the interesting case for intersection and difference.
fn make_set(start: u32, count: u32) -> IpSet<Ipv4Addr> {
    let mut builder = IpSetBuilder::<Ipv4Addr>::new();
    for i in start..start + count {
        let b2 = ((i / 256) % 256) as u8;
        let b3 = (i % 256) as u8;
        builder.add_range(IpRange::new(
            Ipv4Addr::new(10, b2, b3, 0),
            Ipv4Addr::new(10, b2, b3, 255),
        ));
    }
    builder.build()
}

/// Returns the raw (unsorted, not yet built) ranges for `count` /24 blocks,
/// enumerated in reverse order so `build()` has real sorting work to do.
fn make_raw_ranges(count: u32) -> Vec<IpRange<Ipv4Addr>> {
    (0..count)
        .rev()
        .map(|i| {
            let b2 = ((i / 256) % 256) as u8;
            let b3 = (i % 256) as u8;
            IpRange::new(
                Ipv4Addr::new(10, b2, b3, 0),
                Ipv4Addr::new(10, b2, b3, 255),
            )
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

/// `contains_ip` — binary search; should be O(log n).
fn bench_contains_ip(c: &mut Criterion) {
    let mut group = c.benchmark_group("contains_ip");
    for &size in &[100u32, 1_000, 10_000] {
        let set = make_set(0, size);
        // Pick an IP near the middle of the set — exercises a representative
        // number of binary search comparisons.
        let mid = size / 2;
        let ip = Ipv4Addr::new(10, ((mid / 256) % 256) as u8, (mid % 256) as u8, 128);
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| set.contains_ip(black_box(ip)));
        });
    }
    group.finish();
}

/// `IpSetBuilder::build` — sort + merge; dominated by the sort, O(n log n).
fn bench_build(c: &mut Criterion) {
    let mut group = c.benchmark_group("build");
    for &size in &[100u32, 1_000, 10_000] {
        let raw = make_raw_ranges(size);
        group.bench_with_input(BenchmarkId::from_parameter(size), &raw, |b, raw| {
            b.iter(|| {
                let mut builder = IpSetBuilder::<Ipv4Addr>::new();
                for &range in raw {
                    builder.add_range(range);
                }
                black_box(builder.build())
            });
        });
    }
    group.finish();
}

/// `union` — concatenate + normalize; O((m + n) log(m + n)).
fn bench_union(c: &mut Criterion) {
    let mut group = c.benchmark_group("union");
    for &size in &[100u32, 1_000, 10_000] {
        // Overlap in the upper half of a / lower half of b
        let a = make_set(0, size);
        let b = make_set(size / 2, size);
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |bench, _| {
            bench.iter(|| black_box(a.union(black_box(&b))));
        });
    }
    group.finish();
}

/// `intersection` — two-pointer walk; O(m + n).
fn bench_intersection(c: &mut Criterion) {
    let mut group = c.benchmark_group("intersection");
    for &size in &[100u32, 1_000, 10_000] {
        let a = make_set(0, size);
        let b = make_set(size / 2, size);
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |bench, _| {
            bench.iter(|| black_box(a.intersection(black_box(&b))));
        });
    }
    group.finish();
}

/// `difference` — subtract each range in b from a; O(m × n) worst-case but
/// O(m + n) for sorted, non-overlapping sets like these.
fn bench_difference(c: &mut Criterion) {
    let mut group = c.benchmark_group("difference");
    for &size in &[100u32, 1_000, 10_000] {
        let a = make_set(0, size);
        let b = make_set(size / 2, size);
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |bench, _| {
            bench.iter(|| black_box(a.difference(black_box(&b))));
        });
    }
    group.finish();
}

/// `complement` — one pass over stored ranges to emit gaps; O(n).
fn bench_complement(c: &mut Criterion) {
    let mut group = c.benchmark_group("complement");
    for &size in &[100u32, 1_000, 10_000] {
        let a = make_set(0, size);
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |bench, _| {
            bench.iter(|| black_box(a.complement()));
        });
    }
    group.finish();
}

/// `count` — single linear pass to sum range widths; O(n).
fn bench_count(c: &mut Criterion) {
    let mut group = c.benchmark_group("count");
    for &size in &[100u32, 1_000, 10_000] {
        let a = make_set(0, size);
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |bench, _| {
            bench.iter(|| black_box(a.count()));
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------

criterion_group!(
    benches,
    bench_contains_ip,
    bench_build,
    bench_union,
    bench_intersection,
    bench_difference,
    bench_complement,
    bench_count,
);
criterion_main!(benches);
