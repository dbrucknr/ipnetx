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

/// Builds an `IpSet` of `count` unaligned ranges.
///
/// Each range is `10.x.y.1..10.x.y.254` — misaligned start and non-power-of-two
/// size — so every range decomposes into 14 CIDR prefixes via `prefixes()`.
/// Used to contrast against the aligned case in `bench_ipset_prefixes`.
fn make_unaligned_set(count: u32) -> IpSet<Ipv4Addr> {
    let mut builder = IpSetBuilder::<Ipv4Addr>::new();
    for i in 0..count {
        let b2 = ((i / 256) % 256) as u8;
        let b3 = (i % 256) as u8;
        builder.add_range(IpRange::new(
            Ipv4Addr::new(10, b2, b3, 1),
            Ipv4Addr::new(10, b2, b3, 254),
        ));
    }
    builder.build()
}

/// Builds an `IpSet` of `count` non-merging ranges with a gap between each.
///
/// Each range covers `10.x.y.0..10.x.y.100` with a step of 3 between block
/// indices, leaving a gap that prevents normalization from merging them. A
/// non-zero `start_offset` shifts the block indices so two calls with offsets
/// 0 and 1 produce perfectly interleaved sets — ideal for stressing `union`.
fn make_sparse_set(start_offset: u32, count: u32) -> IpSet<Ipv4Addr> {
    let mut builder = IpSetBuilder::<Ipv4Addr>::new();
    for i in 0..count {
        let idx = start_offset + i * 3;
        let b2 = ((idx / 256) % 256) as u8;
        let b3 = (idx % 256) as u8;
        builder.add_range(IpRange::new(
            Ipv4Addr::new(10, b2, b3, 0),
            Ipv4Addr::new(10, b2, b3, 100),
        ));
    }
    builder.build()
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

/// `union` — two-pointer merge + collapse; O(m + n).
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

/// `union` with sparse (non-merging) sets — the case that most benefits from the
/// O(m+n) merge over the old O((m+n) log(m+n)) sort.
///
/// Set `a` holds ranges at block indices 0, 3, 6, ...; set `b` at 1, 4, 7, ...
/// The two sets interleave perfectly and produce 2×size ranges after union.
fn bench_union_sparse(c: &mut Criterion) {
    let mut group = c.benchmark_group("union_sparse");
    for &size in &[100u32, 1_000, 10_000] {
        let a = make_sparse_set(0, size);
        let b = make_sparse_set(1, size);
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

/// `difference` — two-pointer walk; O(m + n).
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

/// `IpSetBuilder::build` with removals — O((n + k) log(n + k)).
///
/// Each run adds `size` ranges in reverse order (forcing real sort work) and
/// removes `size / 2` ranges covering the upper half of the add space.
/// Demonstrates the lazy-removal path: all `remove_range` calls are O(1) and
/// the subtraction is resolved in one pass during `build()`.
fn bench_build_with_removals(c: &mut Criterion) {
    let mut group = c.benchmark_group("build_with_removals");
    for &size in &[100u32, 1_000, 10_000] {
        let raw_adds: Vec<IpRange<Ipv4Addr>> = (0..size)
            .rev()
            .map(|i| {
                let b2 = ((i / 256) % 256) as u8;
                let b3 = (i % 256) as u8;
                IpRange::new(Ipv4Addr::new(10, b2, b3, 0), Ipv4Addr::new(10, b2, b3, 255))
            })
            .collect();
        let raw_removes: Vec<IpRange<Ipv4Addr>> = (size / 2..size)
            .map(|i| {
                let b2 = ((i / 256) % 256) as u8;
                let b3 = (i % 256) as u8;
                IpRange::new(Ipv4Addr::new(10, b2, b3, 0), Ipv4Addr::new(10, b2, b3, 255))
            })
            .collect();
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                let mut builder = IpSetBuilder::<Ipv4Addr>::new();
                for &range in &raw_adds {
                    builder.add_range(range);
                }
                for &range in &raw_removes {
                    builder.remove_range(range);
                }
                black_box(builder.build())
            });
        });
    }
    group.finish();
}

/// `is_subset_of` — two-pointer walk via difference; O(m + n).
///
/// Three cases:
///   true_subset  — a is fully contained within b (best case: early exit possible).
///   false_subset — a extends beyond b (worst case: full walk).
///   disjoint     — a and b share no addresses.
fn bench_is_subset_of(c: &mut Criterion) {
    let mut group = c.benchmark_group("is_subset_of");
    for &size in &[100u32, 1_000, 10_000] {
        // a ⊆ b: inner half is always a subset of the full set
        let a_sub = make_set(size / 4, size / 2);
        let b_full = make_set(0, size);
        group.bench_with_input(BenchmarkId::new("true_subset", size), &size, |bench, _| {
            bench.iter(|| black_box(a_sub.is_subset_of(black_box(&b_full))));
        });

        // a ⊄ b: a extends past b's end
        let a_ext = make_set(size / 2, size);
        let b_half = make_set(0, size / 2);
        group.bench_with_input(BenchmarkId::new("false_subset", size), &size, |bench, _| {
            bench.iter(|| black_box(a_ext.is_subset_of(black_box(&b_half))));
        });

        // Disjoint: a and b share no addresses
        let a_lo = make_set(0, size / 2);
        let b_hi = make_set(size, size / 2);
        group.bench_with_input(BenchmarkId::new("disjoint", size), &size, |bench, _| {
            bench.iter(|| black_box(a_lo.is_subset_of(black_box(&b_hi))));
        });
    }
    group.finish();
}

/// `IpRange::prefixes` — CIDR decomposition of a single range.
///
/// Two cases:
///   aligned   — `/24` block; always produces 1 prefix.
///   unaligned — `10.0.0.1..10.0.0.254`; produces 14 prefixes (staircase).
fn bench_iprange_prefixes(c: &mut Criterion) {
    let mut group = c.benchmark_group("iprange_prefixes");
    let aligned = IpRange::new(Ipv4Addr::new(192, 168, 1, 0), Ipv4Addr::new(192, 168, 1, 255));
    group.bench_with_input(BenchmarkId::from_parameter("aligned"), &aligned, |b, r| {
        b.iter(|| black_box(r.prefixes()));
    });
    let unaligned = IpRange::new(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 254));
    group.bench_with_input(BenchmarkId::from_parameter("unaligned"), &unaligned, |b, r| {
        b.iter(|| black_box(r.prefixes()));
    });
    group.finish();
}

/// `IpSet::prefixes` — CIDR decomposition across a full set.
///
/// Two sub-groups at each size:
///   aligned   — each stored range is a /24 block; 1 prefix per range, O(n) total.
///   unaligned — each stored range is `*.1..*.254`; 14 prefixes per range, O(14n) total.
fn bench_ipset_prefixes(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipset_prefixes");
    for &size in &[100u32, 1_000, 10_000] {
        let aligned = make_set(0, size);
        group.bench_with_input(BenchmarkId::new("aligned", size), &size, |b, _| {
            b.iter(|| black_box(aligned.prefixes()));
        });
        let unaligned = make_unaligned_set(size);
        group.bench_with_input(BenchmarkId::new("unaligned", size), &size, |b, _| {
            b.iter(|| black_box(unaligned.prefixes()));
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------

criterion_group!(
    benches,
    bench_contains_ip,
    bench_build,
    bench_build_with_removals,
    bench_union,
    bench_union_sparse,
    bench_intersection,
    bench_difference,
    bench_complement,
    bench_count,
    bench_is_subset_of,
    bench_iprange_prefixes,
    bench_ipset_prefixes,
);
criterion_main!(benches);
