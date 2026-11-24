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
use ipnetx::prefix::IpPrefix;
use ipnetx::range::IpRange;
use std::net::{Ipv4Addr, Ipv6Addr};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Returns the `idx`-th /24 block in the benchmark address layout.
///
/// Blocks are laid out with a stride of two /24s (`10.0.0.0/24`, `10.0.2.0/24`,
/// ...), so **adjacent indices are never adjacent in address space**. This
/// matters: `IpSetBuilder::build` merges touching ranges, so a layout of
/// back-to-back /24s collapses to a single stored range regardless of `count`
/// and every benchmark would silently measure a one-element set.
fn block(idx: u32) -> IpRange<Ipv4Addr> {
    let n = idx * 2;
    let b2 = ((n / 256) % 256) as u8;
    let b3 = (n % 256) as u8;
    IpRange::new(Ipv4Addr::new(10, b2, b3, 0), Ipv4Addr::new(10, b2, b3, 255))
}

/// Builds an `IpSet` of `count` separated /24 blocks, offset by `start`.
///
/// Block indices `start..start + count` are used, so two calls with different
/// `start` values produce sets that partially overlap, which is the interesting
/// case for intersection and difference. Asserts that the stored range count
/// equals `count`, so a layout change that causes merging fails loudly.
fn make_set(start: u32, count: u32) -> IpSet<Ipv4Addr> {
    let mut builder = IpSetBuilder::<Ipv4Addr>::new();
    for i in start..start + count {
        builder.add_range(block(i));
    }
    let set = builder.build();
    assert_eq!(set.len(), count as usize, "make_set must not merge ranges");
    set
}

/// Returns the raw (unsorted, not yet built) ranges for `count` separated
/// /24 blocks, enumerated in reverse order so `build()` has real sorting work.
fn make_raw_ranges(count: u32) -> Vec<IpRange<Ipv4Addr>> {
    (0..count).rev().map(block).collect()
}

/// IPv6 counterpart of [`make_set`]: `count` separated /48 blocks under
/// `2001:db8::/32`, stride of two /48s.
fn v6_block(idx: u32) -> IpPrefix<Ipv6Addr> {
    let n = idx * 2;
    IpPrefix::new(Ipv6Addr::new(0x2001, 0xdb8, n as u16, 0, 0, 0, 0, 0), 48).unwrap()
}

fn make_set_v6(count: u32) -> IpSet<Ipv6Addr> {
    assert!(count * 2 <= u16::MAX as u32);
    let mut builder = IpSetBuilder::<Ipv6Addr>::new();
    for i in 0..count {
        builder.add_prefix(v6_block(i));
    }
    let set = builder.build();
    assert_eq!(set.len(), count as usize, "make_set_v6 must not merge ranges");
    set
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
    let set = builder.build();
    assert_eq!(set.len(), count as usize, "make_unaligned_set must not merge ranges");
    set
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
    let set = builder.build();
    assert_eq!(set.len(), count as usize, "make_sparse_set must not merge ranges");
    set
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

/// `contains_ip` — binary search; should be O(log n).
fn bench_contains_ip(c: &mut Criterion) {
    let mut group = c.benchmark_group("contains_ip");
    for &size in &[100u32, 1_000, 10_000] {
        let set = make_set(0, size);
        // An IP inside the middle block, and one in the gap just after it.
        let mid = block(size / 2);
        let hit = Ipv4Addr::from_bits(mid.start().to_bits() + 128);
        let miss = Ipv4Addr::from_bits(mid.end().to_bits() + 128);
        assert!(set.contains_ip(hit) && !set.contains_ip(miss));
        group.bench_with_input(BenchmarkId::new("hit", size), &size, |b, _| {
            b.iter(|| set.contains_ip(black_box(hit)));
        });
        group.bench_with_input(BenchmarkId::new("miss", size), &size, |b, _| {
            b.iter(|| set.contains_ip(black_box(miss)));
        });
    }
    group.finish();
}

/// Whole-range and whole-prefix membership — the route-policy hot path.
///
/// `contains_range` and `contains_prefix` should cost the same; both are
/// included so any divergence is visible. Cases per size:
///   hit  — a /26 inside the middle stored block (host bits set in the input).
///   gap  — a /24 sitting in the gap between two stored blocks.
///   span — a /23 covering a stored block *and* the gap after it: both
///          endpoints would pass `contains_ip` individually only if the gap
///          were filled, so this exercises the "single enclosing range" rule.
/// IPv6 gets the same treatment on /48 blocks.
fn bench_contains_prefix(c: &mut Criterion) {
    let mut group = c.benchmark_group("contains_prefix");
    for &size in &[100u32, 1_000, 10_000] {
        let set = make_set(0, size);
        let mid = block(size / 2).start().to_bits();
        let hit = IpPrefix::new(Ipv4Addr::from_bits(mid + 64 + 5), 26).unwrap();
        let gap = IpPrefix::new(Ipv4Addr::from_bits(mid + 256), 24).unwrap();
        let span = IpPrefix::new(Ipv4Addr::from_bits(mid), 23).unwrap();
        assert!(set.contains_prefix(hit) && !set.contains_prefix(gap) && !set.contains_prefix(span));

        group.bench_with_input(BenchmarkId::new("v4_hit", size), &size, |b, _| {
            b.iter(|| set.contains_prefix(black_box(hit)));
        });
        group.bench_with_input(BenchmarkId::new("v4_gap", size), &size, |b, _| {
            b.iter(|| set.contains_prefix(black_box(gap)));
        });
        group.bench_with_input(BenchmarkId::new("v4_span", size), &size, |b, _| {
            b.iter(|| set.contains_prefix(black_box(span)));
        });
        // The pre-contains_prefix spelling used by pathvector-policy, kept as a baseline.
        group.bench_with_input(BenchmarkId::new("v4_hit_range_form", size), &size, |b, _| {
            b.iter(|| set.contains_range(black_box(hit).masked().to_range()));
        });

        let set6 = make_set_v6(size);
        let base = v6_block(size / 2);
        let hit6 = IpPrefix::new(
            Ipv6Addr::from_bits(base.ip().to_bits() + (1u128 << 70) + 7),
            64,
        )
        .unwrap();
        // /48 immediately after the middle block: the stride leaves it unstored.
        let gap6 = IpPrefix::new(Ipv6Addr::from_bits(base.ip().to_bits() + (1u128 << 80)), 48).unwrap();
        assert!(set6.contains_prefix(hit6) && !set6.contains_prefix(gap6));
        group.bench_with_input(BenchmarkId::new("v6_hit", size), &size, |b, _| {
            b.iter(|| set6.contains_prefix(black_box(hit6)));
        });
        group.bench_with_input(BenchmarkId::new("v6_gap", size), &size, |b, _| {
            b.iter(|| set6.contains_prefix(black_box(gap6)));
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
        let raw_adds = make_raw_ranges(size);
        let raw_removes: Vec<IpRange<Ipv4Addr>> = (size / 2..size).map(block).collect();
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
    bench_contains_prefix,
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
