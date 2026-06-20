//! Property-based regression tests.
//!
//! Covers algebraic laws, round-trips, and consistency invariants across
//! IpRange, IpPrefix, and IpSet for both IPv4 and IPv6.  Tests are
//! structured to act as a regression net over the O(m+n) rewrites of union,
//! difference, is_subset_of, and prefix decomposition.

use proptest::prelude::*;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::{
    ipset::{IpSet, IpSetBuilder},
    prefix::IpPrefix,
    range::IpRange,
};

// ── Strategies ────────────────────────────────────────────────────────────────

fn arb_ipv4() -> impl Strategy<Value = Ipv4Addr> {
    any::<u32>().prop_map(Ipv4Addr::from_bits)
}

fn arb_ipv4_range() -> impl Strategy<Value = IpRange<Ipv4Addr>> {
    (any::<u32>(), any::<u32>()).prop_map(|(a, b)| {
        let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
        IpRange::new(Ipv4Addr::from_bits(lo), Ipv4Addr::from_bits(hi))
    })
}

fn arb_ipv4_prefix() -> impl Strategy<Value = IpPrefix<Ipv4Addr>> {
    (any::<u32>(), 0u8..=32u8).prop_map(|(ip, mask)| {
        IpPrefix::new(Ipv4Addr::from_bits(ip), mask).unwrap()
    })
}

fn arb_ipv4_set() -> impl Strategy<Value = IpSet<Ipv4Addr>> {
    proptest::collection::vec(arb_ipv4_range(), 0..=8).prop_map(|ranges| {
        ranges
            .into_iter()
            .collect::<IpSetBuilder<Ipv4Addr>>()
            .build()
    })
}

// IPv6 addresses limited to the lower 32-bit range so that cardinalities stay
// manageable for tests that enumerate addresses or call prefixes().
fn arb_ipv6_small() -> impl Strategy<Value = Ipv6Addr> {
    any::<u32>().prop_map(|x| Ipv6Addr::from_bits(x as u128))
}

fn arb_ipv6_range_small() -> impl Strategy<Value = IpRange<Ipv6Addr>> {
    (any::<u32>(), any::<u32>()).prop_map(|(a, b)| {
        let (lo, hi) = if a <= b {
            (a as u128, b as u128)
        } else {
            (b as u128, a as u128)
        };
        IpRange::new(Ipv6Addr::from_bits(lo), Ipv6Addr::from_bits(hi))
    })
}

fn arb_ipv6_set_small() -> impl Strategy<Value = IpSet<Ipv6Addr>> {
    proptest::collection::vec(arb_ipv6_range_small(), 0..=8).prop_map(|ranges| {
        ranges
            .into_iter()
            .collect::<IpSetBuilder<Ipv6Addr>>()
            .build()
    })
}

// Full 128-bit address space — for IpRange/IpPrefix tests and algebra tests
// that don't enumerate individual addresses.
fn arb_ipv6() -> impl Strategy<Value = Ipv6Addr> {
    any::<u128>().prop_map(Ipv6Addr::from_bits)
}

fn arb_ipv6_prefix() -> impl Strategy<Value = IpPrefix<Ipv6Addr>> {
    (any::<u128>(), 0u8..=128u8).prop_map(|(ip, mask)| {
        IpPrefix::new(Ipv6Addr::from_bits(ip), mask).unwrap()
    })
}

fn arb_ipv6_range_full() -> impl Strategy<Value = IpRange<Ipv6Addr>> {
    (any::<u128>(), any::<u128>()).prop_map(|(a, b)| {
        let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
        IpRange::new(Ipv6Addr::from_bits(lo), Ipv6Addr::from_bits(hi))
    })
}

fn arb_ipv6_set_full() -> impl Strategy<Value = IpSet<Ipv6Addr>> {
    proptest::collection::vec(arb_ipv6_range_full(), 0..=8).prop_map(|ranges| {
        ranges
            .into_iter()
            .collect::<IpSetBuilder<Ipv6Addr>>()
            .build()
    })
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn empty_v4() -> IpSet<Ipv4Addr> {
    IpSetBuilder::<Ipv4Addr>::new().build()
}

fn full_v4() -> IpSet<Ipv4Addr> {
    let mut b = IpSetBuilder::<Ipv4Addr>::new();
    b.add_range(IpRange::new(Ipv4Addr::UNSPECIFIED, Ipv4Addr::BROADCAST));
    b.build()
}

fn empty_v6() -> IpSet<Ipv6Addr> {
    IpSetBuilder::<Ipv6Addr>::new().build()
}

// ── IPv4: IpRange ─────────────────────────────────────────────────────────────

proptest! {
    #[test]
    fn prop_v4_range_contains_iff_in_bounds(r in arb_ipv4_range(), ip in arb_ipv4()) {
        let ip_u = ip.to_bits();
        let expected = ip_u >= r.start().to_bits() && ip_u <= r.end().to_bits();
        prop_assert_eq!(r.contains(ip), expected);
    }

    #[test]
    fn prop_v4_range_overlaps_reflexive(r in arb_ipv4_range()) {
        prop_assert!(r.overlaps(&r));
    }

    #[test]
    fn prop_v4_range_overlaps_symmetric(a in arb_ipv4_range(), b in arb_ipv4_range()) {
        prop_assert_eq!(a.overlaps(&b), b.overlaps(&a));
    }

    #[test]
    fn prop_v4_range_prefixes_cover_exact_addresses(r in arb_ipv4_range()) {
        // Rebuilding from prefix decomposition produces the same set as the range.
        let mut from_prefixes = IpSetBuilder::<Ipv4Addr>::new();
        for p in r.prefixes() {
            from_prefixes.add_prefix(p);
        }
        let mut from_range = IpSetBuilder::<Ipv4Addr>::new();
        from_range.add_range(r);
        prop_assert_eq!(from_prefixes.build(), from_range.build());
    }

    #[test]
    fn prop_v4_range_each_prefix_is_valid_cidr(r in arb_ipv4_range()) {
        // Every prefix from prefixes() round-trips through to_range().prefix().
        for p in r.prefixes() {
            let recovered = p.masked().to_range().prefix();
            prop_assert!(
                recovered.is_some(),
                "prefix {:?} did not round-trip; to_range().prefix() was None",
                p
            );
        }
    }
}

// ── IPv4: IpPrefix ────────────────────────────────────────────────────────────

proptest! {
    #[test]
    fn prop_v4_prefix_contains_iff_in_range(p in arb_ipv4_prefix(), ip in arb_ipv4()) {
        prop_assert_eq!(p.contains(ip), p.to_range().contains(ip));
    }

    #[test]
    fn prop_v4_prefix_to_range_roundtrip(p in arb_ipv4_prefix()) {
        // masked() gives canonical form; its range must identify as the same prefix.
        let canonical = p.masked();
        let recovered = canonical
            .to_range()
            .prefix()
            .expect("canonical prefix range must identify as CIDR");
        prop_assert_eq!(recovered, canonical);
    }

    #[test]
    fn prop_v4_prefix_masked_is_idempotent(p in arb_ipv4_prefix()) {
        prop_assert_eq!(p.masked().masked(), p.masked());
    }

    #[test]
    fn prop_v4_prefix_overlaps_self(p in arb_ipv4_prefix()) {
        prop_assert!(p.overlaps(&p));
    }

    #[test]
    fn prop_v4_prefix_overlaps_symmetric(a in arb_ipv4_prefix(), b in arb_ipv4_prefix()) {
        prop_assert_eq!(a.overlaps(&b), b.overlaps(&a));
    }
}

// ── IPv4: Union laws ──────────────────────────────────────────────────────────

proptest! {
    #[test]
    fn prop_v4_union_commutative(a in arb_ipv4_set(), b in arb_ipv4_set()) {
        prop_assert_eq!(a.union(&b), b.union(&a));
    }

    #[test]
    fn prop_v4_union_associative(
        a in arb_ipv4_set(),
        b in arb_ipv4_set(),
        c in arb_ipv4_set(),
    ) {
        prop_assert_eq!(a.union(&b).union(&c), a.union(&b.union(&c)));
    }

    #[test]
    fn prop_v4_union_identity(a in arb_ipv4_set()) {
        prop_assert_eq!(a.union(&empty_v4()), a.clone());
        prop_assert_eq!(empty_v4().union(&a), a);
    }

    #[test]
    fn prop_v4_union_with_full_is_full(a in arb_ipv4_set()) {
        prop_assert_eq!(a.union(&full_v4()), full_v4());
    }

    #[test]
    fn prop_v4_union_idempotent(a in arb_ipv4_set()) {
        prop_assert_eq!(a.union(&a), a);
    }
}

// ── IPv4: Intersection laws ───────────────────────────────────────────────────

proptest! {
    #[test]
    fn prop_v4_intersection_commutative(a in arb_ipv4_set(), b in arb_ipv4_set()) {
        prop_assert_eq!(a.intersection(&b), b.intersection(&a));
    }

    #[test]
    fn prop_v4_intersection_associative(
        a in arb_ipv4_set(),
        b in arb_ipv4_set(),
        c in arb_ipv4_set(),
    ) {
        prop_assert_eq!(
            a.intersection(&b).intersection(&c),
            a.intersection(&b.intersection(&c))
        );
    }

    #[test]
    fn prop_v4_intersection_with_empty_is_empty(a in arb_ipv4_set()) {
        prop_assert_eq!(a.intersection(&empty_v4()), empty_v4());
        prop_assert_eq!(empty_v4().intersection(&a), empty_v4());
    }

    #[test]
    fn prop_v4_intersection_with_full_is_self(a in arb_ipv4_set()) {
        prop_assert_eq!(a.intersection(&full_v4()), a);
    }

    #[test]
    fn prop_v4_intersection_idempotent(a in arb_ipv4_set()) {
        prop_assert_eq!(a.intersection(&a), a);
    }
}

// ── IPv4: Absorption and distributivity ───────────────────────────────────────

proptest! {
    #[test]
    fn prop_v4_absorption_union_of_intersection(a in arb_ipv4_set(), b in arb_ipv4_set()) {
        // a ∪ (a ∩ b) == a
        prop_assert_eq!(a.union(&a.intersection(&b)), a);
    }

    #[test]
    fn prop_v4_absorption_intersection_of_union(a in arb_ipv4_set(), b in arb_ipv4_set()) {
        // a ∩ (a ∪ b) == a
        prop_assert_eq!(a.intersection(&a.union(&b)), a);
    }

    #[test]
    fn prop_v4_distributivity_intersection_over_union(
        a in arb_ipv4_set(),
        b in arb_ipv4_set(),
        c in arb_ipv4_set(),
    ) {
        // a ∩ (b ∪ c) == (a ∩ b) ∪ (a ∩ c)
        prop_assert_eq!(
            a.intersection(&b.union(&c)),
            a.intersection(&b).union(&a.intersection(&c))
        );
    }

    #[test]
    fn prop_v4_distributivity_union_over_intersection(
        a in arb_ipv4_set(),
        b in arb_ipv4_set(),
        c in arb_ipv4_set(),
    ) {
        // a ∪ (b ∩ c) == (a ∪ b) ∩ (a ∪ c)
        prop_assert_eq!(
            a.union(&b.intersection(&c)),
            a.union(&b).intersection(&a.union(&c))
        );
    }
}

// ── IPv4: Complement laws ─────────────────────────────────────────────────────

proptest! {
    #[test]
    fn prop_v4_complement_involution(a in arb_ipv4_set()) {
        prop_assert_eq!(a.complement().complement(), a);
    }

    #[test]
    fn prop_v4_complement_union_is_full(a in arb_ipv4_set()) {
        prop_assert_eq!(a.union(&a.complement()), full_v4());
    }

    #[test]
    fn prop_v4_complement_intersection_is_empty(a in arb_ipv4_set()) {
        prop_assert!(a.intersection(&a.complement()).is_empty());
    }

    #[test]
    fn prop_v4_de_morgan_union(a in arb_ipv4_set(), b in arb_ipv4_set()) {
        // complement(a ∪ b) == complement(a) ∩ complement(b)
        prop_assert_eq!(
            a.union(&b).complement(),
            a.complement().intersection(&b.complement())
        );
    }

    #[test]
    fn prop_v4_de_morgan_intersection(a in arb_ipv4_set(), b in arb_ipv4_set()) {
        // complement(a ∩ b) == complement(a) ∪ complement(b)
        prop_assert_eq!(
            a.intersection(&b).complement(),
            a.complement().union(&b.complement())
        );
    }
}

// ── IPv4: Difference laws ─────────────────────────────────────────────────────

proptest! {
    #[test]
    fn prop_v4_difference_self_is_empty(a in arb_ipv4_set()) {
        prop_assert!(a.difference(&a).is_empty());
    }

    #[test]
    fn prop_v4_difference_with_empty(a in arb_ipv4_set()) {
        prop_assert_eq!(a.difference(&empty_v4()), a.clone());
        prop_assert!(empty_v4().difference(&a).is_empty());
    }

    #[test]
    fn prop_v4_difference_with_full_is_empty(a in arb_ipv4_set()) {
        prop_assert!(a.difference(&full_v4()).is_empty());
    }

    #[test]
    fn prop_v4_difference_equals_intersection_with_complement(
        a in arb_ipv4_set(),
        b in arb_ipv4_set(),
    ) {
        // a ∖ b == a ∩ complement(b)  — cross-validates difference against complement+intersection
        prop_assert_eq!(a.difference(&b), a.intersection(&b.complement()));
    }

    #[test]
    fn prop_v4_difference_disjoint_from_subtracted(a in arb_ipv4_set(), b in arb_ipv4_set()) {
        // (a ∖ b) ∩ b == ∅
        prop_assert!(a.difference(&b).intersection(&b).is_empty());
    }

    #[test]
    fn prop_v4_difference_is_subset_of_original(a in arb_ipv4_set(), b in arb_ipv4_set()) {
        // a ∖ b ⊆ a
        prop_assert!(a.difference(&b).is_subset_of(&a));
    }

    #[test]
    fn prop_v4_original_subset_of_difference_union_b(a in arb_ipv4_set(), b in arb_ipv4_set()) {
        // a ⊆ (a ∖ b) ∪ b
        prop_assert!(a.is_subset_of(&a.difference(&b).union(&b)));
    }
}

// ── IPv4: Subset / superset ───────────────────────────────────────────────────

proptest! {
    #[test]
    fn prop_v4_subset_reflexive(a in arb_ipv4_set()) {
        prop_assert!(a.is_subset_of(&a));
        prop_assert!(a.is_superset_of(&a));
    }

    #[test]
    fn prop_v4_empty_is_subset_of_everything(a in arb_ipv4_set()) {
        prop_assert!(empty_v4().is_subset_of(&a));
        prop_assert!(a.is_superset_of(&empty_v4()));
    }

    #[test]
    fn prop_v4_everything_is_subset_of_full(a in arb_ipv4_set()) {
        prop_assert!(a.is_subset_of(&full_v4()));
    }

    #[test]
    fn prop_v4_subset_iff_intersection_eq_self(a in arb_ipv4_set(), b in arb_ipv4_set()) {
        // a ⊆ b  ←→  a ∩ b == a
        prop_assert_eq!(a.is_subset_of(&b), a.intersection(&b) == a);
    }

    #[test]
    fn prop_v4_subset_iff_union_eq_other(a in arb_ipv4_set(), b in arb_ipv4_set()) {
        // a ⊆ b  ←→  a ∪ b == b
        prop_assert_eq!(a.is_subset_of(&b), a.union(&b) == b);
    }

    #[test]
    fn prop_v4_subset_iff_difference_empty(a in arb_ipv4_set(), b in arb_ipv4_set()) {
        // a ⊆ b  ←→  a ∖ b == ∅
        prop_assert_eq!(a.is_subset_of(&b), a.difference(&b).is_empty());
    }

    #[test]
    fn prop_v4_subset_antisymmetric(a in arb_ipv4_set(), b in arb_ipv4_set()) {
        // a ⊆ b ∧ b ⊆ a  →  a == b
        if a.is_subset_of(&b) && b.is_subset_of(&a) {
            prop_assert_eq!(a, b);
        }
    }

    #[test]
    fn prop_v4_subset_transitive(
        a in arb_ipv4_set(),
        b in arb_ipv4_set(),
        c in arb_ipv4_set(),
    ) {
        // a ⊆ b ∧ b ⊆ c  →  a ⊆ c
        if a.is_subset_of(&b) && b.is_subset_of(&c) {
            prop_assert!(a.is_subset_of(&c));
        }
    }
}

// ── IPv4: Overlaps ────────────────────────────────────────────────────────────

proptest! {
    #[test]
    fn prop_v4_overlaps_symmetric(a in arb_ipv4_set(), b in arb_ipv4_set()) {
        prop_assert_eq!(a.overlaps_ip_set(&b), b.overlaps_ip_set(&a));
    }

    #[test]
    fn prop_v4_overlaps_iff_intersection_nonempty(a in arb_ipv4_set(), b in arb_ipv4_set()) {
        prop_assert_eq!(a.overlaps_ip_set(&b), !a.intersection(&b).is_empty());
    }

    #[test]
    fn prop_v4_empty_does_not_overlap(a in arb_ipv4_set()) {
        prop_assert!(!empty_v4().overlaps_ip_set(&a));
        prop_assert!(!a.overlaps_ip_set(&empty_v4()));
    }
}

// ── IPv4: Count / cardinality ─────────────────────────────────────────────────

proptest! {
    #[test]
    fn prop_v4_count_inclusion_exclusion(a in arb_ipv4_set(), b in arb_ipv4_set()) {
        // |a ∪ b| + |a ∩ b| == |a| + |b|
        prop_assert_eq!(
            a.union(&b).count() + a.intersection(&b).count(),
            a.count() + b.count()
        );
    }

    #[test]
    fn prop_v4_count_complement(a in arb_ipv4_set()) {
        // |a| + |complement(a)| == 2^32
        prop_assert_eq!(a.count() + a.complement().count(), 1u128 << 32);
    }

    #[test]
    fn prop_v4_count_difference(a in arb_ipv4_set(), b in arb_ipv4_set()) {
        // |a ∖ b| == |a| − |a ∩ b|
        prop_assert_eq!(
            a.difference(&b).count(),
            a.count() - a.intersection(&b).count()
        );
    }

    #[test]
    fn prop_v4_count_monotone_union(a in arb_ipv4_set(), b in arb_ipv4_set()) {
        let u = a.union(&b).count();
        prop_assert!(u >= a.count(), "|a ∪ b| < |a|");
        prop_assert!(u >= b.count(), "|a ∪ b| < |b|");
    }

    #[test]
    fn prop_v4_count_monotone_intersection(a in arb_ipv4_set(), b in arb_ipv4_set()) {
        let i = a.intersection(&b).count();
        prop_assert!(i <= a.count(), "|a ∩ b| > |a|");
        prop_assert!(i <= b.count(), "|a ∩ b| > |b|");
    }
}

// ── IPv4: Prefix round-trips ──────────────────────────────────────────────────

proptest! {
    #[test]
    fn prop_v4_ipset_prefixes_roundtrip(a in arb_ipv4_set()) {
        // IpSet::prefixes() decomposes exactly; rebuilding gives the same set.
        let rebuilt: IpSetBuilder<Ipv4Addr> = a.prefixes().into_iter().collect();
        prop_assert_eq!(rebuilt.build(), a);
    }

    #[test]
    fn prop_v4_ipset_prefixes_idempotent(a in arb_ipv4_set()) {
        prop_assert_eq!(a.prefixes(), a.prefixes());
    }
}

// ── IPv4: Contains consistency ────────────────────────────────────────────────

proptest! {
    #[test]
    fn prop_v4_contains_ip_iff_in_some_range(a in arb_ipv4_set(), ip in arb_ipv4()) {
        let expected = a.ranges().iter().any(|r| r.contains(ip));
        prop_assert_eq!(a.contains_ip(ip), expected);
    }

    #[test]
    fn prop_v4_contains_ip_union(a in arb_ipv4_set(), b in arb_ipv4_set(), ip in arb_ipv4()) {
        // ip ∈ a ∪ b  ←→  ip ∈ a OR ip ∈ b
        prop_assert_eq!(
            a.union(&b).contains_ip(ip),
            a.contains_ip(ip) || b.contains_ip(ip)
        );
    }

    #[test]
    fn prop_v4_contains_ip_intersection(
        a in arb_ipv4_set(),
        b in arb_ipv4_set(),
        ip in arb_ipv4(),
    ) {
        // ip ∈ a ∩ b  ←→  ip ∈ a AND ip ∈ b
        prop_assert_eq!(
            a.intersection(&b).contains_ip(ip),
            a.contains_ip(ip) && b.contains_ip(ip)
        );
    }

    #[test]
    fn prop_v4_contains_ip_difference(
        a in arb_ipv4_set(),
        b in arb_ipv4_set(),
        ip in arb_ipv4(),
    ) {
        // ip ∈ a ∖ b  ←→  ip ∈ a AND ip ∉ b
        prop_assert_eq!(
            a.difference(&b).contains_ip(ip),
            a.contains_ip(ip) && !b.contains_ip(ip)
        );
    }

    #[test]
    fn prop_v4_contains_ip_complement(a in arb_ipv4_set(), ip in arb_ipv4()) {
        // ip ∈ complement(a)  ←→  ip ∉ a
        prop_assert_eq!(a.complement().contains_ip(ip), !a.contains_ip(ip));
    }

    #[test]
    fn prop_v4_contains_range_implies_is_subset(a in arb_ipv4_set(), r in arb_ipv4_range()) {
        // contains_range(r) → the set {r} is a subset of a
        if a.contains_range(r) {
            let mut br = IpSetBuilder::<Ipv4Addr>::new();
            br.add_range(r);
            prop_assert!(br.build().is_subset_of(&a));
        }
    }
}

// ── IPv4: Normalization invariant ─────────────────────────────────────────────

proptest! {
    #[test]
    fn prop_v4_ranges_sorted_nonoverlapping_nonadjacent(a in arb_ipv4_set()) {
        // Consecutive stored ranges must be strictly separated (not adjacent, not overlapping).
        for w in a.ranges().windows(2) {
            let end = w[0].end().to_bits() as u128;
            let start = w[1].start().to_bits() as u128;
            prop_assert!(
                end + 1 < start,
                "ranges not properly separated: prev_end={end} next_start={start}"
            );
        }
    }
}

// ── IPv6: IpRange ─────────────────────────────────────────────────────────────

proptest! {
    #[test]
    fn prop_v6_range_contains_iff_in_bounds(r in arb_ipv6_range_full(), ip in arb_ipv6()) {
        let ip_u = ip.to_bits();
        let expected = ip_u >= r.start().to_bits() && ip_u <= r.end().to_bits();
        prop_assert_eq!(r.contains(ip), expected);
    }

    #[test]
    fn prop_v6_range_overlaps_reflexive(r in arb_ipv6_range_full()) {
        prop_assert!(r.overlaps(&r));
    }

    #[test]
    fn prop_v6_range_overlaps_symmetric(a in arb_ipv6_range_full(), b in arb_ipv6_range_full()) {
        prop_assert_eq!(a.overlaps(&b), b.overlaps(&a));
    }

    #[test]
    fn prop_v6_range_prefixes_cover_exact_addresses(r in arb_ipv6_range_small()) {
        // Use small ranges so prefix decomposition stays tractable.
        let mut from_prefixes = IpSetBuilder::<Ipv6Addr>::new();
        for p in r.prefixes() {
            from_prefixes.add_prefix(p);
        }
        let mut from_range = IpSetBuilder::<Ipv6Addr>::new();
        from_range.add_range(r);
        prop_assert_eq!(from_prefixes.build(), from_range.build());
    }

    #[test]
    fn prop_v6_range_each_prefix_is_valid_cidr(r in arb_ipv6_range_small()) {
        for p in r.prefixes() {
            let recovered = p.masked().to_range().prefix();
            prop_assert!(
                recovered.is_some(),
                "prefix {:?} did not round-trip; to_range().prefix() was None",
                p
            );
        }
    }
}

// ── IPv6: IpPrefix ────────────────────────────────────────────────────────────

proptest! {
    #[test]
    fn prop_v6_prefix_contains_iff_in_range(p in arb_ipv6_prefix(), ip in arb_ipv6()) {
        prop_assert_eq!(p.contains(ip), p.to_range().contains(ip));
    }

    #[test]
    fn prop_v6_prefix_to_range_roundtrip(p in arb_ipv6_prefix()) {
        let canonical = p.masked();
        let recovered = canonical
            .to_range()
            .prefix()
            .expect("canonical prefix range must identify as CIDR");
        prop_assert_eq!(recovered, canonical);
    }

    #[test]
    fn prop_v6_prefix_masked_is_idempotent(p in arb_ipv6_prefix()) {
        prop_assert_eq!(p.masked().masked(), p.masked());
    }

    #[test]
    fn prop_v6_prefix_overlaps_self(p in arb_ipv6_prefix()) {
        prop_assert!(p.overlaps(&p));
    }

    #[test]
    fn prop_v6_prefix_overlaps_symmetric(a in arb_ipv6_prefix(), b in arb_ipv6_prefix()) {
        prop_assert_eq!(a.overlaps(&b), b.overlaps(&a));
    }
}

// ── IPv6: Union laws ──────────────────────────────────────────────────────────

proptest! {
    #[test]
    fn prop_v6_union_commutative(a in arb_ipv6_set_full(), b in arb_ipv6_set_full()) {
        prop_assert_eq!(a.union(&b), b.union(&a));
    }

    #[test]
    fn prop_v6_union_associative(
        a in arb_ipv6_set_full(),
        b in arb_ipv6_set_full(),
        c in arb_ipv6_set_full(),
    ) {
        prop_assert_eq!(a.union(&b).union(&c), a.union(&b.union(&c)));
    }

    #[test]
    fn prop_v6_union_identity(a in arb_ipv6_set_full()) {
        prop_assert_eq!(a.union(&empty_v6()), a.clone());
        prop_assert_eq!(empty_v6().union(&a), a);
    }

    #[test]
    fn prop_v6_union_idempotent(a in arb_ipv6_set_full()) {
        prop_assert_eq!(a.union(&a), a);
    }
}

// ── IPv6: Intersection laws ───────────────────────────────────────────────────

proptest! {
    #[test]
    fn prop_v6_intersection_commutative(a in arb_ipv6_set_full(), b in arb_ipv6_set_full()) {
        prop_assert_eq!(a.intersection(&b), b.intersection(&a));
    }

    #[test]
    fn prop_v6_intersection_associative(
        a in arb_ipv6_set_full(),
        b in arb_ipv6_set_full(),
        c in arb_ipv6_set_full(),
    ) {
        prop_assert_eq!(
            a.intersection(&b).intersection(&c),
            a.intersection(&b.intersection(&c))
        );
    }

    #[test]
    fn prop_v6_intersection_idempotent(a in arb_ipv6_set_full()) {
        prop_assert_eq!(a.intersection(&a), a);
    }
}

// ── IPv6: Complement laws ─────────────────────────────────────────────────────

proptest! {
    #[test]
    fn prop_v6_complement_involution(a in arb_ipv6_set_full()) {
        prop_assert_eq!(a.complement().complement(), a);
    }

    #[test]
    fn prop_v6_complement_intersection_is_empty(a in arb_ipv6_set_full()) {
        prop_assert!(a.intersection(&a.complement()).is_empty());
    }

    #[test]
    fn prop_v6_de_morgan_union(a in arb_ipv6_set_full(), b in arb_ipv6_set_full()) {
        prop_assert_eq!(
            a.union(&b).complement(),
            a.complement().intersection(&b.complement())
        );
    }

    #[test]
    fn prop_v6_de_morgan_intersection(a in arb_ipv6_set_full(), b in arb_ipv6_set_full()) {
        prop_assert_eq!(
            a.intersection(&b).complement(),
            a.complement().union(&b.complement())
        );
    }
}

// ── IPv6: Difference laws ─────────────────────────────────────────────────────

proptest! {
    #[test]
    fn prop_v6_difference_equals_intersection_with_complement(
        a in arb_ipv6_set_full(),
        b in arb_ipv6_set_full(),
    ) {
        prop_assert_eq!(a.difference(&b), a.intersection(&b.complement()));
    }

    #[test]
    fn prop_v6_difference_disjoint_from_subtracted(
        a in arb_ipv6_set_full(),
        b in arb_ipv6_set_full(),
    ) {
        prop_assert!(a.difference(&b).intersection(&b).is_empty());
    }

    #[test]
    fn prop_v6_difference_is_subset_of_original(
        a in arb_ipv6_set_full(),
        b in arb_ipv6_set_full(),
    ) {
        prop_assert!(a.difference(&b).is_subset_of(&a));
    }
}

// ── IPv6: Subset ──────────────────────────────────────────────────────────────

proptest! {
    #[test]
    fn prop_v6_subset_iff_intersection_eq_self(
        a in arb_ipv6_set_full(),
        b in arb_ipv6_set_full(),
    ) {
        prop_assert_eq!(a.is_subset_of(&b), a.intersection(&b) == a);
    }

    #[test]
    fn prop_v6_subset_iff_union_eq_other(
        a in arb_ipv6_set_full(),
        b in arb_ipv6_set_full(),
    ) {
        prop_assert_eq!(a.is_subset_of(&b), a.union(&b) == b);
    }

    #[test]
    fn prop_v6_subset_iff_difference_empty(
        a in arb_ipv6_set_full(),
        b in arb_ipv6_set_full(),
    ) {
        prop_assert_eq!(a.is_subset_of(&b), a.difference(&b).is_empty());
    }
}

// ── IPv6: Overlaps ────────────────────────────────────────────────────────────

proptest! {
    #[test]
    fn prop_v6_overlaps_symmetric(a in arb_ipv6_set_full(), b in arb_ipv6_set_full()) {
        prop_assert_eq!(a.overlaps_ip_set(&b), b.overlaps_ip_set(&a));
    }

    #[test]
    fn prop_v6_overlaps_iff_intersection_nonempty(
        a in arb_ipv6_set_full(),
        b in arb_ipv6_set_full(),
    ) {
        prop_assert_eq!(a.overlaps_ip_set(&b), !a.intersection(&b).is_empty());
    }
}

// ── IPv6: Normalization invariant ─────────────────────────────────────────────

proptest! {
    #[test]
    fn prop_v6_ranges_sorted_nonoverlapping_nonadjacent(a in arb_ipv6_set_full()) {
        for w in a.ranges().windows(2) {
            let end = w[0].end().to_bits();
            let start = w[1].start().to_bits();
            // end < u128::MAX here (there can be no next range if end were u128::MAX)
            prop_assert!(
                end.checked_add(1).map_or(false, |n| n < start),
                "ranges not properly separated: prev_end={end} next_start={start}"
            );
        }
    }
}

// ── IPv6: Small-space count, prefixes, and membership ────────────────────────

proptest! {
    #[test]
    fn prop_v6_count_inclusion_exclusion(
        a in arb_ipv6_set_small(),
        b in arb_ipv6_set_small(),
    ) {
        prop_assert_eq!(
            a.union(&b).count() + a.intersection(&b).count(),
            a.count() + b.count()
        );
    }

    #[test]
    fn prop_v6_ipset_prefixes_roundtrip(a in arb_ipv6_set_small()) {
        let rebuilt: IpSetBuilder<Ipv6Addr> = a.prefixes().into_iter().collect();
        prop_assert_eq!(rebuilt.build(), a);
    }

    #[test]
    fn prop_v6_contains_ip_union(
        a in arb_ipv6_set_small(),
        b in arb_ipv6_set_small(),
        ip in arb_ipv6_small(),
    ) {
        prop_assert_eq!(
            a.union(&b).contains_ip(ip),
            a.contains_ip(ip) || b.contains_ip(ip)
        );
    }

    #[test]
    fn prop_v6_contains_ip_intersection(
        a in arb_ipv6_set_small(),
        b in arb_ipv6_set_small(),
        ip in arb_ipv6_small(),
    ) {
        prop_assert_eq!(
            a.intersection(&b).contains_ip(ip),
            a.contains_ip(ip) && b.contains_ip(ip)
        );
    }

    #[test]
    fn prop_v6_contains_ip_difference(
        a in arb_ipv6_set_small(),
        b in arb_ipv6_set_small(),
        ip in arb_ipv6_small(),
    ) {
        prop_assert_eq!(
            a.difference(&b).contains_ip(ip),
            a.contains_ip(ip) && !b.contains_ip(ip)
        );
    }

    #[test]
    fn prop_v6_contains_ip_complement(a in arb_ipv6_set_small(), ip in arb_ipv6_small()) {
        // ip is in the lower 32-bit subspace; complement covers everything not in a,
        // including both gaps within that subspace and the entire upper range.
        prop_assert_eq!(a.complement().contains_ip(ip), !a.contains_ip(ip));
    }
}
