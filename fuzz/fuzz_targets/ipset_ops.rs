#![no_main]

use arbitrary::Arbitrary;
use ipnetx::ipset::{IpSet, IpSetBuilder};
use ipnetx::range::IpRange;
use libfuzzer_sys::fuzz_target;
use std::net::Ipv4Addr;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    ranges_a: Vec<(u32, u32)>,
    ranges_b: Vec<(u32, u32)>,
}

fn build(pairs: &[(u32, u32)]) -> IpSet<Ipv4Addr> {
    let mut b = IpSetBuilder::<Ipv4Addr>::new();
    for &(s, e) in pairs {
        b.add_range(IpRange::new(
            Ipv4Addr::from_bits(s.min(e)),
            Ipv4Addr::from_bits(s.max(e)),
        ));
    }
    b.build()
}

fuzz_target!(|input: FuzzInput| {
    let a = build(&input.ranges_a);
    let b = build(&input.ranges_b);

    // Commutativity
    assert_eq!(a.union(&b), b.union(&a));
    assert_eq!(a.intersection(&b), b.intersection(&a));

    // Idempotence
    assert_eq!(a.union(&a), a);
    assert_eq!(a.intersection(&a), a);

    // Double complement
    assert_eq!(a.complement().complement(), a);

    // De Morgan: (a ∪ b)ᶜ == aᶜ ∩ bᶜ
    assert_eq!(
        a.union(&b).complement(),
        a.complement().intersection(&b.complement())
    );

    // difference == intersection with complement
    assert_eq!(a.difference(&b), a.intersection(&b.complement()));

    // Inclusion–exclusion: |a ∪ b| + |a ∩ b| == |a| + |b|
    assert_eq!(
        a.union(&b).count() + a.intersection(&b).count(),
        a.count() + b.count()
    );

    // Complement law: |a| + |aᶜ| == 2³²
    assert_eq!(a.count() + a.complement().count(), 1u128 << 32);

    // Subset / superset consistency
    assert_eq!(a.is_subset_of(&b), b.is_superset_of(&a));

    // Normalization invariant: ranges are sorted, non-overlapping, non-adjacent.
    for set in [&a, &b, &a.union(&b), &a.intersection(&b), &a.difference(&b)] {
        let ranges = set.ranges();
        for w in ranges.windows(2) {
            let end = w[0].end().to_bits();
            let next = w[1].start().to_bits();
            assert!(
                next > end.saturating_add(1),
                "normalization violated: end={end} next_start={next}"
            );
        }
    }
});
