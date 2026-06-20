#![no_main]

use arbitrary::Arbitrary;
use ipnetx::ipset::IpSetBuilder;
use ipnetx::prefix::IpPrefix;
use ipnetx::range::IpRange;
use libfuzzer_sys::fuzz_target;
use std::net::Ipv4Addr;

#[derive(Arbitrary, Debug)]
enum Op {
    AddRange(u32, u32),
    RemoveRange(u32, u32),
    AddPrefix(u32, u8),
    RemovePrefix(u32, u8),
    AddIp(u32),
    RemoveIp(u32),
}

fuzz_target!(|ops: Vec<Op>| {
    let mut b = IpSetBuilder::<Ipv4Addr>::new();
    for op in ops {
        match op {
            Op::AddRange(s, e) => b.add_range(IpRange::new(
                Ipv4Addr::from_bits(s.min(e)),
                Ipv4Addr::from_bits(s.max(e)),
            )),
            Op::RemoveRange(s, e) => b.remove_range(IpRange::new(
                Ipv4Addr::from_bits(s.min(e)),
                Ipv4Addr::from_bits(s.max(e)),
            )),
            Op::AddPrefix(ip, mask) => {
                let mask = mask % 33;
                if let Ok(p) = IpPrefix::new(Ipv4Addr::from_bits(ip), mask) {
                    b.add_prefix(p);
                }
            }
            Op::RemovePrefix(ip, mask) => {
                let mask = mask % 33;
                if let Ok(p) = IpPrefix::new(Ipv4Addr::from_bits(ip), mask) {
                    b.remove_prefix(p);
                }
            }
            Op::AddIp(ip) => b.add_ip(Ipv4Addr::from_bits(ip)),
            Op::RemoveIp(ip) => b.remove_ip(Ipv4Addr::from_bits(ip)),
        }
    }

    let set = b.build();

    // Normalization invariant: sorted, non-overlapping, non-adjacent.
    for w in set.ranges().windows(2) {
        let end = w[0].end().to_bits();
        let next = w[1].start().to_bits();
        assert!(
            next > end.saturating_add(1),
            "normalization violated after builder ops: end={end} next_start={next}"
        );
    }

    // count() must agree with the number of ranges.
    assert!(set.count() >= set.len() as u128);

    // A set is always a subset of itself.
    assert!(set.is_subset_of(&set));
});
