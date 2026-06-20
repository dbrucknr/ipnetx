#![no_main]

use ipnetx::range::IpRange;
use libfuzzer_sys::fuzz_target;
use std::net::{Ipv4Addr, Ipv6Addr};

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    if let Ok(r) = s.parse::<IpRange<Ipv4Addr>>() {
        // Successful parses must round-trip through Display.
        let repr = r.to_string();
        let reparsed = repr
            .parse::<IpRange<Ipv4Addr>>()
            .expect("Display output must re-parse");
        assert_eq!(r, reparsed, "IPv4 round-trip failed for {repr}");

        // Valid ranges must have start <= end.
        if r.is_valid() {
            assert!(r.start() <= r.end());
        }
    }

    if let Ok(r) = s.parse::<IpRange<Ipv6Addr>>() {
        let repr = r.to_string();
        let reparsed = repr
            .parse::<IpRange<Ipv6Addr>>()
            .expect("Display output must re-parse");
        assert_eq!(r, reparsed, "IPv6 round-trip failed for {repr}");

        if r.is_valid() {
            assert!(r.start() <= r.end());
        }
    }
});
