#![no_main]

use ipnetx::prefix::IpPrefix;
use libfuzzer_sys::fuzz_target;
use std::net::{Ipv4Addr, Ipv6Addr};

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    if let Ok(p) = s.parse::<IpPrefix<Ipv4Addr>>() {
        // Successful parses must round-trip through Display.
        let repr = p.to_string();
        let reparsed = repr
            .parse::<IpPrefix<Ipv4Addr>>()
            .expect("Display output must re-parse");
        assert_eq!(p, reparsed, "IPv4 round-trip failed for {repr}");

        // mask must be in [0, 32].
        assert!(p.mask() <= 32);

        // masked() must be idempotent.
        assert_eq!(p.masked(), p.masked().masked());
    }

    if let Ok(p) = s.parse::<IpPrefix<Ipv6Addr>>() {
        let repr = p.to_string();
        let reparsed = repr
            .parse::<IpPrefix<Ipv6Addr>>()
            .expect("Display output must re-parse");
        assert_eq!(p, reparsed, "IPv6 round-trip failed for {repr}");

        assert!(p.mask() <= 128);
        assert_eq!(p.masked(), p.masked().masked());
    }
});
