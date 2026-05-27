use crate::{interfaces::IpAddress, prefix::IpPrefix};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpRange<A: IpAddress> {
    start: A,
    end: A,
}

impl<A: IpAddress> IpRange<A> {
    pub fn new(start: A, end: A) -> Self {
        Self { start, end }
    }

    pub fn start(&self) -> A {
        self.start
    }

    pub fn end(&self) -> A {
        self.end
    }

    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.start <= self.end
    }

    // Answers the question: "Is this IP entirely enclosed by this range?"
    #[must_use]
    pub fn contains(&self, ip: A) -> bool {
        self.is_valid() && self.start <= ip && ip <= self.end
    }

    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.start.is_unspecified() && self.end.is_unspecified()
    }

    // Answers the question: "does this share any IPs with the other range?"
    #[must_use]
    pub fn overlaps(&self, other: &IpRange<A>) -> bool {
        self.is_valid() && other.is_valid() && self.end >= other.start && self.start <= other.end
    }

    /// Returns `Some(prefix)` if this range is exactly one CIDR block, `None` otherwise.
    ///
    /// A range qualifies when its size is a power of two *and* the start address
    /// is aligned to that size (all host bits are zero).
    ///
    /// # Examples
    /// - `192.168.1.0..192.168.1.255` → `Some(192.168.1.0/24)`
    /// - `192.168.1.1..192.168.1.254` → `None` (size 254 is not a power of two)
    /// - `192.168.1.1..192.168.1.4`   → `None` (size 4 but start is misaligned)
    /// - `10.0.0.1..10.0.0.1`         → `Some(10.0.0.1/32)` (single IP)
    pub fn prefix(&self) -> Option<IpPrefix<A>> {
        if !self.is_valid() {
            return None;
        }

        let start = self.start().to_u128();
        let end = self.end().to_u128();
        let bits = A::BITS as u32;

        // size = end − start + 1 (number of addresses).
        // wrapping_add handles the entire-address-space edge case:
        // when span == u128::MAX, size wraps to 0, which we treat as 2^128.
        let span = end - start;
        let size = span.wrapping_add(1);

        // size must be a power of two (0 represents 2^128, which qualifies).
        if size != 0 && !size.is_power_of_two() {
            return None;
        }

        // h = host bits in the CIDR prefix.
        // For IPv4 h <= 32 == bits; for IPv6 h <= 128 == bits — never exceeds bits.
        let h = if size == 0 {
            // This line: `h = if size == 0` is showing as a missing region in llvm-cov (it's covered by IPv6, but not reachable with IPv4)
            128
        } else {
            size.trailing_zeros()
        };

        // start must be aligned to the block: its bottom h bits must all be zero.
        if start.trailing_zeros() < h {
            return None;
        }

        // mask is always in [0, bits]: IpPrefix::new cannot fail here.
        let mask = bits as u8 - h as u8;
        Some(IpPrefix::new(A::from_u128(start), mask).unwrap())
    }

    #[must_use]
    pub fn prefixes(&self) -> Vec<IpPrefix<A>> {
        if !self.is_valid() {
            return Vec::new();
        }

        let mut result = Vec::new();
        let mut start = self.start.to_u128();
        let end = self.end.to_u128();
        let bits = A::BITS as u32;

        while start <= end {
            // How many trailing zero bits does `start` have?
            // A CIDR block of size 2^h must be aligned to 2^h, so `start`
            // must have at least h trailing zeros to be the network address.
            // e.g. a /30 (h=2) must start at ...00 in binary.
            let max_host_bits = start.trailing_zeros().min(bits);

            // Of the allowed sizes, pick the largest block that fits within
            // `end` — work downward from max_host_bits until the block end
            // doesn't overshoot.
            let host_bits = (0..=max_host_bits)
                .rev()
                .find(|&h| {
                    // host_mask: all 1s in the bottom h bits, 0s above
                    let host_mask: u128 = if h == 0 { 0 } else { u128::MAX >> (128 - h) };
                    start | host_mask <= end
                })
                .unwrap_or(0);

            let host_mask: u128 = if host_bits == 0 {
                0
            } else {
                u128::MAX >> (128 - host_bits)
            };
            let mask = bits as u8 - host_bits as u8;

            result.push(IpPrefix::new(A::from_u128(start), mask).unwrap());

            // Advance start past the end of this block.
            // If host_mask is u128::MAX we've consumed the whole address space.
            match start.checked_add(host_mask).and_then(|n| n.checked_add(1)) {
                Some(next) => start = next,
                None => break,
            }
        }

        result
    }
}

impl<A: IpAddress> std::fmt::Display for IpRange<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}..{}", self.start, self.end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // --- Construction ---

    // cargo test range::tests::test_v4_new
    #[test]
    fn test_v4_new() {
        let range =
            IpRange::<Ipv4Addr>::new(Ipv4Addr::new(1, 0, 0, 0), Ipv4Addr::new(1, 255, 255, 255));
        assert!(range.is_valid());
    }

    // cargo test range::tests::test_v6_new
    #[test]
    fn test_v6_new() {
        let range = IpRange::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xff),
        );
        assert!(range.is_valid());
    }

    // --- Start / End ---

    // cargo test range::tests::test_v4_start
    #[test]
    fn test_v4_start() {
        let range = IpRange::new(Ipv4Addr::new(1, 0, 0, 0), Ipv4Addr::new(1, 255, 255, 255));
        assert_eq!(range.start(), Ipv4Addr::new(1, 0, 0, 0));
    }

    // cargo test range::tests::test_v4_end
    #[test]
    fn test_v4_end() {
        let range = IpRange::new(Ipv4Addr::new(1, 0, 0, 0), Ipv4Addr::new(1, 255, 255, 255));
        assert_eq!(range.end(), Ipv4Addr::new(1, 255, 255, 255));
    }

    // cargo test range::tests::test_v6_start
    #[test]
    fn test_v6_start() {
        let range = IpRange::new(
            Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 255),
        );
        assert_eq!(range.start(), Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 1));
    }

    // cargo test range::tests::test_v6_end
    #[test]
    fn test_v6_end() {
        let range = IpRange::new(
            Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 255),
        );
        assert_eq!(range.end(), Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 255));
    }

    // --- Validity ---

    // cargo test range::tests::test_v4_valid
    #[test]
    fn test_v4_valid() {
        let range = IpRange::new(Ipv4Addr::new(1, 0, 0, 0), Ipv4Addr::new(1, 255, 255, 255));
        assert!(range.is_valid());
    }

    // cargo test range::tests::test_v4_invalid
    #[test]
    fn test_v4_invalid() {
        let range = IpRange::new(Ipv4Addr::new(1, 255, 255, 255), Ipv4Addr::new(1, 0, 0, 0));
        assert!(!range.is_valid());
    }

    // cargo test range::tests::test_v6_valid
    #[test]
    fn test_v6_valid() {
        let range = IpRange::new(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),
        );
        assert!(range.is_valid());
    }

    // cargo test range::tests::test_v6_invalid
    #[test]
    fn test_v6_invalid() {
        let range = IpRange::new(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),
        );
        assert!(!range.is_valid());
    }

    // --- Contains ---

    // cargo test range::tests::test_v4_contains
    #[test]
    fn test_v4_contains() {
        let range = IpRange::new(Ipv4Addr::new(1, 0, 0, 0), Ipv4Addr::new(1, 255, 255, 255));
        assert!(range.contains(Ipv4Addr::new(1, 1, 1, 1)));
        assert!(!range.contains(Ipv4Addr::new(2, 0, 0, 0)));
    }

    // cargo test range::tests::test_v4_contains_boundaries
    #[test]
    fn test_v4_contains_boundaries() {
        let range = IpRange::new(Ipv4Addr::new(1, 0, 0, 0), Ipv4Addr::new(1, 255, 255, 255));

        assert!(range.contains(Ipv4Addr::new(1, 0, 0, 0))); // start inclusive
        assert!(range.contains(Ipv4Addr::new(1, 255, 255, 255))); // end inclusive

        assert!(!range.contains(Ipv4Addr::new(0, 255, 255, 255))); // just before start
        assert!(!range.contains(Ipv4Addr::new(2, 0, 0, 0))); // just after end
    }

    // cargo test range::tests::test_v4_contains_start_eq_end
    #[test]
    fn test_v4_contains_start_eq_end() {
        let range = IpRange::new(Ipv4Addr::new(1, 0, 0, 0), Ipv4Addr::new(1, 0, 0, 0));
        assert!(range.contains(Ipv4Addr::new(1, 0, 0, 0)));
    }

    // cargo test range::tests::test_v4_invalid_contains
    #[test]
    fn test_v4_invalid_contains() {
        let range = IpRange::new(Ipv4Addr::new(1, 255, 255, 255), Ipv4Addr::new(1, 0, 0, 0));
        assert!(!range.contains(Ipv4Addr::new(1, 1, 1, 1)));
        assert!(!range.contains(Ipv4Addr::new(2, 0, 0, 0)));
    }

    // cargo test range::tests::test_v6_contains
    #[test]
    fn test_v6_contains() {
        let range = IpRange::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xff),
        );
        assert!(range.contains(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x20)));
        assert!(!range.contains(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)));
    }

    // cargo test range::tests::test_v6_invalid_contains
    #[test]
    fn test_v6_invalid_contains() {
        let range = IpRange::new(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),
        );
        assert!(!range.contains(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)));
    }

    // --- Zero / Unspecified ---

    // cargo test range::tests::test_v4_is_zero
    #[test]
    fn test_v4_is_zero() {
        let range = IpRange::new(Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED);
        assert!(range.is_zero());
    }

    // cargo test range::tests::test_v6_is_zero
    #[test]
    fn test_v6_is_zero() {
        let range = IpRange::new(Ipv6Addr::UNSPECIFIED, Ipv6Addr::UNSPECIFIED);
        assert!(range.is_zero());
    }

    // cargo test range::tests::test_v4_is_not_zero
    #[test]
    fn test_v4_is_not_zero() {
        let range = IpRange::new(Ipv4Addr::new(1, 0, 0, 0), Ipv4Addr::new(1, 255, 255, 255));
        assert!(!range.is_zero());
    }

    // cargo test range::tests::test_v6_is_not_zero
    #[test]
    fn test_v6_is_not_zero() {
        let range = IpRange::new(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 2),
        );
        assert!(!range.is_zero());
    }

    // --- Overlaps ---

    // cargo test range::tests::test_v4_overlaps
    #[test]
    fn test_v4_overlaps() {
        let a = IpRange::new(Ipv4Addr::new(1, 0, 0, 0), Ipv4Addr::new(1, 255, 255, 255));
        let b = IpRange::new(Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(1, 255, 255, 255));
        assert!(a.overlaps(&b));
    }

    // cargo test range::tests::test_v4_overlaps_no_overlap
    #[test]
    fn test_v4_overlaps_no_overlap() {
        let a = IpRange::new(Ipv4Addr::new(1, 0, 0, 0), Ipv4Addr::new(1, 255, 255, 255));
        let b = IpRange::new(Ipv4Addr::new(2, 0, 0, 0), Ipv4Addr::new(2, 255, 255, 255));
        assert!(!a.overlaps(&b));
    }

    // cargo test range::tests::test_v4_overlaps_invalid_range
    #[test]
    fn test_v4_overlaps_invalid_range() {
        let valid = IpRange::new(Ipv4Addr::new(1, 0, 0, 0), Ipv4Addr::new(1, 255, 255, 255));
        let invalid = IpRange::new(Ipv4Addr::new(1, 255, 255, 255), Ipv4Addr::new(1, 0, 0, 0));
        assert!(!valid.overlaps(&invalid));
    }

    // cargo test range::tests::test_v4_adjacent_overlap
    #[test]
    fn test_v4_adjacent_overlap() {
        let a = IpRange::new(Ipv4Addr::new(1, 0, 0, 0), Ipv4Addr::new(1, 0, 0, 5));
        let b = IpRange::new(Ipv4Addr::new(1, 0, 0, 5), Ipv4Addr::new(1, 0, 0, 10));
        assert!(a.overlaps(&b)); // shares 1.0.0.5
    }

    // cargo test range::tests::test_v4_complete_overlap
    #[test]
    fn test_v4_complete_overlap() {
        let outer = IpRange::new(Ipv4Addr::new(1, 0, 0, 0), Ipv4Addr::new(1, 255, 255, 255));
        let inner = IpRange::new(Ipv4Addr::new(1, 10, 0, 0), Ipv4Addr::new(1, 20, 0, 0));
        assert!(outer.overlaps(&inner));
    }

    // cargo test range::tests::test_v6_overlaps
    #[test]
    fn test_v6_overlaps() {
        let a = IpRange::new(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 255),
        );
        let b = IpRange::new(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 255),
        );
        assert!(a.overlaps(&b));
    }

    // cargo test range::tests::test_v6_overlaps_no_overlap
    #[test]
    fn test_v6_overlaps_no_overlap() {
        let a = IpRange::new(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 255),
        );
        let b = IpRange::new(
            Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 255),
        );
        assert!(!a.overlaps(&b));
    }

    // cargo test range::tests::test_v6_overlaps_invalid_range
    #[test]
    fn test_v6_overlaps_invalid_range() {
        let valid = IpRange::new(
            Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 255),
        );
        let invalid = IpRange::new(
            Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 511),
            Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 255),
        );
        assert!(!valid.overlaps(&invalid));
    }

    // cargo test range::tests::test_v6_adjacent_overlap
    #[test]
    fn test_v6_adjacent_overlap() {
        let a = IpRange::new(
            Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 255),
        );
        let b = IpRange::new(
            Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 255),
            Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 511),
        );
        assert!(a.overlaps(&b));
    }

    // cargo test range::tests::test_v6_complete_overlap
    #[test]
    fn test_v6_complete_overlap() {
        let outer = IpRange::new(
            Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 255),
        );
        let inner = IpRange::new(
            Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 128),
            Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 200),
        );
        assert!(outer.overlaps(&inner));
    }

    // --- Prefixes ---

    // cargo test range::tests::test_v4_prefixes_aligned_range
    #[test]
    fn test_v4_prefixes_aligned_range() {
        let range = IpRange::new(
            Ipv4Addr::new(192, 168, 1, 0),
            Ipv4Addr::new(192, 168, 1, 255),
        );
        let prefixes = range.prefixes();

        assert_eq!(prefixes.len(), 1);
        assert_eq!(prefixes[0].ip(), Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(prefixes[0].mask(), 24);
    }

    // cargo test range::tests::test_v6_prefixes_aligned_range
    #[test]
    fn test_v6_prefixes_aligned_range() {
        let range = IpRange::new(
            Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 0),
            Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 255),
        );
        let prefixes = range.prefixes();

        assert_eq!(prefixes.len(), 1);
        assert_eq!(prefixes[0].ip(), Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 0));
        assert_eq!(prefixes[0].mask(), 120);
    }

    // cargo test range::tests::test_v4_prefixes_two_coalesced_ranges
    #[test]
    fn test_v4_prefixes_two_coalesced_ranges() {
        let range = IpRange::new(
            Ipv4Addr::new(192, 168, 0, 0),
            Ipv4Addr::new(192, 168, 1, 255),
        );
        let prefixes = range.prefixes();

        assert_eq!(prefixes.len(), 1);
        assert_eq!(prefixes[0].ip(), Ipv4Addr::new(192, 168, 0, 0));
        assert_eq!(prefixes[0].mask(), 23);
    }

    // cargo test range::tests::test_v6_prefixes_two_coalesced_ranges
    #[test]
    fn test_v6_prefixes_two_coalesced_ranges() {
        // Range: 1:: .. 1::1:ff  (covers 1::/112 then 1::1:0/120)
        let range = IpRange::new(
            Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 0),
            Ipv6Addr::new(1, 0, 0, 0, 0, 0, 1, 255),
        );
        let prefixes = range.prefixes();

        assert_eq!(prefixes.len(), 2);
        // first block: 1::/112 — 2^16 addresses (last 16 bits all free)
        assert_eq!(prefixes[0].ip(), Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 0));
        assert_eq!(prefixes[0].mask(), 112);
        // second block: 1::1:0/120 — 2^8 addresses (last 8 bits free)
        assert_eq!(prefixes[1].ip(), Ipv6Addr::new(1, 0, 0, 0, 0, 0, 1, 0));
        assert_eq!(prefixes[1].mask(), 120);
    }

    // cargo test range::tests::test_v4_prefixes_single_ip
    #[test]
    fn test_v4_prefixes_single_ip() {
        let range = IpRange::new(Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(192, 168, 1, 1));
        let prefixes = range.prefixes();

        assert_eq!(prefixes.len(), 1);
        assert_eq!(prefixes[0].ip(), Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(prefixes[0].mask(), 32);
    }

    // cargo test range::tests::test_v6_prefixes_single_ip
    #[test]
    fn test_v6_prefixes_single_ip() {
        let range = IpRange::new(
            Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 1),
        );
        let prefixes = range.prefixes();

        assert_eq!(prefixes.len(), 1);
        assert_eq!(prefixes[0].ip(), Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 1));
        assert_eq!(prefixes[0].mask(), 128);
    }

    // cargo test range::tests::test_v4_prefixes_unaligned_two_32
    #[test]
    fn test_v4_prefixes_unaligned_two_32() {
        let range = IpRange::new(Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(192, 168, 1, 2));
        let prefixes = range.prefixes();

        assert_eq!(prefixes.len(), 2);
        assert_eq!(prefixes[0].ip(), Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(prefixes[0].mask(), 32);
        assert_eq!(prefixes[1].ip(), Ipv4Addr::new(192, 168, 1, 2));
        assert_eq!(prefixes[1].mask(), 32);
    }

    // cargo test range::tests::test_v6_prefixes_unaligned_two_128
    #[test]
    fn test_v6_prefixes_unaligned_two_128() {
        let range = IpRange::new(
            Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 2),
        );
        let prefixes = range.prefixes();

        assert_eq!(prefixes.len(), 2);
        assert_eq!(prefixes[0].ip(), Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 1));
        assert_eq!(prefixes[0].mask(), 128);
        assert_eq!(prefixes[1].ip(), Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 2));
        assert_eq!(prefixes[1].mask(), 128);
    }

    // cargo test range::tests::test_v4_prefixes_small_aligned_block
    #[test]
    fn test_v4_prefixes_small_aligned_block() {
        let range = IpRange::new(Ipv4Addr::new(192, 168, 1, 0), Ipv4Addr::new(192, 168, 1, 3));
        let prefixes = range.prefixes();

        assert_eq!(prefixes.len(), 1);
        assert_eq!(prefixes[0].ip(), Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(prefixes[0].mask(), 30);
    }

    // cargo test range::tests::test_v6_prefixes_small_aligned_block
    #[test]
    fn test_v6_prefixes_small_aligned_block() {
        let range = IpRange::new(
            Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 0),
            Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 3),
        );
        let prefixes = range.prefixes();

        assert_eq!(prefixes.len(), 1);
        assert_eq!(prefixes[0].ip(), Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 0));
        assert_eq!(prefixes[0].mask(), 126);
    }

    // cargo test range::tests::test_v4_prefixes_entire_address_space
    #[test]
    fn test_v4_prefixes_entire_address_space() {
        let range = IpRange::new(Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(255, 255, 255, 255));
        let prefixes = range.prefixes();

        assert_eq!(prefixes.len(), 1);
        assert_eq!(prefixes[0].ip(), Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(prefixes[0].mask(), 0);
    }

    // cargo test range::tests::test_v6_prefixes_entire_address_space
    #[test]
    fn test_v6_prefixes_entire_address_space() {
        // Each Ipv6Addr::new() group is u16, so the maximum per group is 0xffff
        // (not 0xff — that's only 8 bits and produces 00ff:00ff:... not ffff:ffff:...).
        // The full IPv6 space starts at :: which has 128 trailing zeros, so the
        // entire range collapses into a single ::/0 prefix.
        let range = IpRange::new(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),
            Ipv6Addr::new(
                0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
            ),
        );
        let prefixes = range.prefixes();

        assert_eq!(prefixes.len(), 1);
        assert_eq!(prefixes[0].ip(), Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));
        assert_eq!(prefixes[0].mask(), 0);
    }

    // cargo test range::tests::test_v4_prefixes_invalid_range
    #[test]
    fn test_v4_prefixes_invalid_range() {
        let range = IpRange::new(
            Ipv4Addr::new(192, 168, 1, 255),
            Ipv4Addr::new(192, 168, 1, 0),
        );
        assert!(range.prefixes().is_empty());
    }

    // cargo test range::tests::test_v6_prefixes_invalid_range
    #[test]
    fn test_v6_prefixes_invalid_range() {
        let range = IpRange::new(
            Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 255),
            Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 0),
        );
        assert!(range.prefixes().is_empty());
    }

    // cargo test range::tests::test_v4_prefixes_unaligned_multi_prefixes
    #[test]
    fn test_v4_prefixes_unaligned_multi_prefixes() {
        let range = IpRange::new(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 254),
        );
        let prefixes = range.prefixes();

        assert_eq!(prefixes.len(), 14);
        assert_eq!(prefixes[0].ip(), Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(prefixes[0].mask(), 32);
        assert_eq!(prefixes[1].ip(), Ipv4Addr::new(192, 168, 1, 2));
        assert_eq!(prefixes[1].mask(), 31);
        assert_eq!(prefixes[2].ip(), Ipv4Addr::new(192, 168, 1, 4));
        assert_eq!(prefixes[2].mask(), 30);
        // pivot: largest block, where the staircase turns
        assert_eq!(prefixes[7].ip(), Ipv4Addr::new(192, 168, 1, 128));
        assert_eq!(prefixes[7].mask(), 26);
        // symmetric descent matches the ascent
        assert_eq!(prefixes[12].ip(), Ipv4Addr::new(192, 168, 1, 252));
        assert_eq!(prefixes[12].mask(), 31);
        assert_eq!(prefixes[13].ip(), Ipv4Addr::new(192, 168, 1, 254));
        assert_eq!(prefixes[13].mask(), 32);
    }

    // cargo test range::tests::test_v6_prefixes_unaligned_multi_prefixes
    #[test]
    fn test_v6_prefixes_unaligned_multi_prefixes() {
        // IPv6 mirror of test_v4_prefixes_unaligned_multi_prefixes.
        // The last u16 group spans 0x01..0xfe (same 1..254 as the V4 last octet),
        // so the staircase shape is identical — 14 prefixes ascending to a /122
        // pivot then descending symmetrically.  Masks are 128−h instead of 32−h.
        //
        // Ascent  (start gains alignment):
        //   1::01/128  1::02/127  1::04/126  1::08/125  1::10/124
        //   1::20/123  1::40/122
        // Pivot   (tries h=7 → 0x7f would overshoot 0xfe):
        //   1::80/122
        // Descent (mirror of ascent):
        //   1::c0/123  1::e0/124  1::f0/125  1::f8/126  1::fc/127  1::fe/128
        let range = IpRange::new(
            Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 0x01),
            Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 0xfe),
        );
        let prefixes = range.prefixes();

        assert_eq!(prefixes.len(), 14);
        // ascending staircase
        assert_eq!(prefixes[0].ip(), Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 0x01));
        assert_eq!(prefixes[0].mask(), 128);
        assert_eq!(prefixes[1].ip(), Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 0x02));
        assert_eq!(prefixes[1].mask(), 127);
        assert_eq!(prefixes[2].ip(), Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 0x04));
        assert_eq!(prefixes[2].mask(), 126);
        // pivot: largest fitting block
        assert_eq!(prefixes[7].ip(), Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 0x80));
        assert_eq!(prefixes[7].mask(), 122);
        // descending staircase mirrors the ascent
        assert_eq!(prefixes[12].ip(), Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 0xfc));
        assert_eq!(prefixes[12].mask(), 127);
        assert_eq!(prefixes[13].ip(), Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 0xfe));
        assert_eq!(prefixes[13].mask(), 128);
    }

    // --- prefix() ---

    // cargo test range::tests::test_v4_prefix_cidr_aligned
    #[test]
    fn test_v4_prefix_cidr_aligned() {
        // The happy path — power-of-two size + aligned start
        // 192.168.1.0..192.168.1.255 is exactly 192.168.1.0/24
        let range = IpRange::new(
            Ipv4Addr::new(192, 168, 1, 0),
            Ipv4Addr::new(192, 168, 1, 255),
        );
        let p = range.prefix().unwrap();
        assert_eq!(p.ip(), Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(p.mask(), 24);
    }

    // cargo test range::tests::test_v4_prefix_unaligned_span
    #[test]
    fn test_v4_prefix_unaligned_span() {
        // Rejects non-power-of-two sizes
        // size 254 is not a power of two → None
        let range = IpRange::new(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 254),
        );
        assert!(range.prefix().is_none());
    }

    // cargo test range::tests::test_v4_prefix_misaligned_start
    #[test]
    fn test_v4_prefix_misaligned_start() {
        // Rejects power-of-two size where start has too few trailing zeros
        // size 4 = 2^2 but .1 has 0 trailing zeros — misaligned
        let range = IpRange::new(Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(192, 168, 1, 4));
        assert!(range.prefix().is_none());
    }

    // cargo test range::tests::test_v4_prefix_single_ip
    #[test]
    fn test_v4_prefix_single_ip() {
        // h=0 edge case — any single IP is its own /32 or /128
        // A single-IP range is always a /32
        let range = IpRange::new(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 1));
        let p = range.prefix().unwrap();
        assert_eq!(p.ip(), Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(p.mask(), 32);
    }

    // cargo test range::tests::test_v4_prefix_entire_space
    #[test]
    fn test_v4_prefix_entire_space() {
        // IPv4: size=2^32 fits in u128 normally; IPv6: the wrapping_add=0 edge case
        // 0.0.0.0/0
        let range = IpRange::new(Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(255, 255, 255, 255));
        let p = range.prefix().unwrap();
        assert_eq!(p.ip(), Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(p.mask(), 0);
    }

    // cargo test range::tests::test_v4_prefix_invalid_range
    #[test]
    fn test_v4_prefix_invalid_range() {
        // Returns None before even checking the math
        let range = IpRange::new(
            Ipv4Addr::new(192, 168, 1, 255),
            Ipv4Addr::new(192, 168, 1, 0),
        );
        assert!(range.prefix().is_none());
    }

    // cargo test range::tests::test_v6_prefix_cidr_aligned
    #[test]
    fn test_v6_prefix_cidr_aligned() {
        // 1::/120 — 256 addresses, start aligned
        let range = IpRange::new(
            Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 0x00),
            Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 0xff),
        );
        let p = range.prefix().unwrap();
        assert_eq!(p.ip(), Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 0));
        assert_eq!(p.mask(), 120);
    }

    // cargo test range::tests::test_v6_prefix_entire_space
    #[test]
    fn test_v6_prefix_entire_space() {
        // ::/0
        let range = IpRange::new(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),
            Ipv6Addr::new(
                0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
            ),
        );
        let p = range.prefix().unwrap();
        assert_eq!(p.ip(), Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));
        assert_eq!(p.mask(), 0);
    }

    // cargo test range::tests::test_v6_prefix_single_ip
    #[test]
    fn test_v6_prefix_single_ip() {
        let range = IpRange::new(
            Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 1),
        );
        let p = range.prefix().unwrap();
        assert_eq!(p.ip(), Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 1));
        assert_eq!(p.mask(), 128);
    }

    // --- Display ---

    // cargo test range::tests::test_v4_display
    #[test]
    fn test_v4_display() {
        let range = IpRange::new(Ipv4Addr::new(1, 0, 0, 0), Ipv4Addr::new(1, 255, 255, 255));
        assert_eq!(format!("{}", range), "1.0.0.0..1.255.255.255");
    }

    // cargo test range::tests::test_v6_display
    #[test]
    fn test_v6_display() {
        let range = IpRange::new(
            Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 255),
        );
        assert_eq!(format!("{}", range), "1::1..1::ff");
    }
}
