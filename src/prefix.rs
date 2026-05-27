use crate::{interfaces::IpAddress, range::IpRange};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpPrefix<A: IpAddress> {
    ip: A,
    mask: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidPrefixLen;

impl<A: IpAddress> IpPrefix<A> {
    /// Returns `None` if `mask` exceeds the address bit width
    /// (> 32 for IPv4, > 128 for IPv6).
    pub fn new(ip: A, mask: u8) -> Result<Self, InvalidPrefixLen> {
        if mask > A::BITS {
            return Err(InvalidPrefixLen);
        }
        Ok(Self { ip, mask })
    }

    pub fn ip(&self) -> A {
        self.ip
    }

    pub fn mask(&self) -> u8 {
        self.mask
    }

    pub fn contains(&self, ip: A) -> bool {
        // Two addresses share the same /mask prefix iff their top `mask` bits
        // are identical — mask the host bits of both and compare.
        let network = self.network_mask();
        self.ip.to_u128() & network == ip.to_u128() & network
    }

    pub fn to_range(&self) -> IpRange<A> {
        let ip = self.ip.to_u128();
        let network = self.network_mask();
        let host = self.host_mask();
        // start: zero out the host bits (network address)
        // end:   set all the host bits (broadcast / last address)
        IpRange::new(A::from_u128(ip & network), A::from_u128(ip | host))
    }

    /// Returns a new prefix with the host bits of the address zeroed.
    ///
    /// The prefix length is unchanged; only the IP portion is affected.
    ///
    /// # Examples
    /// - `192.168.1.100/24` → `192.168.1.0/24`
    /// - `192.168.1.0/24`   → `192.168.1.0/24`  (already masked; no change)
    /// - `10.0.0.1/32`      → `10.0.0.1/32`     (/32 has no host bits to zero)
    pub fn masked(&self) -> Self {
        Self {
            ip: A::from_u128(self.ip.to_u128() & self.network_mask()),
            mask: self.mask,
        }
    }

    // ── helpers ────────────────────────────────────────────────────────────

    /// Bit mask covering the network portion (top `mask` bits within the
    /// address width). e.g. /24 on IPv4 → 0xFFFFFF00.
    fn network_mask(&self) -> u128 {
        // addr_max isolates the relevant bits for this address family:
        //   IPv4 → 0x00000000_...._FFFFFFFF
        //   IPv6 → 0xFFFFFFFF_...._FFFFFFFF
        let addr_max: u128 = u128::MAX >> (128 - A::BITS as u32);
        let shift = A::BITS - self.mask;
        // shift == 128 for an IPv6 /0 prefix; shifting u128 by its full width
        // overflows, so checked_shl returns None and we fall back to 0 (correct:
        // a /0 has no network bits, so the network mask is all zeros).
        let shifted = u128::MAX.checked_shl(shift as u32).unwrap_or(0);
        addr_max & shifted
    }

    /// Bit mask covering the host portion (bottom `BITS - mask` bits).
    /// e.g. /24 on IPv4 → 0x000000FF.
    fn host_mask(&self) -> u128 {
        let addr_max: u128 = u128::MAX >> (128 - A::BITS as u32);
        addr_max & !self.network_mask()
    }
}

impl<A: IpAddress> std::fmt::Display for IpPrefix<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.ip, self.mask)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // --- Construction ---

    // cargo test prefix::tests::test_v4_prefix_new
    #[test]
    fn test_v4_prefix_new() {
        let prefix = IpPrefix::<Ipv4Addr>::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap();
        assert_eq!(prefix.ip(), Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(prefix.mask(), 24);
    }

    // cargo test prefix::tests::test_v6_prefix_new
    #[test]
    fn test_v6_prefix_new() {
        let prefix = IpPrefix::<Ipv6Addr>::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), 64).unwrap();
        assert_eq!(prefix.ip(), Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
        assert_eq!(prefix.mask(), 64);
    }

    // cargo test prefix::tests::test_v4_prefix_new_invalid_mask
    #[test]
    fn test_v4_prefix_new_invalid_mask() {
        assert!(IpPrefix::<Ipv4Addr>::new(Ipv4Addr::new(192, 168, 1, 0), 33).is_err());
    }

    // cargo test prefix::tests::test_v6_prefix_new_invalid_mask
    #[test]
    fn test_v6_prefix_new_invalid_mask() {
        assert!(IpPrefix::<Ipv6Addr>::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), 129).is_err());
    }

    // --- Contains ---

    // cargo test prefix::tests::test_ip_v4_prefix_contains
    #[test]
    fn test_ip_v4_prefix_contains() {
        let prefix = IpPrefix::<Ipv4Addr>::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap();
        assert!(prefix.contains(Ipv4Addr::new(192, 168, 1, 0))); // network address
        assert!(prefix.contains(Ipv4Addr::new(192, 168, 1, 255))); // last address
        assert!(!prefix.contains(Ipv4Addr::new(192, 167, 255, 255))); // just before
        assert!(!prefix.contains(Ipv4Addr::new(192, 168, 2, 0))); // just after
    }

    // cargo test prefix::tests::test_ip_v4_prefix_not_contains
    #[test]
    fn test_ip_v4_prefix_not_contains() {
        let prefix = IpPrefix::<Ipv4Addr>::new(Ipv4Addr::new(192, 168, 1, 0), 32).unwrap();
        assert!(prefix.contains(Ipv4Addr::new(192, 168, 1, 0))); // the only IP in /32
        assert!(!prefix.contains(Ipv4Addr::new(192, 168, 1, 1))); // immediately outside
    }

    // cargo test prefix::tests::test_ip_v6_prefix_contains
    #[test]
    fn test_ip_v6_prefix_contains() {
        // 2001:db8::/64 — the RFC 3849 documentation prefix
        let prefix =
            IpPrefix::<Ipv6Addr>::new(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0), 64).unwrap();
        assert!(prefix.contains(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1))); // first host
        assert!(prefix.contains(Ipv6Addr::new(
            0x2001, 0x0db8, 0, 0, 0xffff, 0xffff, 0xffff, 0xffff
        ))); // last
        assert!(!prefix.contains(Ipv6Addr::new(0x2001, 0x0db9, 0, 0, 0, 0, 0, 0))); // different /64
    }

    // cargo test prefix::tests::test_ip_v6_prefix_not_contains
    #[test]
    fn test_ip_v6_prefix_not_contains() {
        let prefix = IpPrefix::<Ipv6Addr>::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), 64).unwrap();
        assert!(!prefix.contains(Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 2)));
    }

    // --- To Range ---

    // cargo test prefix::tests::test_ip_v4_prefix_to_range
    #[test]
    fn test_ip_v4_prefix_to_range() {
        let prefix = IpPrefix::<Ipv4Addr>::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap();
        let range = prefix.to_range();

        assert_eq!(range.start(), Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(range.end(), Ipv4Addr::new(192, 168, 1, 255));
    }

    // cargo test prefix::tests::test_ip_v4_prefix_to_range_entire_addr_space
    #[test]
    fn test_ip_v4_prefix_to_range_entire_addr_space() {
        let prefix = IpPrefix::<Ipv4Addr>::new(Ipv4Addr::new(0, 0, 0, 0), 0).unwrap();
        let range = prefix.to_range();

        assert_eq!(range.start(), Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(range.end(), Ipv4Addr::new(255, 255, 255, 255));
    }

    // cargo test prefix::tests::test_ip_v4_prefix_to_range_single_host
    #[test]
    fn test_ip_v4_prefix_to_range_single_host() {
        let prefix = IpPrefix::<Ipv4Addr>::new(Ipv4Addr::new(192, 168, 1, 0), 32).unwrap();
        let range = prefix.to_range();

        assert_eq!(range.start(), Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(range.end(), Ipv4Addr::new(192, 168, 1, 0));
    }

    // cargo test prefix::tests::test_ip_v6_prefix_to_range
    #[test]
    fn test_ip_v6_prefix_to_range() {
        // /120 means 8 free host bits, so the last u16 group spans 0x00..0xff.
        // The base must be the network address (host bits already zero): ::
        // Compare to IPv4: 192.168.1.0/24, not 192.168.1.1/24.
        let prefix = IpPrefix::<Ipv6Addr>::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), 120).unwrap();
        let range = prefix.to_range();

        assert_eq!(range.start(), Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0x00)); // ::
        assert_eq!(range.end(), Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0xff)); // ::ff
    }

    // cargo test prefix::tests::test_ip_v6_prefix_to_range_single_host
    #[test]
    fn test_ip_v6_prefix_to_range_single_host() {
        let prefix =
            IpPrefix::<Ipv6Addr>::new(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1), 128)
                .unwrap();
        let range = prefix.to_range();

        assert_eq!(
            range.start(),
            Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)
        );
        assert_eq!(range.end(), Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1));
    }

    // cargo test prefix::tests::test_ip_v4_prefix_display
    #[test]
    fn test_ip_v4_prefix_display() {
        let prefix = IpPrefix::<Ipv4Addr>::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap();
        assert_eq!(format!("{}", prefix), "192.168.1.0/24");
    }

    // cargo test prefix::tests::test_ip_v6_prefix_display
    #[test]
    fn test_ip_v6_prefix_display() {
        let prefix = IpPrefix::<Ipv6Addr>::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), 120).unwrap();
        assert_eq!(format!("{}", prefix), "::/120");
    }

    // --- masked() ---

    // cargo test prefix::tests::test_v4_masked_with_host_bits
    #[test]
    fn test_v4_masked_with_host_bits() {
        // 192.168.1.100/24 → 192.168.1.0/24
        let prefix = IpPrefix::new(Ipv4Addr::new(192, 168, 1, 100), 24).unwrap();
        let masked = prefix.masked();
        assert_eq!(masked.ip(), Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(masked.mask(), 24);
    }

    // cargo test prefix::tests::test_v4_masked_already_clean
    #[test]
    fn test_v4_masked_already_clean() {
        // Already network-aligned — masked() is a no-op
        let prefix = IpPrefix::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap();
        let masked = prefix.masked();
        assert_eq!(masked.ip(), Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(masked.mask(), 24);
    }

    // cargo test prefix::tests::test_v4_masked_slash32
    #[test]
    fn test_v4_masked_slash32() {
        // /32 has no host bits — masked() is always a no-op
        let prefix = IpPrefix::new(Ipv4Addr::new(10, 0, 0, 1), 32).unwrap();
        let masked = prefix.masked();
        assert_eq!(masked.ip(), Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(masked.mask(), 32);
    }

    // cargo test prefix::tests::test_v4_masked_slash0
    #[test]
    fn test_v4_masked_slash0() {
        // /0 — all bits are host bits, so any IP collapses to 0.0.0.0
        let prefix = IpPrefix::new(Ipv4Addr::new(10, 20, 30, 40), 0).unwrap();
        let masked = prefix.masked();
        assert_eq!(masked.ip(), Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(masked.mask(), 0);
    }

    // cargo test prefix::tests::test_v6_masked_with_host_bits
    #[test]
    fn test_v6_masked_with_host_bits() {
        // 2001:db8::ff/120 → 2001:db8::/120
        let prefix =
            IpPrefix::new(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0xff), 120).unwrap();
        let masked = prefix.masked();
        assert_eq!(masked.ip(), Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0));
        assert_eq!(masked.mask(), 120);
    }

    // cargo test prefix::tests::test_v6_masked_slash0
    #[test]
    fn test_v6_masked_slash0() {
        // /0 — any IPv6 address collapses to ::
        let prefix = IpPrefix::new(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1), 0).unwrap();
        let masked = prefix.masked();
        assert_eq!(masked.ip(), Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));
        assert_eq!(masked.mask(), 0);
    }
}
