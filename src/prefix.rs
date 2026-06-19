use crate::{interfaces::IpAddress, range::IpRange};

/// A CIDR prefix: an IP address paired with a prefix length.
///
/// A prefix represents all addresses that share the same top `mask` bits as
/// `ip`. The constructor [`IpPrefix::new`] does not zero host bits — use
/// [`masked`](IpPrefix::masked) to obtain canonical form where host bits are
/// all zero.
///
/// The prefix length must be in `[0, A::BITS]`: `[0, 32]` for IPv4 and
/// `[0, 128]` for IPv6.
///
/// # Examples
///
/// ```
/// use std::net::Ipv4Addr;
/// use ipnetx::prefix::IpPrefix;
///
/// let prefix = IpPrefix::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap();
/// assert!(prefix.contains(Ipv4Addr::new(192, 168, 1, 100)));
/// assert!(!prefix.contains(Ipv4Addr::new(192, 168, 2, 0)));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpPrefix<A: IpAddress> {
    ip: A,
    mask: u8,
}

/// Error returned by [`IpPrefix::new`] when the mask exceeds the address
/// bit width (`> 32` for IPv4, `> 128` for IPv6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidPrefixLen;

/// Error returned when parsing an [`IpPrefix`] from a string fails.
///
/// Produced by `"192.168.1.0/24".parse::<IpPrefix<Ipv4Addr>>()` on failure.
///
/// # Variants at a glance
///
/// | Input | Variant |
/// |---|---|
/// | `"192.168.1.0"` (no slash) | `MissingSeparator` |
/// | `"999.0.0.0/24"` | `InvalidAddress` |
/// | `"192.168.1.0/abc"` | `InvalidMask` |
/// | `"192.168.1.0/33"` (> 32 for IPv4) | `InvalidMask` |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParsePrefixError {
    /// The input did not contain a `/` separator.
    MissingSeparator,
    /// The part before `/` is not a valid IP address for this address family.
    InvalidAddress,
    /// The part after `/` is not a valid decimal integer, or exceeds the
    /// address bit width (`> 32` for IPv4, `> 128` for IPv6).
    InvalidMask,
}

impl std::fmt::Display for ParsePrefixError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingSeparator => f.write_str("missing '/' separator"),
            Self::InvalidAddress => f.write_str("invalid IP address"),
            Self::InvalidMask => f.write_str("invalid prefix length"),
        }
    }
}

impl std::error::Error for ParsePrefixError {}

impl<A: IpAddress> IpPrefix<A> {
    /// Creates a new prefix from an IP address and a prefix length.
    ///
    /// Returns [`Err(InvalidPrefixLen)`](InvalidPrefixLen) if `mask > A::BITS`.
    /// Host bits in `ip` are preserved; use [`masked`](IpPrefix::masked) to
    /// zero them if canonical form is required.
    pub fn new(ip: A, mask: u8) -> Result<Self, InvalidPrefixLen> {
        if mask > A::BITS {
            return Err(InvalidPrefixLen);
        }
        Ok(Self { ip, mask })
    }

    /// Returns the IP address portion of the prefix.
    ///
    /// This may contain host bits if the prefix was not constructed with a
    /// network address. Use [`masked`](IpPrefix::masked) to obtain a version
    /// with host bits zeroed.
    #[must_use]
    pub fn ip(&self) -> A {
        self.ip
    }

    /// Returns the prefix length (number of network bits).
    ///
    /// Always in the range `[0, A::BITS]`.
    #[must_use]
    pub fn mask(&self) -> u8 {
        self.mask
    }

    /// Returns `true` if `ip` falls within this prefix.
    ///
    /// Two addresses share the same network when their top `mask` bits are
    /// identical. Host bits in this prefix's IP are masked out before
    /// comparison, so `192.168.1.100/24` and `192.168.1.0/24` contain the
    /// same set of addresses.
    #[must_use]
    pub fn contains(&self, ip: A) -> bool {
        // Two addresses share the same /mask prefix iff their top `mask` bits
        // are identical — mask the host bits of both and compare.
        let network = self.network_mask();
        self.ip.to_u128() & network == ip.to_u128() & network
    }

    /// Converts this prefix to the equivalent inclusive address range.
    ///
    /// The start of the range is the network address (host bits zeroed) and
    /// the end is the broadcast address (host bits set to all ones). Host bits
    /// in this prefix's IP are masked out before the conversion.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::Ipv4Addr;
    /// use ipnetx::prefix::IpPrefix;
    ///
    /// let prefix = IpPrefix::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap();
    /// let range = prefix.to_range();
    /// assert_eq!(range.start(), Ipv4Addr::new(192, 168, 1, 0));
    /// assert_eq!(range.end(), Ipv4Addr::new(192, 168, 1, 255));
    /// ```
    #[must_use]
    pub fn to_range(&self) -> IpRange<A> {
        let ip = self.ip.to_u128();
        let addr_max: u128 = u128::MAX >> (128 - A::BITS as u32);
        let network = self.network_mask();
        let host = addr_max & !network;
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
    #[must_use]
    pub fn masked(&self) -> Self {
        Self {
            ip: A::from_u128(self.ip.to_u128() & self.network_mask()),
            mask: self.mask,
        }
    }

    /// Returns `true` if this prefix covers exactly one IP address
    /// (i.e. `/32` for IPv4 or `/128` for IPv6).
    #[must_use]
    pub fn is_single_ip(&self) -> bool {
        self.mask == A::BITS
    }

    /// Returns `true` if this prefix shares at least one address with `other`.
    ///
    /// Two CIDR prefixes either nest (one contains the other) or are disjoint —
    /// partial overlap as seen with arbitrary ranges is not possible. This method
    /// delegates to [`IpRange::overlaps`] via [`IpPrefix::to_range`], so the host bits of
    /// each prefix's IP are automatically masked out before comparison.
    #[must_use]
    pub fn overlaps(&self, other: &IpPrefix<A>) -> bool {
        self.to_range().overlaps(&other.to_range())
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


}

impl<A: IpAddress> std::fmt::Display for IpPrefix<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.ip, self.mask)
    }
}

impl<A: IpAddress> std::str::FromStr for IpPrefix<A> {
    type Err = ParsePrefixError;

    /// Parses a CIDR prefix from its canonical string form `"<addr>/<len>"`.
    ///
    /// The address is parsed by the address family (`Ipv4Addr` or `Ipv6Addr`)
    /// determined by the turbofish or inference context. The prefix length must
    /// be a decimal integer in `[0, A::BITS]`.
    ///
    /// Host bits in the address are preserved, matching the behaviour of
    /// [`IpPrefix::new`]. Use [`.masked()`](IpPrefix::masked) on the result to
    /// zero them if canonical form is needed.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::{Ipv4Addr, Ipv6Addr};
    /// use ipnetx::prefix::IpPrefix;
    ///
    /// // IPv4
    /// let p: IpPrefix<Ipv4Addr> = "192.168.1.0/24".parse().unwrap();
    /// assert_eq!(p.ip(),   Ipv4Addr::new(192, 168, 1, 0));
    /// assert_eq!(p.mask(), 24);
    /// assert_eq!(p.to_string(), "192.168.1.0/24");
    ///
    /// // IPv6
    /// let p6: IpPrefix<Ipv6Addr> = "2001:db8::/32".parse().unwrap();
    /// assert_eq!(p6.mask(), 32);
    ///
    /// // Errors
    /// assert!("192.168.1.0".parse::<IpPrefix<Ipv4Addr>>().is_err());   // no slash
    /// assert!("999.0.0.0/24".parse::<IpPrefix<Ipv4Addr>>().is_err());  // bad address
    /// assert!("192.168.1.0/33".parse::<IpPrefix<Ipv4Addr>>().is_err()); // mask > 32
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr_str, mask_str) = s
            .split_once('/')
            .ok_or(ParsePrefixError::MissingSeparator)?;
        let ip = A::parse_addr(addr_str).ok_or(ParsePrefixError::InvalidAddress)?;
        let mask: u8 = mask_str
            .parse()
            .map_err(|_| ParsePrefixError::InvalidMask)?;
        IpPrefix::new(ip, mask).map_err(|_| ParsePrefixError::InvalidMask)
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

    // --- is_single_ip() ---

    // cargo test prefix::tests::test_v4_is_single_ip_slash32
    #[test]
    fn test_v4_is_single_ip_slash32() {
        let prefix = IpPrefix::new(Ipv4Addr::new(10, 0, 0, 1), 32).unwrap();
        assert!(prefix.is_single_ip());
    }

    // cargo test prefix::tests::test_v4_is_single_ip_not_slash32
    #[test]
    fn test_v4_is_single_ip_not_slash32() {
        let prefix = IpPrefix::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap();
        assert!(!prefix.is_single_ip());
    }

    // cargo test prefix::tests::test_v6_is_single_ip_slash128
    #[test]
    fn test_v6_is_single_ip_slash128() {
        let prefix = IpPrefix::new(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1), 128).unwrap();
        assert!(prefix.is_single_ip());
    }

    // cargo test prefix::tests::test_v6_is_single_ip_not_slash128
    #[test]
    fn test_v6_is_single_ip_not_slash128() {
        let prefix = IpPrefix::new(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0), 64).unwrap();
        assert!(!prefix.is_single_ip());
    }

    // --- overlaps() ---

    // cargo test prefix::tests::test_v4_overlaps_same_prefix
    #[test]
    fn test_v4_overlaps_same_prefix() {
        // A prefix always overlaps itself
        let p = IpPrefix::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap();
        assert!(p.overlaps(&p));
    }

    // cargo test prefix::tests::test_v4_overlaps_sub_prefix
    #[test]
    fn test_v4_overlaps_sub_prefix() {
        // 192.168.1.0/24 contains 192.168.1.0/25 — they overlap
        let parent = IpPrefix::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap();
        let child = IpPrefix::new(Ipv4Addr::new(192, 168, 1, 0), 25).unwrap();
        assert!(parent.overlaps(&child));
        assert!(child.overlaps(&parent)); // symmetric
    }

    // cargo test prefix::tests::test_v4_overlaps_disjoint
    #[test]
    fn test_v4_overlaps_disjoint() {
        // 10.0.0.0/8 and 192.168.0.0/16 share no addresses
        let a = IpPrefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap();
        let b = IpPrefix::new(Ipv4Addr::new(192, 168, 0, 0), 16).unwrap();
        assert!(!a.overlaps(&b));
        assert!(!b.overlaps(&a)); // symmetric
    }

    // cargo test prefix::tests::test_v4_overlaps_adjacent
    #[test]
    fn test_v4_overlaps_adjacent() {
        // 192.168.1.0/25 (0–127) and 192.168.1.128/25 (128–255) — adjacent, not overlapping
        let lo = IpPrefix::new(Ipv4Addr::new(192, 168, 1, 0), 25).unwrap();
        let hi = IpPrefix::new(Ipv4Addr::new(192, 168, 1, 128), 25).unwrap();
        assert!(!lo.overlaps(&hi));
    }

    // cargo test prefix::tests::test_v4_overlaps_unmasked_ip
    #[test]
    fn test_v4_overlaps_unmasked_ip() {
        // Host bits in the IP are masked out before comparison:
        // 192.168.1.100/24 is treated as 192.168.1.0/24 and overlaps 192.168.1.0/25
        let p1 = IpPrefix::new(Ipv4Addr::new(192, 168, 1, 100), 24).unwrap();
        let p2 = IpPrefix::new(Ipv4Addr::new(192, 168, 1, 0), 25).unwrap();
        assert!(p1.overlaps(&p2));
    }

    // cargo test prefix::tests::test_v6_overlaps_sub_prefix
    #[test]
    fn test_v6_overlaps_sub_prefix() {
        // 2001:db8::/32 contains 2001:db8::/64
        let parent = IpPrefix::new(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0), 32).unwrap();
        let child = IpPrefix::new(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0), 64).unwrap();
        assert!(parent.overlaps(&child));
        assert!(child.overlaps(&parent)); // symmetric
    }

    // cargo test prefix::tests::test_v6_overlaps_disjoint
    #[test]
    fn test_v6_overlaps_disjoint() {
        let a = IpPrefix::new(Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0), 32).unwrap();
        let b = IpPrefix::new(Ipv6Addr::new(0x2002, 0, 0, 0, 0, 0, 0, 0), 32).unwrap();
        assert!(!a.overlaps(&b));
    }

    // --- FromStr ---

    // cargo test prefix::tests::test_v4_parse_valid
    #[test]
    fn test_v4_parse_valid() {
        let p: IpPrefix<Ipv4Addr> = "192.168.1.0/24".parse().unwrap();
        assert_eq!(p.ip(), Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(p.mask(), 24);
    }

    // cargo test prefix::tests::test_v4_parse_slash0
    #[test]
    fn test_v4_parse_slash0() {
        let p: IpPrefix<Ipv4Addr> = "0.0.0.0/0".parse().unwrap();
        assert_eq!(p.ip(), Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(p.mask(), 0);
    }

    // cargo test prefix::tests::test_v4_parse_slash32
    #[test]
    fn test_v4_parse_slash32() {
        let p: IpPrefix<Ipv4Addr> = "10.0.0.1/32".parse().unwrap();
        assert_eq!(p.ip(), Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(p.mask(), 32);
    }

    // cargo test prefix::tests::test_v4_parse_preserves_host_bits
    #[test]
    fn test_v4_parse_preserves_host_bits() {
        // FromStr (like new()) preserves host bits — use .masked() for canonical form
        let p: IpPrefix<Ipv4Addr> = "192.168.1.100/24".parse().unwrap();
        assert_eq!(p.ip(), Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(p.mask(), 24);
    }

    // cargo test prefix::tests::test_v4_parse_round_trip
    #[test]
    fn test_v4_parse_round_trip() {
        let s = "10.0.0.0/8";
        let p: IpPrefix<Ipv4Addr> = s.parse().unwrap();
        assert_eq!(p.to_string(), s);
    }

    // cargo test prefix::tests::test_v4_parse_missing_separator
    #[test]
    fn test_v4_parse_missing_separator() {
        let err = "192.168.1.0".parse::<IpPrefix<Ipv4Addr>>().unwrap_err();
        assert_eq!(err, ParsePrefixError::MissingSeparator);
    }

    // cargo test prefix::tests::test_v4_parse_invalid_address
    #[test]
    fn test_v4_parse_invalid_address() {
        let err = "999.168.1.0/24".parse::<IpPrefix<Ipv4Addr>>().unwrap_err();
        assert_eq!(err, ParsePrefixError::InvalidAddress);
    }

    // cargo test prefix::tests::test_v4_parse_mask_not_a_number
    #[test]
    fn test_v4_parse_mask_not_a_number() {
        let err = "192.168.1.0/abc".parse::<IpPrefix<Ipv4Addr>>().unwrap_err();
        assert_eq!(err, ParsePrefixError::InvalidMask);
    }

    // cargo test prefix::tests::test_v4_parse_mask_out_of_range
    #[test]
    fn test_v4_parse_mask_out_of_range() {
        // mask > 32 is rejected even though 33 parses as u8 fine
        let err = "192.168.1.0/33".parse::<IpPrefix<Ipv4Addr>>().unwrap_err();
        assert_eq!(err, ParsePrefixError::InvalidMask);
    }

    // cargo test prefix::tests::test_v4_parse_error_display
    #[test]
    fn test_v4_parse_error_display() {
        assert_eq!(ParsePrefixError::MissingSeparator.to_string(), "missing '/' separator");
        assert_eq!(ParsePrefixError::InvalidAddress.to_string(), "invalid IP address");
        assert_eq!(ParsePrefixError::InvalidMask.to_string(), "invalid prefix length");
    }

    // cargo test prefix::tests::test_v6_parse_valid
    #[test]
    fn test_v6_parse_valid() {
        let p: IpPrefix<Ipv6Addr> = "2001:db8::/32".parse().unwrap();
        assert_eq!(p.ip(), Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0));
        assert_eq!(p.mask(), 32);
    }

    // cargo test prefix::tests::test_v6_parse_slash128
    #[test]
    fn test_v6_parse_slash128() {
        let p: IpPrefix<Ipv6Addr> = "::1/128".parse().unwrap();
        assert_eq!(p.ip(), Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
        assert_eq!(p.mask(), 128);
    }

    // cargo test prefix::tests::test_v6_parse_slash0
    #[test]
    fn test_v6_parse_slash0() {
        let p: IpPrefix<Ipv6Addr> = "::/0".parse().unwrap();
        assert_eq!(p.ip(), Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));
        assert_eq!(p.mask(), 0);
    }

    // cargo test prefix::tests::test_v6_parse_round_trip
    #[test]
    fn test_v6_parse_round_trip() {
        let s = "2001:db8::/32";
        let p: IpPrefix<Ipv6Addr> = s.parse().unwrap();
        assert_eq!(p.to_string(), s);
    }

    // cargo test prefix::tests::test_v6_parse_mask_out_of_range
    #[test]
    fn test_v6_parse_mask_out_of_range() {
        let err = "::/129".parse::<IpPrefix<Ipv6Addr>>().unwrap_err();
        assert_eq!(err, ParsePrefixError::InvalidMask);
    }

    // cargo test prefix::tests::test_v6_parse_rejects_v4_address
    #[test]
    fn test_v6_parse_rejects_v4_address() {
        // IPv4 notation is not valid for IpPrefix<Ipv6Addr>
        let err = "192.168.1.0/24".parse::<IpPrefix<Ipv6Addr>>().unwrap_err();
        assert_eq!(err, ParsePrefixError::InvalidAddress);
    }
}
