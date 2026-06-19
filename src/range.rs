use crate::{interfaces::IpAddress, prefix::IpPrefix};

/// Error returned when parsing an [`IpRange`] from a string fails.
///
/// Produced by `"10.0.0.1..10.0.0.255".parse::<IpRange<Ipv4Addr>>()` on
/// failure. The separator between start and end is `..` — the same token
/// used by [`Display`](std::fmt::Display).
///
/// # Variants at a glance
///
/// | Input | Variant |
/// |---|---|
/// | `"10.0.0.1-10.0.0.255"` (wrong separator) | `MissingSeparator` |
/// | `"999.0.0.1..10.0.0.255"` | `InvalidStart` |
/// | `"10.0.0.1..999.0.0.255"` | `InvalidEnd` |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseRangeError {
    /// The input did not contain a `..` separator.
    MissingSeparator,
    /// The part before `..` is not a valid IP address for this address family.
    InvalidStart,
    /// The part after `..` is not a valid IP address for this address family.
    InvalidEnd,
}

impl std::fmt::Display for ParseRangeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingSeparator => f.write_str("missing '..' separator"),
            Self::InvalidStart => f.write_str("invalid start address"),
            Self::InvalidEnd => f.write_str("invalid end address"),
        }
    }
}

impl std::error::Error for ParseRangeError {}

/// An inclusive IP address range `[start, end]`.
///
/// A range is *valid* when `start <= end`. An invalid range (`start > end`)
/// can be constructed with [`IpRange::new`] but is treated as empty by all
/// operations — [`is_valid`](IpRange::is_valid) returns `false` and methods
/// such as [`contains`](IpRange::contains) and [`overlaps`](IpRange::overlaps)
/// always return `false`.
///
/// Both IPv4 and IPv6 are supported through the [`IpAddress`] bound.
///
/// # Examples
///
/// ```
/// use std::net::Ipv4Addr;
/// use ipnetx::range::IpRange;
///
/// let range = IpRange::new(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 255, 255, 255));
/// assert!(range.is_valid());
/// assert!(range.contains(Ipv4Addr::new(10, 1, 2, 3)));
/// assert!(!range.contains(Ipv4Addr::new(192, 168, 0, 1)));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpRange<A: IpAddress> {
    start: A,
    end: A,
}

impl<A: IpAddress> IpRange<A> {
    /// Creates a new range spanning `[start, end]` (both endpoints inclusive).
    ///
    /// Construction always succeeds. Use [`is_valid`](IpRange::is_valid) to
    /// check whether `start <= end` before performing operations on the range.
    pub fn new(start: A, end: A) -> Self {
        Self { start, end }
    }

    /// Returns the first address in the range.
    #[must_use]
    pub fn start(&self) -> A {
        self.start
    }

    /// Returns the last address in the range.
    #[must_use]
    pub fn end(&self) -> A {
        self.end
    }

    /// Returns `true` if `start <= end`.
    ///
    /// An invalid range is treated as empty by all operations.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.start <= self.end
    }

    /// Returns `true` if `ip` falls within `[start, end]` (inclusive).
    ///
    /// Always returns `false` for an invalid range.
    #[must_use]
    pub fn contains(&self, ip: A) -> bool {
        self.is_valid() && self.start <= ip && ip <= self.end
    }

    /// Returns `true` if both `start` and `end` are the unspecified address
    /// (`0.0.0.0` for IPv4, `::` for IPv6).
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.start.is_unspecified() && self.end.is_unspecified()
    }

    /// Returns `true` if this range and `other` share at least one address.
    ///
    /// Ranges that touch at a single endpoint (e.g. `[1..5]` and `[5..10]`)
    /// are considered overlapping — they share address `5`. Always returns
    /// `false` if either range is invalid.
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

    /// Decomposes this range into the minimal list of CIDR prefixes that
    /// exactly cover it.
    ///
    /// Prefixes are returned in ascending address order. An unaligned or
    /// non-power-of-two range may require multiple prefixes — for example,
    /// `1..254` decomposes into 14 prefixes. Returns an empty `Vec` for an
    /// invalid range.
    ///
    /// To check whether a range is already a single CIDR block, prefer
    /// [`prefix`](IpRange::prefix), which avoids allocating the full list.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::Ipv4Addr;
    /// use ipnetx::range::IpRange;
    ///
    /// let range = IpRange::new(Ipv4Addr::new(192, 168, 1, 0), Ipv4Addr::new(192, 168, 1, 255));
    /// let prefixes = range.prefixes();
    /// assert_eq!(prefixes.len(), 1);
    /// assert_eq!(prefixes[0].mask(), 24);
    /// ```
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
            // Alignment constraint: a CIDR block of 2^h addresses must start
            // on a 2^h boundary, so h <= trailing_zeros(start).
            let max_host_bits = start.trailing_zeros().min(bits);

            // Size constraint: the block must fit within [start, end], so
            // 2^h <= end - start + 1.  ilog2 gives floor(log2(size)), which
            // is the largest h satisfying 2^h <= size.
            // Special case: when span == u128::MAX the size is 2^128 (IPv6 full
            // space), which overflows u128; alignment is the only constraint.
            let span = end - start;
            let host_bits = if span == u128::MAX {
                max_host_bits
            } else {
                max_host_bits.min((span + 1).ilog2())
            };

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

impl<A: IpAddress> std::str::FromStr for IpRange<A> {
    type Err = ParseRangeError;

    /// Parses an inclusive IP range from its canonical string form
    /// `"<start>..<end>"`.
    ///
    /// The `..` separator matches what [`Display`](std::fmt::Display) produces,
    /// so a round-trip `range.to_string().parse()` always succeeds. The
    /// separator `..` is unambiguous even for IPv6 because no valid IPv6
    /// address contains consecutive dots.
    ///
    /// Construction always succeeds once both addresses parse — an inverted
    /// range (`start > end`) is representable and simply treated as empty by
    /// all operations. Use [`is_valid`](IpRange::is_valid) to check after
    /// parsing if needed.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::{Ipv4Addr, Ipv6Addr};
    /// use ipnetx::range::IpRange;
    ///
    /// // IPv4
    /// let r: IpRange<Ipv4Addr> = "10.0.0.1..10.0.0.255".parse().unwrap();
    /// assert_eq!(r.start(), Ipv4Addr::new(10, 0, 0, 1));
    /// assert_eq!(r.end(),   Ipv4Addr::new(10, 0, 0, 255));
    /// assert_eq!(r.to_string(), "10.0.0.1..10.0.0.255");
    ///
    /// // IPv6
    /// let r6: IpRange<Ipv6Addr> = "2001:db8::1..2001:db8::ff".parse().unwrap();
    /// assert!(r6.is_valid());
    ///
    /// // Errors
    /// assert!("10.0.0.1-10.0.0.255".parse::<IpRange<Ipv4Addr>>().is_err()); // wrong sep
    /// assert!("999.0.0.1..10.0.0.255".parse::<IpRange<Ipv4Addr>>().is_err()); // bad start
    /// assert!("10.0.0.1..999.0.0.255".parse::<IpRange<Ipv4Addr>>().is_err()); // bad end
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (start_str, end_str) = s
            .split_once("..")
            .ok_or(ParseRangeError::MissingSeparator)?;
        let start = A::parse_addr(start_str).ok_or(ParseRangeError::InvalidStart)?;
        let end = A::parse_addr(end_str).ok_or(ParseRangeError::InvalidEnd)?;
        Ok(IpRange::new(start, end))
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

    // --- FromStr ---

    // cargo test range::tests::test_v4_parse_valid
    #[test]
    fn test_v4_parse_valid() {
        let r: IpRange<Ipv4Addr> = "10.0.0.1..10.0.0.255".parse().unwrap();
        assert_eq!(r.start(), Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(r.end(), Ipv4Addr::new(10, 0, 0, 255));
        assert!(r.is_valid());
    }

    // cargo test range::tests::test_v4_parse_single_ip
    #[test]
    fn test_v4_parse_single_ip() {
        let r: IpRange<Ipv4Addr> = "10.0.0.1..10.0.0.1".parse().unwrap();
        assert_eq!(r.start(), r.end());
        assert!(r.is_valid());
    }

    // cargo test range::tests::test_v4_parse_inverted_is_representable
    #[test]
    fn test_v4_parse_inverted_is_representable() {
        // Parsing succeeds (construction always succeeds); is_valid() returns false.
        let r: IpRange<Ipv4Addr> = "10.0.0.255..10.0.0.1".parse().unwrap();
        assert!(!r.is_valid());
    }

    // cargo test range::tests::test_v4_parse_round_trip
    #[test]
    fn test_v4_parse_round_trip() {
        let s = "192.168.1.0..192.168.1.255";
        let r: IpRange<Ipv4Addr> = s.parse().unwrap();
        assert_eq!(r.to_string(), s);
    }

    // cargo test range::tests::test_v4_parse_missing_separator
    #[test]
    fn test_v4_parse_missing_separator() {
        // Common mistake: using '-' instead of '..'
        let err = "10.0.0.1-10.0.0.255".parse::<IpRange<Ipv4Addr>>().unwrap_err();
        assert_eq!(err, ParseRangeError::MissingSeparator);
    }

    // cargo test range::tests::test_v4_parse_invalid_start
    #[test]
    fn test_v4_parse_invalid_start() {
        let err = "999.0.0.1..10.0.0.255".parse::<IpRange<Ipv4Addr>>().unwrap_err();
        assert_eq!(err, ParseRangeError::InvalidStart);
    }

    // cargo test range::tests::test_v4_parse_invalid_end
    #[test]
    fn test_v4_parse_invalid_end() {
        let err = "10.0.0.1..999.0.0.255".parse::<IpRange<Ipv4Addr>>().unwrap_err();
        assert_eq!(err, ParseRangeError::InvalidEnd);
    }

    // cargo test range::tests::test_v4_parse_error_display
    #[test]
    fn test_v4_parse_error_display() {
        assert_eq!(ParseRangeError::MissingSeparator.to_string(), "missing '..' separator");
        assert_eq!(ParseRangeError::InvalidStart.to_string(), "invalid start address");
        assert_eq!(ParseRangeError::InvalidEnd.to_string(), "invalid end address");
    }

    // cargo test range::tests::test_v6_parse_valid
    #[test]
    fn test_v6_parse_valid() {
        let r: IpRange<Ipv6Addr> = "2001:db8::1..2001:db8::ff".parse().unwrap();
        assert_eq!(r.start(), Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1));
        assert_eq!(r.end(), Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0xff));
        assert!(r.is_valid());
    }

    // cargo test range::tests::test_v6_parse_compressed_address
    #[test]
    fn test_v6_parse_compressed_address() {
        // The '::'  compressed form must not confuse the '..' separator
        let r: IpRange<Ipv6Addr> = "::..::1".parse().unwrap();
        assert_eq!(r.start(), Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));
        assert_eq!(r.end(), Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
        assert!(r.is_valid());
    }

    // cargo test range::tests::test_v6_parse_round_trip
    #[test]
    fn test_v6_parse_round_trip() {
        let s = "2001:db8::1..2001:db8::ff";
        let r: IpRange<Ipv6Addr> = s.parse().unwrap();
        assert_eq!(r.to_string(), s);
    }

    // cargo test range::tests::test_v6_parse_rejects_v4_address
    #[test]
    fn test_v6_parse_rejects_v4_address() {
        let err = "10.0.0.1..10.0.0.255".parse::<IpRange<Ipv6Addr>>().unwrap_err();
        assert_eq!(err, ParseRangeError::InvalidStart);
    }
}
