//! A prefix paired with a window of acceptable prefix lengths.
//!
//! [`PrefixMatch`] answers one question about a candidate prefix: *is it inside
//! this prefix, and is its length within this window?* That is the shape of a
//! rule such as "any block inside `10.0.0.0/8` that is a `/16` through a `/24`"
//! in an access list, a filter, or an address-plan check.
//!
//! It is deliberately **not** address-space algebra — see
//! [`IpSet`](crate::ipset::IpSet) for that. The difference matters: an
//! `IpSet` holding `10.0.0.0/25` and `10.0.0.128/25` merges them into one
//! range and therefore "covers" `10.0.0.0/24`, whereas no `PrefixMatch` for
//! either /25 covers or matches the /24.
//!
//! # Bounds are explicit numbers
//!
//! The window is given as plain `min_len` / `max_len` prefix lengths.
//! [`exact`](PrefixMatch::exact) and [`or_longer`](PrefixMatch::or_longer)
//! are shorthands for two common windows, defined only in those numeric terms.
//! If you are translating from a configuration syntax, map it onto these
//! numbers; this module assigns no other meaning to them.
//!
//! # Covers vs matches
//!
//! For a candidate prefix `C` of length `L` and an entry `(P, min_len, max_len)`
//! where `P` has length `p`:
//!
//! * [`covers`](PrefixMatch::covers): `L ≥ p` and the first `p` bits of `C`
//!   equal those of `P` — i.e. `C` lies inside `P`. The window is ignored.
//! * [`matches`](PrefixMatch::matches): `covers` **and**
//!   `min_len ≤ L ≤ max_len`.
//!
//! Matching implies covering, but covering does not imply matching. Host bits
//! of `C` are ignored. `matches` tests containment and length only; any other
//! condition attached to a prefix is the caller's to check.
//!
//! # Examples
//!
//! ```
//! use std::net::Ipv4Addr;
//! use ipnetx::{prefix::IpPrefix, prefix_match::PrefixMatch};
//!
//! let ten = IpPrefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap();
//! // Anything inside 10.0.0.0/8 whose length is between /16 and /24.
//! let entry = PrefixMatch::new(ten, 16, 24).unwrap();
//!
//! let block = |a, b, len| IpPrefix::new(Ipv4Addr::new(10, a, b, 0), len).unwrap();
//! assert!(entry.matches(block(1, 0, 16)));
//! assert!(entry.matches(block(1, 2, 24)));
//! assert!(!entry.matches(block(1, 2, 25)));   // longer than the window
//! assert!(entry.covers(block(1, 2, 25)));     // …but still inside 10/8
//!
//! let outside = IpPrefix::new(Ipv4Addr::new(11, 0, 0, 0), 16).unwrap();
//! assert!(!entry.covers(outside));
//! ```

use crate::{interfaces::IpAddress, prefix::IpPrefix};

/// Why a `(prefix, min_len, max_len)` combination was rejected by
/// [`PrefixMatch::new`].
///
/// When several rules are violated, the first in this order is reported:
/// [`MaxAboveAddrBits`](Self::MaxAboveAddrBits), then
/// [`MinAboveMax`](Self::MinAboveMax), then
/// [`MinBelowPrefixLen`](Self::MinBelowPrefixLen).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InvalidLengthRange {
    /// `max_len` exceeds the address width (32 for IPv4, 128 for IPv6).
    MaxAboveAddrBits,
    /// `min_len` is greater than `max_len`.
    MinAboveMax,
    /// `min_len` is shorter than the entry's own prefix length.
    ///
    /// This is an API rule, not a semantic necessity: such an entry could
    /// still match (lengths below the prefix length are simply unreachable,
    /// since a prefix must be at least as long as the one that covers it).
    /// It is rejected so that [`PrefixMatch::min_len`] always means what it
    /// says.
    MinBelowPrefixLen,
}

impl std::fmt::Display for InvalidLengthRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MaxAboveAddrBits => {
                f.write_str("max_len exceeds the address width of the address family")
            }
            Self::MinAboveMax => f.write_str("min_len is greater than max_len"),
            Self::MinBelowPrefixLen => {
                f.write_str("min_len is shorter than the entry's prefix length")
            }
        }
    }
}

impl std::error::Error for InvalidLengthRange {}

/// A prefix together with an inclusive window of acceptable prefix lengths.
///
/// Invariant: `prefix.mask() ≤ min_len ≤ max_len ≤ A::BITS`, and the stored
/// prefix has its host bits zeroed. Two entries built from the same network
/// and window therefore compare and hash equal regardless of host bits in
/// the input.
///
/// See the [module documentation](self) for the meaning of
/// [`covers`](Self::covers) and [`matches`](Self::matches).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PrefixMatch<A: IpAddress> {
    prefix: IpPrefix<A>,
    min_len: u8,
    max_len: u8,
}

impl<A: IpAddress> PrefixMatch<A> {
    /// Creates an entry accepting prefixes inside `prefix` whose length is in
    /// `min_len..=max_len`.
    ///
    /// Host bits in `prefix` are zeroed.
    ///
    /// # Errors
    ///
    /// Returns an [`InvalidLengthRange`] if `max_len > A::BITS`,
    /// `min_len > max_len`, or `min_len < prefix.mask()` — checked in that
    /// order.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::Ipv4Addr;
    /// use ipnetx::{prefix::IpPrefix, prefix_match::{InvalidLengthRange, PrefixMatch}};
    ///
    /// let p = IpPrefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap();
    /// assert!(PrefixMatch::new(p, 8, 32).is_ok());
    /// assert_eq!(PrefixMatch::new(p, 8, 33), Err(InvalidLengthRange::MaxAboveAddrBits));
    /// assert_eq!(PrefixMatch::new(p, 24, 16), Err(InvalidLengthRange::MinAboveMax));
    /// assert_eq!(PrefixMatch::new(p, 4, 24), Err(InvalidLengthRange::MinBelowPrefixLen));
    /// ```
    pub fn new(prefix: IpPrefix<A>, min_len: u8, max_len: u8) -> Result<Self, InvalidLengthRange> {
        if max_len > A::BITS {
            return Err(InvalidLengthRange::MaxAboveAddrBits);
        }
        if min_len > max_len {
            return Err(InvalidLengthRange::MinAboveMax);
        }
        if min_len < prefix.mask() {
            return Err(InvalidLengthRange::MinBelowPrefixLen);
        }
        Ok(Self {
            prefix: prefix.masked(),
            min_len,
            max_len,
        })
    }

    /// Creates an entry that matches only `prefix` itself
    /// (`min_len == max_len == prefix.mask()`).
    ///
    /// Host bits in `prefix` are zeroed.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::Ipv4Addr;
    /// use ipnetx::{prefix::IpPrefix, prefix_match::PrefixMatch};
    ///
    /// let p = IpPrefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap();
    /// let e = PrefixMatch::exact(p);
    /// assert!(e.matches(p));
    /// assert!(!e.matches(IpPrefix::new(Ipv4Addr::new(10, 0, 0, 0), 9).unwrap()));
    /// ```
    #[must_use]
    pub fn exact(prefix: IpPrefix<A>) -> Self {
        let len = prefix.mask();
        Self {
            prefix: prefix.masked(),
            min_len: len,
            max_len: len,
        }
    }

    /// Creates an entry matching `prefix` and every more-specific prefix
    /// inside it: lengths from `prefix.mask()` through the address width.
    ///
    /// Host bits in `prefix` are zeroed. The result is the same as
    /// `PrefixMatch::new(prefix, prefix.mask(), A::BITS)`, which cannot fail.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::Ipv4Addr;
    /// use ipnetx::{prefix::IpPrefix, prefix_match::PrefixMatch};
    ///
    /// let ten = IpPrefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap();
    /// let entry = PrefixMatch::or_longer(ten);
    /// assert!(entry.matches(ten));
    /// assert!(entry.matches(IpPrefix::new(Ipv4Addr::new(10, 1, 2, 3), 32).unwrap()));
    /// assert_eq!((entry.min_len(), entry.max_len()), (8, 32));
    /// ```
    #[must_use]
    pub fn or_longer(prefix: IpPrefix<A>) -> Self {
        Self {
            prefix: prefix.masked(),
            min_len: prefix.mask(),
            max_len: A::BITS,
        }
    }

    /// The entry's prefix, with host bits zeroed.
    #[must_use]
    pub fn prefix(&self) -> IpPrefix<A> {
        self.prefix
    }

    /// Shortest prefix length accepted by [`matches`](Self::matches).
    ///
    /// Always at least the prefix length of [`prefix`](Self::prefix).
    #[must_use]
    pub fn min_len(&self) -> u8 {
        self.min_len
    }

    /// Longest prefix length accepted by [`matches`](Self::matches).
    #[must_use]
    pub fn max_len(&self) -> u8 {
        self.max_len
    }

    /// Returns `true` if `candidate` lies inside this entry's prefix, ignoring
    /// the length window.
    ///
    /// This is [`IpPrefix::covers`] applied to the entry's prefix.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::Ipv4Addr;
    /// use ipnetx::{prefix::IpPrefix, prefix_match::PrefixMatch};
    ///
    /// let e = PrefixMatch::exact(IpPrefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap());
    /// let inside = IpPrefix::new(Ipv4Addr::new(10, 1, 2, 0), 24).unwrap();
    /// let shorter = IpPrefix::new(Ipv4Addr::new(10, 0, 0, 0), 7).unwrap();
    /// assert!(e.covers(inside));    // inside, even though exact() would not match it
    /// assert!(!e.matches(inside));
    /// assert!(!e.covers(shorter));  // shorter than the entry: not inside it
    /// ```
    #[must_use]
    pub fn covers(&self, candidate: IpPrefix<A>) -> bool {
        self.prefix.covers(&candidate)
    }

    /// Returns `true` if `candidate` is [covered](Self::covers) and its length
    /// is within `min_len..=max_len`.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::Ipv4Addr;
    /// use ipnetx::{prefix::IpPrefix, prefix_match::PrefixMatch};
    ///
    /// let p = IpPrefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap();
    /// let e = PrefixMatch::new(p, 16, 24).unwrap();
    /// assert!(e.matches(IpPrefix::new(Ipv4Addr::new(10, 1, 0, 0), 16).unwrap()));
    /// assert!(!e.matches(IpPrefix::new(Ipv4Addr::new(10, 1, 0, 0), 15).unwrap()));
    /// assert!(!e.matches(IpPrefix::new(Ipv4Addr::new(11, 1, 0, 0), 16).unwrap()));
    /// ```
    #[must_use]
    pub fn matches(&self, candidate: IpPrefix<A>) -> bool {
        let len = candidate.mask();
        self.min_len <= len && len <= self.max_len && self.covers(candidate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::range::IpRange;
    use proptest::prelude::*;
    use std::collections::HashSet;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // ── Independent oracles ──────────────────────────────────────────────
    //
    // None of these use `to_u128`, `network_mask`, `IpPrefix::contains`, or
    // any shift/mask arithmetic from the implementation under test.

    fn bits4(a: Ipv4Addr) -> Vec<bool> {
        a.octets()
            .iter()
            .flat_map(|o| (0..8).rev().map(move |i| (o >> i) & 1 == 1))
            .collect()
    }

    fn bits6(a: Ipv6Addr) -> Vec<bool> {
        a.octets()
            .iter()
            .flat_map(|o| (0..8).rev().map(move |i| (o >> i) & 1 == 1))
            .collect()
    }

    /// Oracle 1: explicit bit-sequence comparison.
    fn covers_bits_v4(p: IpPrefix<Ipv4Addr>, r: IpPrefix<Ipv4Addr>) -> bool {
        let n = p.mask() as usize;
        r.mask() >= p.mask() && bits4(p.ip())[..n] == bits4(r.ip())[..n]
    }

    fn covers_bits_v6(p: IpPrefix<Ipv6Addr>, r: IpPrefix<Ipv6Addr>) -> bool {
        let n = p.mask() as usize;
        r.mask() >= p.mask() && bits6(p.ip())[..n] == bits6(r.ip())[..n]
    }

    /// Oracle 2: inclusive-range containment via existing `IpRange` values.
    fn covers_range<A: IpAddress>(p: IpPrefix<A>, r: IpPrefix<A>) -> bool {
        let outer: IpRange<A> = p.to_range();
        let inner: IpRange<A> = r.to_range();
        outer.start() <= inner.start() && inner.end() <= outer.end()
    }

    /// Oracle 3: truncate the route to the entry's length and compare as
    /// canonical prefixes (only meaningful when the route is long enough).
    fn covers_truncation<A: IpAddress>(p: IpPrefix<A>, r: IpPrefix<A>) -> bool {
        r.mask() >= p.mask() && IpPrefix::new(r.ip(), p.mask()).unwrap().masked() == p.masked()
    }

    fn v4(a: u8, b: u8, c: u8, d: u8, len: u8) -> IpPrefix<Ipv4Addr> {
        IpPrefix::new(Ipv4Addr::new(a, b, c, d), len).unwrap()
    }

    fn v6(s: &str, len: u8) -> IpPrefix<Ipv6Addr> {
        IpPrefix::new(s.parse().unwrap(), len).unwrap()
    }

    // ── Hand-derived tables ──────────────────────────────────────────────
    //
    // Expected values below were worked out by hand from the definition,
    // bit by bit, before looking at the implementation.

    #[test]
    fn covers_octet_aligned_v4() {
        let e = PrefixMatch::exact(v4(10, 0, 0, 0, 8));
        assert!(e.covers(v4(10, 0, 0, 0, 8))); // equal
        assert!(e.covers(v4(10, 1, 2, 0, 24)));
        assert!(e.covers(v4(10, 255, 255, 255, 32)));
        assert!(!e.covers(v4(10, 0, 0, 0, 7))); // shorter than entry
        assert!(!e.covers(v4(11, 0, 0, 0, 8))); // 11 = 00001011, 10 = 00001010
        assert!(!e.covers(v4(9, 255, 255, 255, 32)));
    }

    #[test]
    fn covers_non_octet_boundaries_v4() {
        // /23: compares 16 bits + the top 7 bits of the third octet.
        let e = PrefixMatch::exact(v4(192, 168, 0, 0, 23));
        assert!(e.covers(v4(192, 168, 0, 0, 24))); // third octet 0000000|0
        assert!(e.covers(v4(192, 168, 1, 0, 24))); // third octet 0000000|1
        assert!(!e.covers(v4(192, 168, 2, 0, 24))); // 0000001|0 differs at bit 23
        assert!(!e.covers(v4(192, 168, 1, 0, 22))); // shorter than the entry

        // /9: only the top bit of the second octet matters.
        let e = PrefixMatch::exact(v4(10, 128, 0, 0, 9)); // second octet 1|0000000
        assert!(e.covers(v4(10, 128, 0, 0, 16)));
        assert!(e.covers(v4(10, 255, 1, 0, 24))); // 255 = 1|1111111
        assert!(!e.covers(v4(10, 127, 0, 0, 16))); // 127 = 0|1111111
        assert!(!e.covers(v4(10, 0, 0, 0, 9)));
    }

    #[test]
    fn covers_default_route_and_host_routes_v4() {
        let all = PrefixMatch::exact(v4(0, 0, 0, 0, 0));
        assert!(all.covers(v4(0, 0, 0, 0, 0)));
        assert!(all.covers(v4(203, 0, 113, 7, 32)));

        let host = PrefixMatch::exact(v4(192, 0, 2, 1, 32));
        assert!(host.covers(v4(192, 0, 2, 1, 32)));
        assert!(!host.covers(v4(192, 0, 2, 2, 32)));
        assert!(!host.covers(v4(192, 0, 2, 0, 31)));
    }

    #[test]
    fn covers_v6() {
        let e = PrefixMatch::exact(v6("2001:db8::", 32));
        assert!(e.covers(v6("2001:db8:1::", 48)));
        assert!(e.covers(v6("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", 128)));
        assert!(!e.covers(v6("2001:db9::", 48))); // db8 vs db9 differ in the last bit of hextet 2
        assert!(!e.covers(v6("2001:db8::", 31))); // shorter

        // /33: top bit of the third hextet decides.
        let e = PrefixMatch::exact(v6("2001:db8:8000::", 33));
        assert!(e.covers(v6("2001:db8:8000::", 48))); // 0x8000 starts with 1
        assert!(e.covers(v6("2001:db8:ffff::", 48)));
        assert!(!e.covers(v6("2001:db8:7fff::", 48))); // 0x7fff starts with 0

        // /65: top bit of the fifth hextet (bit index 64).
        let e = PrefixMatch::exact(v6("2001:db8:0:0:8000::", 65));
        assert!(e.covers(v6("2001:db8:0:0:8000:1::", 80)));
        assert!(!e.covers(v6("2001:db8:0:0:7fff::", 80)));

        // /0 and /128.
        assert!(PrefixMatch::exact(v6("::", 0)).covers(v6("2001:db8::1", 128)));
        let h = PrefixMatch::exact(v6("2001:db8::1", 128));
        assert!(h.covers(v6("2001:db8::1", 128)));
        assert!(!h.covers(v6("2001:db8::2", 128)));
    }

    #[test]
    fn matches_applies_the_window() {
        // Everything inside 10/8 whose length is 16..=24.
        let e = PrefixMatch::new(v4(10, 0, 0, 0, 8), 16, 24).unwrap();
        assert!(e.matches(v4(10, 1, 0, 0, 16))); // lower bound inclusive
        assert!(e.matches(v4(10, 1, 2, 0, 20)));
        assert!(e.matches(v4(10, 1, 2, 0, 24))); // upper bound inclusive
        assert!(!e.matches(v4(10, 1, 2, 0, 25))); // just above
        assert!(!e.matches(v4(10, 1, 0, 0, 15))); // just below
        assert!(!e.matches(v4(10, 0, 0, 0, 8))); // the entry itself: below min
        assert!(!e.matches(v4(11, 1, 0, 0, 16))); // in window, not covered
    }

    #[test]
    fn matches_default_route_cases() {
        // 0.0.0.0/0 exact: only the default route.
        let exact = PrefixMatch::exact(v4(0, 0, 0, 0, 0));
        assert!(exact.matches(v4(0, 0, 0, 0, 0)));
        assert!(!exact.matches(v4(0, 0, 0, 0, 1)));
        assert!(!exact.matches(v4(10, 0, 0, 0, 8)));
        // 0.0.0.0/0 with window 0..=32: every IPv4 prefix.
        let any = PrefixMatch::new(v4(0, 0, 0, 0, 0), 0, 32).unwrap();
        assert!(any.matches(v4(0, 0, 0, 0, 0)));
        assert!(any.matches(v4(198, 51, 100, 9, 32)));
        // /1..=32 excludes the default route itself.
        let non_default = PrefixMatch::new(v4(0, 0, 0, 0, 0), 1, 32).unwrap();
        assert!(!non_default.matches(v4(0, 0, 0, 0, 0)));
        assert!(non_default.matches(v4(128, 0, 0, 0, 1)));
    }

    #[test]
    fn host_bits_on_the_route_are_ignored() {
        let e = PrefixMatch::new(v4(10, 0, 0, 0, 8), 24, 24).unwrap();
        assert!(e.matches(v4(10, 1, 2, 77, 24))); // same as 10.1.2.0/24
        assert!(!e.matches(v4(11, 1, 2, 77, 24)));
    }

    // ── Constructor ──────────────────────────────────────────────────────

    #[test]
    fn constructor_accepts_boundaries() {
        let p = v4(10, 0, 0, 0, 8);
        assert!(PrefixMatch::new(p, 8, 8).is_ok()); // min == p == max
        assert!(PrefixMatch::new(p, 8, 32).is_ok()); // max == BITS
        assert!(PrefixMatch::new(p, 32, 32).is_ok()); // min == max == BITS
        assert!(PrefixMatch::new(v4(1, 2, 3, 4, 32), 32, 32).is_ok());
        assert!(PrefixMatch::new(v6("::", 0), 0, 128).is_ok());
        assert!(PrefixMatch::new(v6("2001:db8::", 32), 32, 128).is_ok());
    }

    #[test]
    fn constructor_error_variants() {
        let p = v4(10, 0, 0, 0, 8);
        assert_eq!(
            PrefixMatch::new(p, 8, 33),
            Err(InvalidLengthRange::MaxAboveAddrBits)
        );
        assert_eq!(
            PrefixMatch::new(p, 24, 16),
            Err(InvalidLengthRange::MinAboveMax)
        );
        assert_eq!(
            PrefixMatch::new(p, 7, 24),
            Err(InvalidLengthRange::MinBelowPrefixLen)
        );
        // max_len < p needs no check of its own: with min == max < p it is a
        // MinBelowPrefixLen, and with min > max it is a MinAboveMax.
        assert_eq!(
            PrefixMatch::new(p, 4, 4),
            Err(InvalidLengthRange::MinBelowPrefixLen)
        );
        // IPv6 width.
        assert_eq!(
            PrefixMatch::new(v6("::", 0), 0, 129),
            Err(InvalidLengthRange::MaxAboveAddrBits)
        );
    }

    #[test]
    fn constructor_error_precedence() {
        let p = v4(10, 0, 0, 0, 8);
        // max too large AND min > max AND min < p: MaxAboveAddrBits wins.
        assert_eq!(
            PrefixMatch::new(p, 40, 33),
            Err(InvalidLengthRange::MaxAboveAddrBits)
        );
        // min > max AND min < p: min 6, max 5, p 8 → MinAboveMax is reported
        // before MinBelowPrefixLen.
        assert_eq!(
            PrefixMatch::new(p, 6, 5),
            Err(InvalidLengthRange::MinAboveMax)
        );
    }

    #[test]
    fn error_display_is_nonempty_and_distinct() {
        let msgs: HashSet<String> = [
            InvalidLengthRange::MaxAboveAddrBits,
            InvalidLengthRange::MinAboveMax,
            InvalidLengthRange::MinBelowPrefixLen,
        ]
        .iter()
        .map(|e| e.to_string())
        .collect();
        assert_eq!(msgs.len(), 3);
        assert!(msgs.iter().all(|m| !m.is_empty()));
    }

    #[test]
    fn entry_prefix_is_masked_and_equality_ignores_host_bits() {
        let a = PrefixMatch::new(v4(10, 1, 2, 3, 8), 16, 24).unwrap();
        let b = PrefixMatch::new(v4(10, 0, 0, 0, 8), 16, 24).unwrap();
        assert_eq!(a.prefix(), v4(10, 0, 0, 0, 8));
        assert_eq!(a, b);
        let set: HashSet<_> = [a, b].into_iter().collect();
        assert_eq!(set.len(), 1);
        // Different window ⇒ different entry.
        let c = PrefixMatch::new(v4(10, 0, 0, 0, 8), 16, 25).unwrap();
        assert_ne!(a, c);
        // exact() masks too.
        assert_eq!(
            PrefixMatch::exact(v4(10, 9, 9, 9, 8)),
            PrefixMatch::exact(v4(10, 0, 0, 0, 8))
        );
    }

    #[test]
    fn or_longer_spans_prefix_length_through_address_width() {
        let e = PrefixMatch::or_longer(v4(10, 9, 9, 9, 8));
        assert_eq!(e.prefix(), v4(10, 0, 0, 0, 8));
        assert_eq!((e.min_len(), e.max_len()), (8, 32));
        assert_eq!(e, PrefixMatch::new(v4(10, 0, 0, 0, 8), 8, 32).unwrap());
        assert!(e.matches(v4(10, 0, 0, 0, 8)));
        assert!(e.matches(v4(10, 1, 2, 3, 32)));
        assert!(!e.matches(v4(10, 0, 0, 0, 7)));
        assert!(!e.matches(v4(11, 0, 0, 0, 16)));

        let e = PrefixMatch::or_longer(v6("2001:db8::", 32));
        assert_eq!((e.min_len(), e.max_len()), (32, 128));
        assert!(e.matches(v6("2001:db8::1", 128)));

        // On a host route there is nothing longer.
        let host = v4(192, 0, 2, 1, 32);
        assert_eq!(PrefixMatch::or_longer(host), PrefixMatch::exact(host));
    }

    #[test]
    fn accessors() {
        let e = PrefixMatch::new(v4(10, 0, 0, 0, 8), 16, 24).unwrap();
        assert_eq!((e.min_len(), e.max_len()), (16, 24));
        let x = PrefixMatch::exact(v6("2001:db8::", 32));
        assert_eq!((x.min_len(), x.max_len()), (32, 32));
    }

    // ── Property tests against the independent oracles ───────────────────

    /// A v4 entry prefix plus a route biased to be related to it half the
    /// time (so covered routes are common, not vanishingly rare).
    fn arb_v4_pair() -> impl Strategy<Value = (IpPrefix<Ipv4Addr>, IpPrefix<Ipv4Addr>)> {
        let entry = (any::<u32>(), 0u8..=32)
            .prop_map(|(a, l)| IpPrefix::new(Ipv4Addr::from_bits(a), l).unwrap());
        entry.prop_flat_map(|p| {
            let related = (any::<u32>(), 0u8..=32).prop_map(move |(suffix, extra)| {
                let len = p.mask() + extra.min(32 - p.mask());
                // keep the entry's leading bits, randomize the rest
                let keep = if p.mask() == 0 {
                    0
                } else {
                    u32::MAX << (32 - p.mask() as u32)
                };
                let addr = (p.ip().to_bits() & keep) | (suffix & !keep);
                IpPrefix::new(Ipv4Addr::from_bits(addr), len).unwrap()
            });
            let unrelated = (any::<u32>(), 0u8..=32)
                .prop_map(|(a, l)| IpPrefix::new(Ipv4Addr::from_bits(a), l).unwrap());
            (Just(p), prop_oneof![related, unrelated])
        })
    }

    fn arb_v6_pair() -> impl Strategy<Value = (IpPrefix<Ipv6Addr>, IpPrefix<Ipv6Addr>)> {
        let entry = (any::<u128>(), 0u8..=128)
            .prop_map(|(a, l)| IpPrefix::new(Ipv6Addr::from_bits(a), l).unwrap());
        entry.prop_flat_map(|p| {
            let related = (any::<u128>(), 0u8..=128).prop_map(move |(suffix, extra)| {
                let len = p.mask() + extra.min(128 - p.mask());
                let keep = if p.mask() == 0 {
                    0
                } else {
                    u128::MAX << (128 - p.mask() as u32)
                };
                let addr = (p.ip().to_bits() & keep) | (suffix & !keep);
                IpPrefix::new(Ipv6Addr::from_bits(addr), len).unwrap()
            });
            let unrelated = (any::<u128>(), 0u8..=128)
                .prop_map(|(a, l)| IpPrefix::new(Ipv6Addr::from_bits(a), l).unwrap());
            (Just(p), prop_oneof![related, unrelated])
        })
    }

    /// Random valid window `(min, max)` for a prefix of length `p`.
    fn arb_window(p: u8, bits: u8) -> impl Strategy<Value = (u8, u8)> {
        (p..=bits).prop_flat_map(move |min| (Just(min), min..=bits))
    }

    proptest! {
        #[test]
        fn covers_agrees_with_three_oracles_v4((p, r) in arb_v4_pair()) {
            let e = PrefixMatch::exact(p);
            let expected = covers_bits_v4(p, r);
            prop_assert_eq!(e.covers(r), expected);
            prop_assert_eq!(covers_range(p, r), expected);
            prop_assert_eq!(covers_truncation(p, r), expected);
        }

        #[test]
        fn covers_agrees_with_three_oracles_v6((p, r) in arb_v6_pair()) {
            let e = PrefixMatch::exact(p);
            let expected = covers_bits_v6(p, r);
            prop_assert_eq!(e.covers(r), expected);
            prop_assert_eq!(covers_range(p, r), expected);
            prop_assert_eq!(covers_truncation(p, r), expected);
        }

        #[test]
        fn matches_is_covers_and_window_v4(
            ((p, r), (min, max)) in arb_v4_pair().prop_flat_map(|(p, r)| {
                let w = arb_window(p.mask(), 32);
                (Just((p, r)), w)
            })
        ) {
            let e = PrefixMatch::new(p, min, max).unwrap();
            let expected = covers_bits_v4(p, r) && min <= r.mask() && r.mask() <= max;
            prop_assert_eq!(e.matches(r), expected);
            // matches ⇒ covers; covers ignores the window.
            if e.matches(r) { prop_assert!(e.covers(r)); }
            prop_assert_eq!(e.covers(r), covers_bits_v4(p, r));
        }

        #[test]
        fn matches_is_covers_and_window_v6(
            ((p, r), (min, max)) in arb_v6_pair().prop_flat_map(|(p, r)| {
                let w = arb_window(p.mask(), 128);
                (Just((p, r)), w)
            })
        ) {
            let e = PrefixMatch::new(p, min, max).unwrap();
            let expected = covers_bits_v6(p, r) && min <= r.mask() && r.mask() <= max;
            prop_assert_eq!(e.matches(r), expected);
            if e.matches(r) { prop_assert!(e.covers(r)); }
            prop_assert_eq!(e.covers(r), covers_bits_v6(p, r));
        }

        #[test]
        fn widening_the_window_never_loses_a_match_v4(
            ((p, r), (min, max), (lo_slack, hi_slack)) in arb_v4_pair().prop_flat_map(|(p, r)| {
                (Just((p, r)), arb_window(p.mask(), 32), (0u8..=32, 0u8..=32))
            })
        ) {
            let narrow = PrefixMatch::new(p, min, max).unwrap();
            let wide_min = min.saturating_sub(lo_slack).max(p.mask());
            let wide_max = max.saturating_add(hi_slack).min(32);
            let wide = PrefixMatch::new(p, wide_min, wide_max).unwrap();
            if narrow.matches(r) { prop_assert!(wide.matches(r)); }
        }

        #[test]
        fn or_longer_matches_whatever_is_covered_v4((p, r) in arb_v4_pair()) {
            let e = PrefixMatch::or_longer(p);
            prop_assert_eq!(e.matches(r), covers_bits_v4(p, r));
            prop_assert_eq!(Ok(e), PrefixMatch::new(p, p.mask(), 32));
        }

        #[test]
        fn or_longer_matches_whatever_is_covered_v6((p, r) in arb_v6_pair()) {
            let e = PrefixMatch::or_longer(p);
            prop_assert_eq!(e.matches(r), covers_bits_v6(p, r));
            prop_assert_eq!(Ok(e), PrefixMatch::new(p, p.mask(), 128));
        }

        #[test]
        fn exact_matches_only_the_same_network_v4((p, r) in arb_v4_pair()) {
            let e = PrefixMatch::exact(p);
            prop_assert_eq!(e.matches(r), r.masked() == p.masked());
        }

        #[test]
        fn exact_matches_only_the_same_network_v6((p, r) in arb_v6_pair()) {
            let e = PrefixMatch::exact(p);
            prop_assert_eq!(e.matches(r), r.masked() == p.masked());
        }

        #[test]
        fn route_host_bits_never_change_the_answer_v4(
            ((p, r), (min, max)) in arb_v4_pair().prop_flat_map(|(p, r)| {
                (Just((p, r)), arb_window(p.mask(), 32))
            })
        ) {
            let e = PrefixMatch::new(p, min, max).unwrap();
            prop_assert_eq!(e.matches(r), e.matches(r.masked()));
            prop_assert_eq!(e.covers(r), e.covers(r.masked()));
        }

        #[test]
        fn entry_host_bits_never_change_the_entry_v4(
            (a, l, (min, max)) in (any::<u32>(), 0u8..=32).prop_flat_map(|(a, l)| {
                (Just(a), Just(l), arb_window(l, 32))
            })
        ) {
            let raw = IpPrefix::new(Ipv4Addr::from_bits(a), l).unwrap();
            let e1 = PrefixMatch::new(raw, min, max).unwrap();
            let e2 = PrefixMatch::new(raw.masked(), min, max).unwrap();
            prop_assert_eq!(e1, e2);
            prop_assert_eq!(e1.prefix(), raw.masked());
        }

        #[test]
        fn constructor_accepts_exactly_the_documented_set_v4(
            a in any::<u32>(), l in 0u8..=32, min in 0u8..=40, max in 0u8..=40
        ) {
            let p = IpPrefix::new(Ipv4Addr::from_bits(a), l).unwrap();
            let result = PrefixMatch::new(p, min, max);
            let expected = if max > 32 {
                Err(InvalidLengthRange::MaxAboveAddrBits)
            } else if min > max {
                Err(InvalidLengthRange::MinAboveMax)
            } else if min < l {
                Err(InvalidLengthRange::MinBelowPrefixLen)
            } else {
                Ok(())
            };
            prop_assert_eq!(result.map(|_| ()), expected);
        }
    }
}
