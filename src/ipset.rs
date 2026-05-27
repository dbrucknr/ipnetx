use crate::{
    interfaces::IpAddress,
    prefix::IpPrefix,
    range::IpRange,
    tools::range::{normalize, subtract_range},
};

/// A builder for constructing a normalized [`IpSet`].
///
/// Ranges and prefixes may be added or removed in any order and any
/// combination. When [`build`](IpSetBuilder::build) is called the builder
/// sorts all pending ranges and merges any that are adjacent or overlapping,
/// producing an [`IpSet`] whose ranges are non-overlapping and in ascending
/// order.
///
/// # Examples
///
/// ```
/// use std::net::Ipv4Addr;
/// use ipnetx::prefix::IpPrefix;
/// use ipnetx::ipset::IpSetBuilder;
///
/// let mut builder = IpSetBuilder::<Ipv4Addr>::new();
/// builder.add_prefix(IpPrefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap());
/// builder.remove_ip(Ipv4Addr::new(10, 0, 0, 1));
/// let set = builder.build();
///
/// assert!(!set.contains_ip(Ipv4Addr::new(10, 0, 0, 1)));
/// assert!(set.contains_ip(Ipv4Addr::new(10, 0, 0, 2)));
/// ```
pub struct IpSetBuilder<A: IpAddress> {
    ranges: Vec<IpRange<A>>,
}

impl<A: IpAddress> Default for IpSetBuilder<A> {
    fn default() -> Self {
        Self::new()
    }
}

impl<A: IpAddress> IpSetBuilder<A> {
    /// Creates a new empty builder.
    ///
    /// Equivalent to [`IpSetBuilder::default`].
    pub fn new() -> Self {
        Self { ranges: Vec::new() }
    }

    /// Adds a single IP address to the set.
    ///
    /// Equivalent to adding a host prefix (`/32` for IPv4, `/128` for IPv6).
    /// Adjacent or overlapping entries are merged when [`build`](IpSetBuilder::build)
    /// is called.
    pub fn add_ip(&mut self, ip: A) {
        // A single IP is nothing more than a range where start == end — a range of size 1
        let range = IpRange::new(ip, ip);
        self.add_range(range);
    }

    /// Removes a single IP address from the set.
    ///
    /// If the address falls in the middle of a stored range, that range is
    /// split into two. Has no effect if the address is not present.
    pub fn remove_ip(&mut self, ip: A) {
        let range = IpRange::new(ip, ip);
        self.remove_range(range);
    }

    /// Adds an address range to the set.
    ///
    /// Invalid ranges (`start > end`) are silently ignored. Adjacent or
    /// overlapping ranges are merged when [`build`](IpSetBuilder::build) is called.
    pub fn add_range(&mut self, range: IpRange<A>) {
        if range.is_valid() {
            self.ranges.push(range);
        }
    }

    /// Removes an address range from the set.
    ///
    /// Each stored range that intersects `range` is trimmed or split as needed.
    /// Five cases arise per stored range: no overlap (kept), fully covered
    /// (dropped), clips left end (right piece survives), clips right end (left
    /// piece survives), or middle removal (splits into two ranges).
    ///
    /// Invalid ranges (`start > end`) are silently ignored.
    pub fn remove_range(&mut self, range: IpRange<A>) {
        // O(n) time complexity
        if !range.is_valid() {
            return;
        }

        // std::mem::take swaps self.ranges out with an empty Vec, giving
        // subtract_range ownership of the data. The result is assigned back.
        self.ranges = subtract_range(std::mem::take(&mut self.ranges), range);
    }

    /// Adds all addresses covered by `prefix` to the set.
    ///
    /// Equivalent to `add_range(prefix.to_range())`.
    pub fn add_prefix(&mut self, prefix: IpPrefix<A>) {
        let range = prefix.to_range();
        self.add_range(range);
    }

    /// Removes all addresses covered by `prefix` from the set.
    ///
    /// Equivalent to `remove_range(prefix.to_range())`.
    pub fn remove_prefix(&mut self, prefix: IpPrefix<A>) {
        let range = prefix.to_range();
        self.remove_range(range);
    }

    /// Consumes the builder and returns a normalized [`IpSet`].
    ///
    /// All pending ranges are sorted by start address and merged: adjacent or
    /// overlapping ranges are collapsed into a single range. The resulting
    /// [`IpSet`] contains non-overlapping ranges in ascending order.
    #[must_use]
    pub fn build(self) -> IpSet<A> {
        let merged = normalize(self.ranges);
        IpSet::new(merged)
    }

}

/// An immutable, normalized set of IP addresses.
///
/// An `IpSet` is always constructed through [`IpSetBuilder::build`], which
/// guarantees that the internal ranges are sorted by start address,
/// non-overlapping, and non-adjacent. This invariant enables O(log n)
/// membership queries via binary search.
///
/// # Examples
///
/// ```
/// use std::net::Ipv4Addr;
/// use ipnetx::prefix::IpPrefix;
/// use ipnetx::ipset::IpSetBuilder;
///
/// let mut builder = IpSetBuilder::<Ipv4Addr>::new();
/// builder.add_prefix(IpPrefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap());
/// let set = builder.build();
///
/// assert!(set.contains_ip(Ipv4Addr::new(10, 1, 2, 3)));
/// assert!(!set.contains_ip(Ipv4Addr::new(192, 168, 1, 1)));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpSet<A: IpAddress> {
    ranges: Vec<IpRange<A>>,
}

impl<A: IpAddress> IpSet<A> {
    fn new(ranges: Vec<IpRange<A>>) -> Self {
        Self { ranges }
    }

    /// Returns the normalized ranges that make up this set.
    ///
    /// Ranges are sorted by start address, non-overlapping, and non-adjacent.
    #[must_use]
    pub fn ranges(&self) -> &[IpRange<A>] {
        &self.ranges
    }

    /// Returns the minimal list of CIDR prefixes that exactly cover this set.
    ///
    /// Each internal range is decomposed via [`IpRange::prefixes`] and the
    /// results are concatenated in ascending address order. The returned list
    /// can be large for sets that contain many unaligned ranges.
    #[must_use]
    pub fn prefixes(&self) -> Vec<IpPrefix<A>> {
        let mut prefixes = Vec::<IpPrefix<A>>::new();
        for range in &self.ranges {
            prefixes.extend(range.prefixes());
        }
        prefixes
    }

    /// Returns `true` if `ip` is a member of this set.
    ///
    /// Uses binary search — O(log n) in the number of stored ranges.
    #[must_use]
    pub fn contains_ip(&self, ip: A) -> bool {
        // O(log n) instead of O(n) linear scan
        self.ranges
            .binary_search_by(|range| {
                if ip < range.start() {
                    std::cmp::Ordering::Greater
                } else if ip > range.end() {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .is_ok()
    }

    /// Returns `true` if every address in `range` is a member of this set.
    ///
    /// The entire range must be enclosed within a *single* stored range. A
    /// query that spans a gap between two stored ranges returns `false` even
    /// if both endpoints are individually contained. Returns `false` for
    /// invalid ranges (`start > end`).
    ///
    /// Uses binary search — O(log n) in the number of stored ranges.
    #[must_use]
    pub fn contains_range(&self, range: IpRange<A>) -> bool {
        if !range.is_valid() {
            return false;
        }

        // O(log n) instead of O(n) linear scan
        let idx = self.ranges.binary_search_by(|r| {
            if range.start() < r.start() {
                std::cmp::Ordering::Greater
            } else if range.end() > r.end() {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        });

        match idx {
            Ok(i) => range.end() <= self.ranges[i].end(),
            Err(_) => false,
        }
    }

    /// Returns `true` if this set and `other` share at least one address.
    ///
    /// Exploits the sorted, non-overlapping invariant of both sets to walk
    /// them simultaneously in O(n + m) time rather than the O(n × m) of a
    /// naive nested loop.
    #[must_use]
    pub fn overlaps_ip_set(&self, other: &IpSet<A>) -> bool {
        // Both sets are sorted and non-overlapping (guaranteed by the IpSetBuilder's .build())
        // We can walk them together in O(n + m) time rather than O(n * m) if we were to loop over all pairs (nested loops)
        let mut i = 0;
        let mut j = 0;

        while i < self.ranges.len() && j < other.ranges.len() {
            let a = &self.ranges[i];
            let b = &other.ranges[j];

            if a.overlaps(b) {
                return true;
            }

            if a.end().to_u128() < b.end().to_u128() {
                i += 1;
            } else {
                j += 1;
            }
        }

        false
    }

    /// Returns the number of distinct ranges in this set.
    ///
    /// This is the count of *ranges*, not individual IP addresses — a single
    /// range can span billions of addresses.
    #[must_use]
    pub fn len(&self) -> usize {
        self.ranges.len()
    }

    /// Returns `true` if the set contains no addresses.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Returns a new set containing every address that is in `self`, `other`,
    /// or both (A ∪ B).
    ///
    /// The result is normalized: ranges from both sets are merged and sorted,
    /// so adjacent or overlapping spans are collapsed automatically.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::Ipv4Addr;
    /// use ipnetx::prefix::IpPrefix;
    /// use ipnetx::ipset::IpSetBuilder;
    ///
    /// let mut b1 = IpSetBuilder::<Ipv4Addr>::new();
    /// b1.add_prefix(IpPrefix::new(Ipv4Addr::new(10, 0, 0, 0), 24).unwrap());
    /// let a = b1.build();
    ///
    /// let mut b2 = IpSetBuilder::<Ipv4Addr>::new();
    /// b2.add_prefix(IpPrefix::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap());
    /// let b = b2.build();
    ///
    /// let u = a.union(&b);
    /// assert!(u.contains_ip(Ipv4Addr::new(10, 0, 0, 1)));      // from a
    /// assert!(u.contains_ip(Ipv4Addr::new(192, 168, 1, 1)));   // from b
    /// assert_eq!(u.len(), 2);                                    // disjoint — two ranges
    /// ```
    #[must_use]
    pub fn union(&self, other: &IpSet<A>) -> IpSet<A> {
        // Collect all ranges from both sets into one Vec, then normalize.
        // normalize sorts and merges adjacent/overlapping spans, so the result
        // satisfies the IpSet invariant regardless of input order.
        let mut ranges = Vec::with_capacity(self.ranges.len() + other.ranges.len());
        ranges.extend_from_slice(&self.ranges);
        ranges.extend_from_slice(&other.ranges);
        IpSet::new(normalize(ranges))
    }

    /// Returns a new set containing every address that is in `self` but not in
    /// `other` (A ∖ B).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::net::Ipv4Addr;
    /// use ipnetx::prefix::IpPrefix;
    /// use ipnetx::ipset::IpSetBuilder;
    ///
    /// let mut b1 = IpSetBuilder::<Ipv4Addr>::new();
    /// b1.add_prefix(IpPrefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap());
    /// let a = b1.build();
    ///
    /// let mut b2 = IpSetBuilder::<Ipv4Addr>::new();
    /// b2.add_prefix(IpPrefix::new(Ipv4Addr::new(10, 0, 0, 0), 24).unwrap());
    /// let b = b2.build();
    ///
    /// let diff = a.difference(&b);
    /// assert!(!diff.contains_ip(Ipv4Addr::new(10, 0, 0, 1))); // carved out
    /// assert!(diff.contains_ip(Ipv4Addr::new(10, 0, 1, 1)));  // still present
    /// ```
    #[must_use]
    pub fn difference(&self, other: &IpSet<A>) -> IpSet<A> {
        todo!()
    }

    /// Returns a new set containing every address that is in both `self` and
    /// `other` (A ∩ B).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::net::Ipv4Addr;
    /// use ipnetx::prefix::IpPrefix;
    /// use ipnetx::ipset::IpSetBuilder;
    ///
    /// let mut b1 = IpSetBuilder::<Ipv4Addr>::new();
    /// b1.add_prefix(IpPrefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap());
    /// let a = b1.build();
    ///
    /// let mut b2 = IpSetBuilder::<Ipv4Addr>::new();
    /// b2.add_prefix(IpPrefix::new(Ipv4Addr::new(10, 0, 0, 0), 24).unwrap());
    /// let b = b2.build();
    ///
    /// let inter = a.intersection(&b);
    /// assert!(inter.contains_ip(Ipv4Addr::new(10, 0, 0, 1)));  // in both
    /// assert!(!inter.contains_ip(Ipv4Addr::new(10, 0, 1, 1))); // only in a
    /// ```
    #[must_use]
    pub fn intersection(&self, other: &IpSet<A>) -> IpSet<A> {
        todo!()
    }

    /// Returns a new set containing every address that is *not* in `self`.
    ///
    /// For IPv4 the complement covers `0.0.0.0/0` minus `self`; for IPv6 it
    /// covers `::/0` minus `self`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::net::Ipv4Addr;
    /// use ipnetx::prefix::IpPrefix;
    /// use ipnetx::ipset::IpSetBuilder;
    ///
    /// let mut builder = IpSetBuilder::<Ipv4Addr>::new();
    /// builder.add_prefix(IpPrefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap());
    /// let a = builder.build();
    ///
    /// let c = a.complement();
    /// assert!(!c.contains_ip(Ipv4Addr::new(10, 0, 0, 1)));     // was in a
    /// assert!(c.contains_ip(Ipv4Addr::new(192, 168, 1, 1)));    // not in a
    /// ```
    #[must_use]
    pub fn complement(&self) -> IpSet<A> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // --- Construction ---

    // cargo test ipset::tests::test_v4_ipset_default_construction
    #[test]
    fn test_v4_ipset_default_construction() {
        let builder = IpSetBuilder::<Ipv4Addr>::default();
        let ipset = builder.build();
        assert!(ipset.is_empty());
    }

    // cargo test ipset::tests::test_v4_ipset_add_range_construction
    #[test]
    fn test_v4_ipset_add_range_construction() {
        let start = Ipv4Addr::new(192, 168, 0, 0);
        let end = Ipv4Addr::new(192, 168, 255, 255);
        let range = IpRange::new(start, end);

        let mut builder = IpSetBuilder::<Ipv4Addr>::new();
        builder.add_range(range);

        let ipset = builder.build();
        assert!(!ipset.is_empty());
        assert_eq!(ipset.len(), 1);
    }

    #[test]
    fn test_v4_ipset_multi_add_adjacent_ranges() {
        let start1 = Ipv4Addr::new(192, 168, 0, 0);
        let end1 = Ipv4Addr::new(192, 168, 255, 255);
        let range1 = IpRange::new(start1, end1);

        let start2 = Ipv4Addr::new(192, 168, 1, 0);
        let end2 = Ipv4Addr::new(192, 168, 255, 255);
        let range2 = IpRange::new(start2, end2);

        let mut builder = IpSetBuilder::<Ipv4Addr>::new();
        builder.add_range(range1);
        builder.add_range(range2);

        let ipset = builder.build();
        assert!(!ipset.is_empty());
        assert_eq!(ipset.len(), 1);
    }

    // cargo test ipset::tests::test_v4_ipset_multi_add_disjoint_ranges
    #[test]
    fn test_v4_ipset_multi_add_disjoint_ranges() {
        let start1 = Ipv4Addr::new(192, 168, 0, 0);
        let end1 = Ipv4Addr::new(192, 168, 255, 255);
        let range1 = IpRange::new(start1, end1);

        let start2 = Ipv4Addr::new(10, 0, 0, 0);
        let end2 = Ipv4Addr::new(10, 255, 255, 255);
        let range2 = IpRange::new(start2, end2);

        let mut builder = IpSetBuilder::<Ipv4Addr>::new();
        builder.add_range(range1);
        builder.add_range(range2);

        let ipset = builder.build();
        assert!(!ipset.is_empty());
        assert_eq!(ipset.len(), 2);
    }

    // cargo test ipset::tests::test_v6_ipset_add_range_construction
    #[test]
    fn test_v6_ipset_add_range_construction() {
        let start = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0);
        let end = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 10);
        let range = IpRange::new(start, end);

        let mut builder = IpSetBuilder::<Ipv6Addr>::new();
        builder.add_range(range);

        let ipset = builder.build();
        assert!(!ipset.is_empty());
        assert_eq!(ipset.len(), 1);
    }

    // cargo test ipset::tests::test_v6_ipset_multi_add_adjacent_ranges
    #[test]
    fn test_v6_ipset_multi_add_adjacent_ranges() {
        let start1 = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0);
        let end1 = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 10);
        let range1 = IpRange::new(start1, end1);

        let start2 = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 11);
        let end2 = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 20);
        let range2 = IpRange::new(start2, end2);

        let mut builder = IpSetBuilder::<Ipv6Addr>::new();
        builder.add_range(range1);
        builder.add_range(range2);

        let ipset = builder.build();
        assert!(!ipset.is_empty());
        assert_eq!(ipset.len(), 1);
        assert_eq!(
            ipset.ranges()[0].start(),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)
        );
        assert_eq!(
            ipset.ranges()[0].end(),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 20)
        );
    }

    #[test]
    fn test_v6_ipset_multi_add_disjoint_ranges() {
        let start1 = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0);
        let end1 = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 10);
        let range1 = IpRange::new(start1, end1);

        let start2 = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 12);
        let end2 = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 20);
        let range2 = IpRange::new(start2, end2);

        let mut builder = IpSetBuilder::<Ipv6Addr>::new();
        builder.add_range(range1);
        builder.add_range(range2);

        let ipset = builder.build();
        assert!(!ipset.is_empty());
        assert_eq!(ipset.len(), 2);
        assert_eq!(
            ipset.ranges()[0].start(),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)
        );
        assert_eq!(
            ipset.ranges()[0].end(),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 10)
        );
        assert_eq!(
            ipset.ranges()[1].start(),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 12)
        );
        assert_eq!(
            ipset.ranges()[1].end(),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 20)
        );
    }

    // --- Add Ip ---
    // cargo test ipset::tests::test_add_ip
    #[test]
    fn test_add_ip() {
        let mut builder = IpSetBuilder::<Ipv4Addr>::new();
        builder.add_ip(Ipv4Addr::new(192, 168, 1, 1));

        let ipset = builder.build();

        assert!(!ipset.is_empty());
        assert_eq!(ipset.len(), 1);
        assert_eq!(ipset.ranges()[0].start(), Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(ipset.ranges()[0].end(), Ipv4Addr::new(192, 168, 1, 1));
    }

    // --- Remove IP ---
    // cargo test ipset::tests::test_remove_ip
    #[test]
    fn test_remove_ip() {
        let mut builder = IpSetBuilder::<Ipv4Addr>::new();
        builder.add_ip(Ipv4Addr::new(192, 168, 1, 1));
        builder.remove_ip(Ipv4Addr::new(192, 168, 1, 1));
        let ipset = builder.build();

        assert!(ipset.is_empty());
        assert_eq!(ipset.len(), 0);
    }

    // --- Remove IP: split and no-op ---
    // cargo test ipset::tests::test_remove_ip_splits_range
    #[test]
    fn test_remove_ip_splits_range() {
        // Remove 10.0.0.5 from [10.0.0.1..10.0.0.10] → [1..4] and [6..10]
        let mut builder = IpSetBuilder::<Ipv4Addr>::new();
        builder.add_range(IpRange::new(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 10),
        ));
        builder.remove_ip(Ipv4Addr::new(10, 0, 0, 5));
        let ipset = builder.build();
        assert_eq!(ipset.len(), 2);
        assert_eq!(ipset.ranges()[0].start(), Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(ipset.ranges()[0].end(), Ipv4Addr::new(10, 0, 0, 4));
        assert_eq!(ipset.ranges()[1].start(), Ipv4Addr::new(10, 0, 0, 6));
        assert_eq!(ipset.ranges()[1].end(), Ipv4Addr::new(10, 0, 0, 10));
    }

    // cargo test ipset::tests::test_remove_ip_not_in_set
    #[test]
    fn test_remove_ip_not_in_set() {
        // Removing an IP that isn't in the set is a no-op
        let mut builder = IpSetBuilder::<Ipv4Addr>::new();
        builder.add_range(IpRange::new(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 10),
        ));
        builder.remove_ip(Ipv4Addr::new(10, 0, 0, 20));
        let ipset = builder.build();
        assert_eq!(ipset.len(), 1);
    }

    // --- Add IP: merging ---
    // cargo test ipset::tests::test_add_ip_merges_adjacent
    #[test]
    fn test_add_ip_merges_adjacent() {
        // 10.0.0.11 is adjacent to [10.0.0.1..10.0.0.10] — should merge
        let mut builder = IpSetBuilder::<Ipv4Addr>::new();
        builder.add_range(IpRange::new(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 10),
        ));
        builder.add_ip(Ipv4Addr::new(10, 0, 0, 11));
        let ipset = builder.build();
        assert_eq!(ipset.len(), 1);
        assert_eq!(ipset.ranges()[0].start(), Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(ipset.ranges()[0].end(), Ipv4Addr::new(10, 0, 0, 11));
    }

    // Note on remove operations: removing from the middle of a stored range requires splitting it into up to two pieces.
    // Five cases arise per stored range: no overlap (keep), fully covered (drop), clips left end (trim start),
    // clips right end (trim end), removal in the middle (split into two).

    // cargo test ipset::tests::test_remove_range_invalid_is_noop
    #[test]
    fn test_remove_range_invalid_is_noop() {
        // An invalid range (start > end) is silently ignored — stored ranges unchanged
        let mut builder = IpSetBuilder::<Ipv4Addr>::new();
        builder.add_range(IpRange::new(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 10),
        ));
        builder.remove_range(IpRange::new(
            Ipv4Addr::new(10, 0, 0, 10),
            Ipv4Addr::new(10, 0, 0, 1), // start > end — invalid
        ));
        let ipset = builder.build();
        assert_eq!(ipset.len(), 1);
        assert_eq!(ipset.ranges()[0].start(), Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(ipset.ranges()[0].end(), Ipv4Addr::new(10, 0, 0, 10));
    }

    // --- Remove Range ---
    // cargo test ipset::tests::test_remove_range
    #[test]
    fn test_remove_range() {
        let mut builder = IpSetBuilder::<Ipv4Addr>::new();
        builder.add_range(IpRange::new(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 255),
        ));
        builder.remove_range(IpRange::new(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 255),
        ));
        let ipset = builder.build();

        assert!(ipset.is_empty());
        assert_eq!(ipset.len(), 0);
    }

    // cargo test ipset::tests::test_remove_range_no_overlap
    #[test]
    fn test_remove_range_no_overlap() {
        // Removing a range that doesn't touch stored ranges is a no-op
        let mut builder = IpSetBuilder::<Ipv4Addr>::new();
        builder.add_range(IpRange::new(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 10),
        ));
        builder.remove_range(IpRange::new(
            Ipv4Addr::new(10, 0, 0, 20),
            Ipv4Addr::new(10, 0, 0, 30),
        ));
        let ipset = builder.build();
        assert_eq!(ipset.len(), 1);
        assert_eq!(ipset.ranges()[0].start(), Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(ipset.ranges()[0].end(), Ipv4Addr::new(10, 0, 0, 10));
    }

    // cargo test ipset::tests::test_remove_range_clips_left_of_stored
    #[test]
    fn test_remove_range_clips_left_of_stored() {
        // Remove [1..5] from stored [1..10] → right piece [6..10] survives
        let mut builder = IpSetBuilder::<Ipv4Addr>::new();
        builder.add_range(IpRange::new(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 10),
        ));
        builder.remove_range(IpRange::new(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 5),
        ));
        let ipset = builder.build();
        assert_eq!(ipset.len(), 1);
        assert_eq!(ipset.ranges()[0].start(), Ipv4Addr::new(10, 0, 0, 6));
        assert_eq!(ipset.ranges()[0].end(), Ipv4Addr::new(10, 0, 0, 10));
    }

    // cargo test ipset::tests::test_remove_range_clips_right_of_stored
    #[test]
    fn test_remove_range_clips_right_of_stored() {
        // Remove [6..10] from stored [1..10] → left piece [1..5] survives
        let mut builder = IpSetBuilder::<Ipv4Addr>::new();
        builder.add_range(IpRange::new(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 10),
        ));
        builder.remove_range(IpRange::new(
            Ipv4Addr::new(10, 0, 0, 6),
            Ipv4Addr::new(10, 0, 0, 10),
        ));
        let ipset = builder.build();
        assert_eq!(ipset.len(), 1);
        assert_eq!(ipset.ranges()[0].start(), Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(ipset.ranges()[0].end(), Ipv4Addr::new(10, 0, 0, 5));
    }

    // cargo test ipset::tests::test_remove_range_middle_split
    #[test]
    fn test_remove_range_middle_split() {
        // Remove [4..7] from stored [1..10] → two pieces: [1..3] and [8..10]
        let mut builder = IpSetBuilder::<Ipv4Addr>::new();
        builder.add_range(IpRange::new(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 10),
        ));
        builder.remove_range(IpRange::new(
            Ipv4Addr::new(10, 0, 0, 4),
            Ipv4Addr::new(10, 0, 0, 7),
        ));
        let ipset = builder.build();
        assert_eq!(ipset.len(), 2);
        assert_eq!(ipset.ranges()[0].start(), Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(ipset.ranges()[0].end(), Ipv4Addr::new(10, 0, 0, 3));
        assert_eq!(ipset.ranges()[1].start(), Ipv4Addr::new(10, 0, 0, 8));
        assert_eq!(ipset.ranges()[1].end(), Ipv4Addr::new(10, 0, 0, 10));
    }

    // --- Remove Prefix
    // cargo test ipset::tests::test_remove_prefix
    #[test]
    fn test_remove_prefix() {
        let mut builder = IpSetBuilder::<Ipv4Addr>::new();
        builder.add_prefix(IpPrefix::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap());
        builder.remove_prefix(IpPrefix::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap());
        let ipset = builder.build();

        assert!(ipset.is_empty());
        assert_eq!(ipset.len(), 0);
    }

    // --- Builder: edge cases ---

    // cargo test ipset::tests::test_v4_builder_empty
    #[test]
    fn test_v4_builder_empty() {
        let ipset = IpSetBuilder::<Ipv4Addr>::new().build();
        assert!(ipset.is_empty());
        assert_eq!(ipset.len(), 0);
    }

    // cargo test ipset::tests::test_v6_builder_empty
    #[test]
    fn test_v6_builder_empty() {
        let ipset = IpSetBuilder::<Ipv6Addr>::new().build();
        assert!(ipset.is_empty());
        assert_eq!(ipset.len(), 0);
    }

    // cargo test ipset::tests::test_v4_builder_invalid_range_ignored
    #[test]
    fn test_v4_builder_invalid_range_ignored() {
        // start > end — builder silently drops it; set stays empty
        let invalid = IpRange::new(Ipv4Addr::new(10, 0, 0, 10), Ipv4Addr::new(10, 0, 0, 0));
        let mut builder = IpSetBuilder::<Ipv4Addr>::new();
        builder.add_range(invalid);
        assert!(builder.build().is_empty());
    }

    // cargo test ipset::tests::test_v6_builder_invalid_range_ignored
    #[test]
    fn test_v6_builder_invalid_range_ignored() {
        let invalid = IpRange::new(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 10),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),
        );
        let mut builder = IpSetBuilder::<Ipv6Addr>::new();
        builder.add_range(invalid);
        assert!(builder.build().is_empty());
    }

    // cargo test ipset::tests::test_v4_builder_add_prefix
    #[test]
    fn test_v4_builder_add_prefix() {
        // 10.0.0.0/8 → range 10.0.0.0..10.255.255.255
        let prefix = IpPrefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap();
        let mut builder = IpSetBuilder::<Ipv4Addr>::new();
        builder.add_prefix(prefix);
        let ipset = builder.build();
        assert_eq!(ipset.len(), 1);
        assert_eq!(ipset.ranges()[0].start(), Ipv4Addr::new(10, 0, 0, 0));
        assert_eq!(ipset.ranges()[0].end(), Ipv4Addr::new(10, 255, 255, 255));
    }

    // cargo test ipset::tests::test_v6_builder_add_prefix
    #[test]
    fn test_v6_builder_add_prefix() {
        // 1::/120 → range 1::0..1::ff
        let prefix = IpPrefix::new(Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 0), 120).unwrap();
        let mut builder = IpSetBuilder::<Ipv6Addr>::new();
        builder.add_prefix(prefix);
        let ipset = builder.build();
        assert_eq!(ipset.len(), 1);
        assert_eq!(
            ipset.ranges()[0].start(),
            Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 0)
        );
        assert_eq!(
            ipset.ranges()[0].end(),
            Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 255)
        );
    }

    // cargo test ipset::tests::test_v4_builder_overlapping_ranges_merged
    #[test]
    fn test_v4_builder_overlapping_ranges_merged() {
        // [0..10] and [5..20] overlap — should collapse to [0..20]
        let range1 = IpRange::new(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 10));
        let range2 = IpRange::new(Ipv4Addr::new(10, 0, 0, 5), Ipv4Addr::new(10, 0, 0, 20));
        let mut builder = IpSetBuilder::<Ipv4Addr>::new();
        builder.add_range(range1);
        builder.add_range(range2);
        let ipset = builder.build();
        assert_eq!(ipset.len(), 1);
        assert_eq!(ipset.ranges()[0].start(), Ipv4Addr::new(10, 0, 0, 0));
        assert_eq!(ipset.ranges()[0].end(), Ipv4Addr::new(10, 0, 0, 20));
    }

    // cargo test ipset::tests::test_v4_builder_three_ranges_partial_merge
    #[test]
    fn test_v4_builder_three_ranges_partial_merge() {
        // [1..5] and [3..8] overlap → merged to [1..8]; [20..30] stays separate
        let range1 = IpRange::new(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 5));
        let range2 = IpRange::new(Ipv4Addr::new(10, 0, 0, 3), Ipv4Addr::new(10, 0, 0, 8));
        let range3 = IpRange::new(Ipv4Addr::new(10, 0, 0, 20), Ipv4Addr::new(10, 0, 0, 30));
        let mut builder = IpSetBuilder::<Ipv4Addr>::new();
        builder.add_range(range1);
        builder.add_range(range2);
        builder.add_range(range3);
        let ipset = builder.build();
        assert_eq!(ipset.len(), 2);
        assert_eq!(ipset.ranges()[0].start(), Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(ipset.ranges()[0].end(), Ipv4Addr::new(10, 0, 0, 8));
        assert_eq!(ipset.ranges()[1].start(), Ipv4Addr::new(10, 0, 0, 20));
        assert_eq!(ipset.ranges()[1].end(), Ipv4Addr::new(10, 0, 0, 30));
    }

    // --- Contains IP: boundary and gap ---

    // cargo test ipset::tests::test_v4_contains_ip_start_boundary
    #[test]
    fn test_v4_contains_ip_start_boundary() {
        let mut builder = IpSetBuilder::<Ipv4Addr>::new();
        builder.add_range(IpRange::new(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 10),
        ));
        let ipset = builder.build();
        assert!(ipset.contains_ip(Ipv4Addr::new(10, 0, 0, 1))); // inclusive
        assert!(!ipset.contains_ip(Ipv4Addr::new(10, 0, 0, 0))); // just before
    }

    // cargo test ipset::tests::test_v4_contains_ip_end_boundary
    #[test]
    fn test_v4_contains_ip_end_boundary() {
        let mut builder = IpSetBuilder::<Ipv4Addr>::new();
        builder.add_range(IpRange::new(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 10),
        ));
        let ipset = builder.build();
        assert!(ipset.contains_ip(Ipv4Addr::new(10, 0, 0, 10))); // inclusive
        assert!(!ipset.contains_ip(Ipv4Addr::new(10, 0, 0, 11))); // just after
    }

    // cargo test ipset::tests::test_v4_contains_ip_in_gap
    #[test]
    fn test_v4_contains_ip_in_gap() {
        // Two ranges with a gap at .6..=.9
        let mut builder = IpSetBuilder::<Ipv4Addr>::new();
        builder.add_range(IpRange::new(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 5),
        ));
        builder.add_range(IpRange::new(
            Ipv4Addr::new(10, 0, 0, 10),
            Ipv4Addr::new(10, 0, 0, 20),
        ));
        let ipset = builder.build();
        assert!(!ipset.contains_ip(Ipv4Addr::new(10, 0, 0, 7))); // in the gap
        assert!(ipset.contains_ip(Ipv4Addr::new(10, 0, 0, 5))); // last of first range
        assert!(ipset.contains_ip(Ipv4Addr::new(10, 0, 0, 10))); // first of second range
    }

    // cargo test ipset::tests::test_v6_contains_ip_in_gap
    #[test]
    fn test_v6_contains_ip_in_gap() {
        let mut builder = IpSetBuilder::<Ipv6Addr>::new();
        builder.add_range(IpRange::new(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 5),
        ));
        builder.add_range(IpRange::new(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 10),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 20),
        ));
        let ipset = builder.build();
        assert!(!ipset.contains_ip(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 7)));
    }

    // cargo test ipset::tests::test_v4_contains_ip_empty_set
    #[test]
    fn test_v4_contains_ip_empty_set() {
        let ipset = IpSetBuilder::<Ipv4Addr>::new().build();
        assert!(!ipset.contains_ip(Ipv4Addr::new(10, 0, 0, 1)));
    }

    // --- Contains Range ---

    // cargo test ipset::tests::test_v4_contains_range_fully_contained
    #[test]
    fn test_v4_contains_range_fully_contained() {
        let mut builder = IpSetBuilder::<Ipv4Addr>::new();
        builder.add_range(IpRange::new(
            Ipv4Addr::new(10, 0, 0, 0),
            Ipv4Addr::new(10, 0, 0, 100),
        ));
        let ipset = builder.build();
        let query = IpRange::new(Ipv4Addr::new(10, 0, 0, 10), Ipv4Addr::new(10, 0, 0, 50));
        assert!(ipset.contains_range(query));
    }

    // cargo test ipset::tests::test_v4_contains_range_exact_match
    #[test]
    fn test_v4_contains_range_exact_match() {
        // A range identical to a stored range is contained
        let mut builder = IpSetBuilder::<Ipv4Addr>::new();
        builder.add_range(IpRange::new(
            Ipv4Addr::new(10, 0, 0, 0),
            Ipv4Addr::new(10, 0, 0, 100),
        ));
        let ipset = builder.build();
        let query = IpRange::new(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 100));
        assert!(ipset.contains_range(query));
    }

    // cargo test ipset::tests::test_v4_contains_range_spans_gap
    #[test]
    fn test_v4_contains_range_spans_gap() {
        // Query crosses the gap between two stored ranges — not fully contained
        let mut builder = IpSetBuilder::<Ipv4Addr>::new();
        builder.add_range(IpRange::new(
            Ipv4Addr::new(10, 0, 0, 0),
            Ipv4Addr::new(10, 0, 0, 10),
        ));
        builder.add_range(IpRange::new(
            Ipv4Addr::new(10, 0, 0, 20),
            Ipv4Addr::new(10, 0, 0, 30),
        ));
        let ipset = builder.build();
        let query = IpRange::new(Ipv4Addr::new(10, 0, 0, 5), Ipv4Addr::new(10, 0, 0, 25));
        assert!(!ipset.contains_range(query));
    }

    // cargo test ipset::tests::test_v4_contains_range_exceeds_stored
    #[test]
    fn test_v4_contains_range_exceeds_stored() {
        // Query is larger than any stored range — not contained
        let mut builder = IpSetBuilder::<Ipv4Addr>::new();
        builder.add_range(IpRange::new(
            Ipv4Addr::new(10, 0, 0, 10),
            Ipv4Addr::new(10, 0, 0, 20),
        ));
        let ipset = builder.build();
        let query = IpRange::new(Ipv4Addr::new(10, 0, 0, 5), Ipv4Addr::new(10, 0, 0, 25));
        assert!(!ipset.contains_range(query));
    }

    // cargo test ipset::tests::test_v4_contains_range_invalid_input
    #[test]
    fn test_v4_contains_range_invalid_input() {
        let mut builder = IpSetBuilder::<Ipv4Addr>::new();
        builder.add_range(IpRange::new(
            Ipv4Addr::new(10, 0, 0, 0),
            Ipv4Addr::new(10, 0, 0, 100),
        ));
        let ipset = builder.build();
        let invalid = IpRange::new(Ipv4Addr::new(10, 0, 0, 50), Ipv4Addr::new(10, 0, 0, 10));
        assert!(!ipset.contains_range(invalid));
    }

    // cargo test ipset::tests::test_v6_contains_range_fully_contained
    #[test]
    fn test_v6_contains_range_fully_contained() {
        let mut builder = IpSetBuilder::<Ipv6Addr>::new();
        builder.add_range(IpRange::new(
            Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 0),
            Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 100),
        ));
        let ipset = builder.build();
        let query = IpRange::new(
            Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 10),
            Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 50),
        );
        assert!(ipset.contains_range(query));
    }

    // cargo test ipset::tests::test_v6_contains_range_spans_gap
    #[test]
    fn test_v6_contains_range_spans_gap() {
        let mut builder = IpSetBuilder::<Ipv6Addr>::new();
        builder.add_range(IpRange::new(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 10),
        ));
        builder.add_range(IpRange::new(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 20),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 30),
        ));
        let ipset = builder.build();
        let query = IpRange::new(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 5),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 25),
        );
        assert!(!ipset.contains_range(query));
    }

    // --- Overlaps IP Set ---

    // cargo test ipset::tests::test_v4_overlaps_ip_set_overlap
    #[test]
    fn test_v4_overlaps_ip_set_overlap() {
        let mut b1 = IpSetBuilder::<Ipv4Addr>::new();
        b1.add_range(IpRange::new(
            Ipv4Addr::new(10, 0, 0, 0),
            Ipv4Addr::new(10, 0, 0, 20),
        ));
        let set1 = b1.build();

        let mut b2 = IpSetBuilder::<Ipv4Addr>::new();
        b2.add_range(IpRange::new(
            Ipv4Addr::new(10, 0, 0, 10),
            Ipv4Addr::new(10, 0, 0, 30),
        ));
        let set2 = b2.build();

        assert!(set1.overlaps_ip_set(&set2));
        assert!(set2.overlaps_ip_set(&set1)); // symmetric
    }

    // cargo test ipset::tests::test_v4_overlaps_ip_set_disjoint
    #[test]
    fn test_v4_overlaps_ip_set_disjoint() {
        let mut b1 = IpSetBuilder::<Ipv4Addr>::new();
        b1.add_range(IpRange::new(
            Ipv4Addr::new(10, 0, 0, 0),
            Ipv4Addr::new(10, 0, 0, 10),
        ));
        let set1 = b1.build();

        let mut b2 = IpSetBuilder::<Ipv4Addr>::new();
        b2.add_range(IpRange::new(
            Ipv4Addr::new(10, 0, 0, 20),
            Ipv4Addr::new(10, 0, 0, 30),
        ));
        let set2 = b2.build();

        assert!(!set1.overlaps_ip_set(&set2));
        assert!(!set2.overlaps_ip_set(&set1)); // symmetric
    }

    // cargo test ipset::tests::test_v4_overlaps_ip_set_empty
    #[test]
    fn test_v4_overlaps_ip_set_empty() {
        let mut b1 = IpSetBuilder::<Ipv4Addr>::new();
        b1.add_range(IpRange::new(
            Ipv4Addr::new(10, 0, 0, 0),
            Ipv4Addr::new(10, 0, 0, 10),
        ));
        let populated = b1.build();
        let empty = IpSetBuilder::<Ipv4Addr>::new().build();

        assert!(!populated.overlaps_ip_set(&empty));
        assert!(!empty.overlaps_ip_set(&populated));
        assert!(!empty.overlaps_ip_set(&empty));
    }

    // cargo test ipset::tests::test_v4_overlaps_ip_set_single_address_touch
    #[test]
    fn test_v4_overlaps_ip_set_single_address_touch() {
        // The sets share exactly one address (10.0.0.10) — that counts as overlap
        let mut b1 = IpSetBuilder::<Ipv4Addr>::new();
        b1.add_range(IpRange::new(
            Ipv4Addr::new(10, 0, 0, 0),
            Ipv4Addr::new(10, 0, 0, 10),
        ));
        let set1 = b1.build();

        let mut b2 = IpSetBuilder::<Ipv4Addr>::new();
        b2.add_range(IpRange::new(
            Ipv4Addr::new(10, 0, 0, 10),
            Ipv4Addr::new(10, 0, 0, 20),
        ));
        let set2 = b2.build();

        assert!(set1.overlaps_ip_set(&set2));
    }

    // cargo test ipset::tests::test_v4_overlaps_ip_set_subset
    #[test]
    fn test_v4_overlaps_ip_set_subset() {
        // One set fully inside the other — still overlaps
        let mut b1 = IpSetBuilder::<Ipv4Addr>::new();
        b1.add_range(IpRange::new(
            Ipv4Addr::new(10, 0, 0, 0),
            Ipv4Addr::new(10, 0, 0, 100),
        ));
        let outer = b1.build();

        let mut b2 = IpSetBuilder::<Ipv4Addr>::new();
        b2.add_range(IpRange::new(
            Ipv4Addr::new(10, 0, 0, 40),
            Ipv4Addr::new(10, 0, 0, 60),
        ));
        let inner = b2.build();

        assert!(outer.overlaps_ip_set(&inner));
        assert!(inner.overlaps_ip_set(&outer)); // symmetric
    }

    // cargo test ipset::tests::test_v6_overlaps_ip_set_overlap
    #[test]
    fn test_v6_overlaps_ip_set_overlap() {
        let mut b1 = IpSetBuilder::<Ipv6Addr>::new();
        b1.add_range(IpRange::new(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 20),
        ));
        let set1 = b1.build();

        let mut b2 = IpSetBuilder::<Ipv6Addr>::new();
        b2.add_range(IpRange::new(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 10),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 30),
        ));
        let set2 = b2.build();

        assert!(set1.overlaps_ip_set(&set2));
        assert!(set2.overlaps_ip_set(&set1)); // symmetric
    }

    // cargo test ipset::tests::test_v6_overlaps_ip_set_disjoint
    #[test]
    fn test_v6_overlaps_ip_set_disjoint() {
        let mut b1 = IpSetBuilder::<Ipv6Addr>::new();
        b1.add_range(IpRange::new(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 10),
        ));
        let set1 = b1.build();

        let mut b2 = IpSetBuilder::<Ipv6Addr>::new();
        b2.add_range(IpRange::new(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 20),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 30),
        ));
        let set2 = b2.build();

        assert!(!set1.overlaps_ip_set(&set2));
        assert!(!set2.overlaps_ip_set(&set1)); // symmetric
    }

    // cargo test ipset::tests::test_v6_overlaps_ip_set_empty
    #[test]
    fn test_v6_overlaps_ip_set_empty() {
        let mut b1 = IpSetBuilder::<Ipv6Addr>::new();
        b1.add_range(IpRange::new(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 10),
        ));
        let populated = b1.build();
        let empty = IpSetBuilder::<Ipv6Addr>::new().build();

        assert!(!populated.overlaps_ip_set(&empty));
        assert!(!empty.overlaps_ip_set(&populated));
    }

    // --- Prefixes ---

    // cargo test ipset::tests::test_v4_ipset_prefixes_single_range
    #[test]
    fn test_v4_ipset_prefixes_single_range() {
        // An aligned range produces exactly one CIDR prefix
        let mut builder = IpSetBuilder::<Ipv4Addr>::new();
        builder.add_range(IpRange::new(
            Ipv4Addr::new(192, 168, 1, 0),
            Ipv4Addr::new(192, 168, 1, 255),
        ));
        let ipset = builder.build();
        let prefixes = ipset.prefixes();
        assert_eq!(prefixes.len(), 1);
        assert_eq!(prefixes[0].ip(), Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(prefixes[0].mask(), 24);
    }

    // cargo test ipset::tests::test_v6_ipset_prefixes_single_range
    #[test]
    fn test_v6_ipset_prefixes_single_range() {
        let mut builder = IpSetBuilder::<Ipv6Addr>::new();
        builder.add_range(IpRange::new(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 255),
        ));
        let ipset = builder.build();
        let prefixes = ipset.prefixes();
        assert_eq!(prefixes.len(), 1);
        assert_eq!(prefixes[0].ip(), Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));
        assert_eq!(prefixes[0].mask(), 120);
    }

    // cargo test ipset::tests::test_v4_ipset_prefixes_multiple_ranges
    #[test]
    fn test_v4_ipset_prefixes_multiple_ranges() {
        // Two disjoint ranges — prefixes from each are concatenated in order
        let mut builder = IpSetBuilder::<Ipv4Addr>::new();
        builder.add_range(IpRange::new(
            Ipv4Addr::new(10, 0, 0, 0),
            Ipv4Addr::new(10, 0, 0, 255),
        ));
        builder.add_range(IpRange::new(
            Ipv4Addr::new(192, 168, 1, 0),
            Ipv4Addr::new(192, 168, 1, 255),
        ));
        let ipset = builder.build();
        let prefixes = ipset.prefixes();
        assert_eq!(prefixes.len(), 2);
        assert_eq!(prefixes[0].ip(), Ipv4Addr::new(10, 0, 0, 0));
        assert_eq!(prefixes[0].mask(), 24);
        assert_eq!(prefixes[1].ip(), Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(prefixes[1].mask(), 24);
    }

    // cargo test ipset::tests::test_v6_ipset_prefixes_multiple_ranges
    #[test]
    fn test_v6_ipset_prefixes_multiple_ranges() {
        let mut builder = IpSetBuilder::<Ipv6Addr>::new();
        builder.add_range(IpRange::new(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 255),
        ));
        builder.add_range(IpRange::new(
            Ipv6Addr::new(2001, 0, 0, 0, 0, 0, 0, 0),
            Ipv6Addr::new(2001, 0, 0, 0, 0, 0, 0, 255),
        ));
        let ipset = builder.build();
        let prefixes = ipset.prefixes();
        assert_eq!(prefixes.len(), 2);
        assert_eq!(prefixes[0].ip(), Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));
        assert_eq!(prefixes[0].mask(), 120);
        assert_eq!(prefixes[1].ip(), Ipv6Addr::new(2001, 0, 0, 0, 0, 0, 0, 0));
        assert_eq!(prefixes[1].mask(), 120);
    }

    // cargo test ipset::tests::test_v4_ipset_prefixes_empty_set
    #[test]
    fn test_v4_ipset_prefixes_empty_set() {
        let ipset = IpSetBuilder::<Ipv4Addr>::new().build();
        assert!(ipset.prefixes().is_empty());
    }

    // cargo test ipset::tests::test_v6_ipset_prefixes_empty_set
    #[test]
    fn test_v6_ipset_prefixes_empty_set() {
        let ipset = IpSetBuilder::<Ipv6Addr>::new().build();
        assert!(ipset.prefixes().is_empty());
    }

    // --- Contains ---

    // cargo test ipset::tests::test_v4_ipset_contains_ip
    #[test]
    fn test_v4_ipset_contains_ip() {
        let start = Ipv4Addr::new(192, 168, 0, 0);
        let end = Ipv4Addr::new(192, 168, 255, 255);
        let range = IpRange::new(start, end);

        let mut builder = IpSetBuilder::<Ipv4Addr>::new();
        builder.add_range(range);

        let ipset = builder.build();
        assert!(ipset.contains_ip(Ipv4Addr::new(192, 168, 1, 1)));
    }

    // cargo test ipset::tests::test_v6_ipset_contains_ip
    #[test]
    fn test_v6_ipset_contains_ip() {
        let start = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0);
        let end = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 10);
        let range = IpRange::new(start, end);

        let mut builder = IpSetBuilder::<Ipv6Addr>::new();
        builder.add_range(range);

        let ipset = builder.build();
        assert!(ipset.contains_ip(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)));
    }

    // cargo test ipset::tests::test_v4_ipset_not_contains_ip
    #[test]
    fn test_v4_ipset_not_contains_ip() {
        let start = Ipv4Addr::new(192, 168, 0, 0);
        let end = Ipv4Addr::new(192, 168, 255, 255);
        let range = IpRange::new(start, end);

        let mut builder = IpSetBuilder::<Ipv4Addr>::new();
        builder.add_range(range);

        let ipset = builder.build();
        assert!(!ipset.contains_ip(Ipv4Addr::new(192, 169, 0, 0)));
    }

    // cargo test ipset::tests::test_v6_ipset_not_contains_ip
    #[test]
    fn test_v6_ipset_not_contains_ip() {
        let start = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0);
        let end = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 10);
        let range = IpRange::new(start, end);

        let mut builder = IpSetBuilder::<Ipv6Addr>::new();
        builder.add_range(range);

        let ipset = builder.build();
        assert!(!ipset.contains_ip(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 11)));
    }

    // --- Union ---

    fn make_v4_set(start: Ipv4Addr, end: Ipv4Addr) -> super::IpSet<Ipv4Addr> {
        let mut b = IpSetBuilder::new();
        b.add_range(IpRange::new(start, end));
        b.build()
    }

    fn make_v6_set(start: Ipv6Addr, end: Ipv6Addr) -> super::IpSet<Ipv6Addr> {
        let mut b = IpSetBuilder::new();
        b.add_range(IpRange::new(start, end));
        b.build()
    }

    // cargo test ipset::tests::test_v4_union_disjoint
    #[test]
    fn test_v4_union_disjoint() {
        // Two completely separate ranges — result contains both, no merging
        let a = make_v4_set(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 255));
        let b = make_v4_set(Ipv4Addr::new(192, 168, 1, 0), Ipv4Addr::new(192, 168, 1, 255));
        let u = a.union(&b);
        assert_eq!(u.len(), 2);
        assert!(u.contains_ip(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(u.contains_ip(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(!u.contains_ip(Ipv4Addr::new(172, 16, 0, 1)));
    }

    // cargo test ipset::tests::test_v4_union_overlapping
    #[test]
    fn test_v4_union_overlapping() {
        // Overlapping ranges — merged into one
        let a = make_v4_set(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 10));
        let b = make_v4_set(Ipv4Addr::new(10, 0, 0, 5), Ipv4Addr::new(10, 0, 0, 20));
        let u = a.union(&b);
        assert_eq!(u.len(), 1);
        assert_eq!(u.ranges()[0].start(), Ipv4Addr::new(10, 0, 0, 0));
        assert_eq!(u.ranges()[0].end(), Ipv4Addr::new(10, 0, 0, 20));
    }

    // cargo test ipset::tests::test_v4_union_adjacent
    #[test]
    fn test_v4_union_adjacent() {
        // Adjacent ranges (no gap) — merged into one
        let a = make_v4_set(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 127));
        let b = make_v4_set(Ipv4Addr::new(10, 0, 0, 128), Ipv4Addr::new(10, 0, 0, 255));
        let u = a.union(&b);
        assert_eq!(u.len(), 1);
        assert_eq!(u.ranges()[0].start(), Ipv4Addr::new(10, 0, 0, 0));
        assert_eq!(u.ranges()[0].end(), Ipv4Addr::new(10, 0, 0, 255));
    }

    // cargo test ipset::tests::test_v4_union_subset
    #[test]
    fn test_v4_union_subset() {
        // b is entirely inside a — result equals a
        let a = make_v4_set(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 255));
        let b = make_v4_set(Ipv4Addr::new(10, 0, 0, 50), Ipv4Addr::new(10, 0, 0, 100));
        let u = a.union(&b);
        assert_eq!(u.len(), 1);
        assert_eq!(u.ranges()[0].start(), Ipv4Addr::new(10, 0, 0, 0));
        assert_eq!(u.ranges()[0].end(), Ipv4Addr::new(10, 0, 0, 255));
    }

    // cargo test ipset::tests::test_v4_union_with_empty
    #[test]
    fn test_v4_union_with_empty() {
        // Union with empty set — result equals the non-empty set
        let a = make_v4_set(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 255));
        let empty = IpSetBuilder::<Ipv4Addr>::new().build();
        assert_eq!(a.union(&empty), a);
        assert_eq!(empty.union(&a), a);
    }

    // cargo test ipset::tests::test_v4_union_both_empty
    #[test]
    fn test_v4_union_both_empty() {
        let a = IpSetBuilder::<Ipv4Addr>::new().build();
        let b = IpSetBuilder::<Ipv4Addr>::new().build();
        assert!(a.union(&b).is_empty());
    }

    // cargo test ipset::tests::test_v4_union_symmetric
    #[test]
    fn test_v4_union_symmetric() {
        // a ∪ b == b ∪ a
        let a = make_v4_set(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 255));
        let b = make_v4_set(Ipv4Addr::new(192, 168, 1, 0), Ipv4Addr::new(192, 168, 1, 255));
        assert_eq!(a.union(&b), b.union(&a));
    }

    // cargo test ipset::tests::test_v6_union_disjoint
    #[test]
    fn test_v6_union_disjoint() {
        let a = make_v6_set(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xff),
        );
        let b = make_v6_set(
            Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 0),
            Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 0xff),
        );
        let u = a.union(&b);
        assert_eq!(u.len(), 2);
        assert!(u.contains_ip(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)));
        assert!(u.contains_ip(Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 1)));
    }

    // cargo test ipset::tests::test_v6_union_overlapping
    #[test]
    fn test_v6_union_overlapping() {
        let a = make_v6_set(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 10),
        );
        let b = make_v6_set(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 5),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 20),
        );
        let u = a.union(&b);
        assert_eq!(u.len(), 1);
        assert_eq!(u.ranges()[0].start(), Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));
        assert_eq!(u.ranges()[0].end(), Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 20));
    }
}
