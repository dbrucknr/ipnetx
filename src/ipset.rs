use crate::{
    interfaces::IpAddress,
    prefix::IpPrefix,
    range::IpRange,
    tools::range::normalize,
};

/// A builder for constructing a normalized [`IpSet`].
///
/// Ranges and prefixes may be added or removed in any order and any
/// combination. Additions and removals are accumulated separately and applied
/// together at [`build`](IpSetBuilder::build) time: the final set is
/// `union(adds) − union(removes)`, so removals always win regardless of the
/// order in which `add_*` and `remove_*` calls are interleaved. When
/// [`build`](IpSetBuilder::build) is called the builder normalizes both sides
/// and computes the difference in a single O((n + k) log(n + k)) pass.
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
    adds: Vec<IpRange<A>>,
    removes: Vec<IpRange<A>>,
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
        Self { adds: Vec::new(), removes: Vec::new() }
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
            self.adds.push(range);
        }
    }

    /// Queues an address range for removal.
    ///
    /// The removal is applied at [`build`](IpSetBuilder::build) time against the
    /// fully merged add-set. This is O(1) — removals are accumulated and
    /// processed in a single pass during `build()`.
    ///
    /// Invalid ranges (`start > end`) are silently ignored.
    pub fn remove_range(&mut self, range: IpRange<A>) {
        if range.is_valid() {
            self.removes.push(range);
        }
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

    /// Adds all addresses in `other` to this builder.
    ///
    /// Equivalent to calling [`add_range`](IpSetBuilder::add_range) for each
    /// range in `other`. Adjacent or overlapping spans are merged when
    /// [`build`](IpSetBuilder::build) is called.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::Ipv4Addr;
    /// use ipnetx::ipset::IpSetBuilder;
    /// use ipnetx::range::IpRange;
    ///
    /// let mut b1 = IpSetBuilder::<Ipv4Addr>::new();
    /// b1.add_range(IpRange::new(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 255)));
    /// let other = b1.build();
    ///
    /// let mut b2 = IpSetBuilder::<Ipv4Addr>::new();
    /// b2.add_ipset(&other);
    /// let set = b2.build();
    ///
    /// assert!(set.contains_ip(Ipv4Addr::new(10, 0, 0, 1)));
    /// ```
    pub fn add_ipset(&mut self, other: &IpSet<A>) {
        for range in &other.ranges {
            self.add_range(*range);
        }
    }

    /// Removes all addresses in `other` from this builder.
    ///
    /// Equivalent to calling [`remove_range`](IpSetBuilder::remove_range) for
    /// each range in `other`. Has no effect for addresses not currently in
    /// the builder.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::Ipv4Addr;
    /// use ipnetx::ipset::IpSetBuilder;
    /// use ipnetx::range::IpRange;
    ///
    /// let mut b1 = IpSetBuilder::<Ipv4Addr>::new();
    /// b1.add_range(IpRange::new(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 255)));
    ///
    /// let mut b2 = IpSetBuilder::<Ipv4Addr>::new();
    /// b2.add_range(IpRange::new(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 127)));
    /// let to_remove = b2.build();
    ///
    /// b1.remove_ipset(&to_remove);
    /// let set = b1.build();
    ///
    /// assert!(!set.contains_ip(Ipv4Addr::new(10, 0, 0, 1)));
    /// assert!(set.contains_ip(Ipv4Addr::new(10, 0, 0, 128)));
    /// ```
    pub fn remove_ipset(&mut self, other: &IpSet<A>) {
        for range in &other.ranges {
            self.remove_range(*range);
        }
    }

    /// Consumes the builder and returns a normalized [`IpSet`].
    ///
    /// Normalizes the accumulated adds and removes separately, then computes
    /// `union(adds) − union(removes)` in a single O((n + k) log(n + k)) pass.
    /// The resulting [`IpSet`] contains non-overlapping ranges in ascending order.
    #[must_use]
    pub fn build(self) -> IpSet<A> {
        let adds = IpSet::new(normalize(self.adds));
        if self.removes.is_empty() {
            return adds;
        }
        let removes = IpSet::new(normalize(self.removes));
        adds.difference(&removes)
    }
}

impl<A: IpAddress> FromIterator<IpRange<A>> for IpSetBuilder<A> {
    /// Constructs an [`IpSetBuilder`] from an iterator of [`IpRange`] values.
    ///
    /// This allows collecting a set of ranges directly into a builder using
    /// iterator adapters.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::Ipv4Addr;
    /// use ipnetx::ipset::IpSetBuilder;
    /// use ipnetx::range::IpRange;
    ///
    /// let ranges = vec![
    ///     IpRange::new(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 255)),
    ///     IpRange::new(Ipv4Addr::new(192, 168, 1, 0), Ipv4Addr::new(192, 168, 1, 255)),
    /// ];
    /// let builder: IpSetBuilder<Ipv4Addr> = ranges.into_iter().collect();
    /// let set = builder.build();
    /// assert_eq!(set.len(), 2);
    /// ```
    fn from_iter<I: IntoIterator<Item = IpRange<A>>>(iter: I) -> Self {
        let mut builder = IpSetBuilder::new();
        for range in iter {
            builder.add_range(range);
        }
        builder
    }
}

impl<A: IpAddress> FromIterator<IpPrefix<A>> for IpSetBuilder<A> {
    /// Constructs an [`IpSetBuilder`] from an iterator of [`IpPrefix`] values.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::Ipv4Addr;
    /// use ipnetx::ipset::IpSetBuilder;
    /// use ipnetx::prefix::IpPrefix;
    ///
    /// let prefixes = vec![
    ///     IpPrefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap(),
    ///     IpPrefix::new(Ipv4Addr::new(192, 168, 0, 0), 16).unwrap(),
    /// ];
    /// let builder: IpSetBuilder<Ipv4Addr> = prefixes.into_iter().collect();
    /// let set = builder.build();
    /// assert!(set.contains_ip(Ipv4Addr::new(10, 1, 2, 3)));
    /// assert!(set.contains_ip(Ipv4Addr::new(192, 168, 1, 100)));
    /// ```
    fn from_iter<I: IntoIterator<Item = IpPrefix<A>>>(iter: I) -> Self {
        let mut builder = IpSetBuilder::new();
        for prefix in iter {
            builder.add_prefix(prefix);
        }
        builder
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

    /// Returns the total number of IP addresses in the set.
    ///
    /// Each stored range contributes `end - start + 1` addresses.  The return
    /// type is `u128` so that an IPv6 set covering the entire address space
    /// (2¹²⁸ addresses) can be represented exactly.
    ///
    /// See [`len`](IpSet::len) to get the number of stored *ranges* instead.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::Ipv4Addr;
    /// use ipnetx::ipset::IpSetBuilder;
    /// use ipnetx::range::IpRange;
    ///
    /// let mut b = IpSetBuilder::<Ipv4Addr>::new();
    /// b.add_range(IpRange::new(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 9)));
    /// b.add_range(IpRange::new(Ipv4Addr::new(192, 168, 1, 0), Ipv4Addr::new(192, 168, 1, 4)));
    /// let set = b.build();
    ///
    /// assert_eq!(set.count(), 15); // 10 + 5
    /// ```
    #[must_use]
    pub fn count(&self) -> u128 {
        self.ranges
            .iter()
            .map(|r| r.end().to_u128() - r.start().to_u128() + 1)
            .sum()
    }

    /// Returns `true` if every address in `self` is also contained in `other`.
    ///
    /// An empty set is a subset of every set (including another empty set).
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::Ipv4Addr;
    /// use ipnetx::ipset::IpSetBuilder;
    /// use ipnetx::range::IpRange;
    ///
    /// let mut ba = IpSetBuilder::<Ipv4Addr>::new();
    /// ba.add_range(IpRange::new(Ipv4Addr::new(10, 0, 0, 50), Ipv4Addr::new(10, 0, 0, 100)));
    /// let a = ba.build();
    ///
    /// let mut bb = IpSetBuilder::<Ipv4Addr>::new();
    /// bb.add_range(IpRange::new(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 255)));
    /// let b = bb.build();
    ///
    /// assert!(a.is_subset_of(&b));   // a ⊆ b
    /// assert!(!b.is_subset_of(&a));  // b ⊄ a
    /// ```
    #[must_use]
    pub fn is_subset_of(&self, other: &IpSet<A>) -> bool {
        if self.is_empty() {
            return true;
        }
        if other.is_empty() {
            return false;
        }
        // Two-pointer walk — O(m + n), no allocation.
        // Both sets are sorted and non-overlapping. For each range in self,
        // find the single range in other that must fully cover it (a normalized
        // set has no adjacent ranges, so a span crossing a gap is never covered).
        let mut j = 0usize;
        for a in &self.ranges {
            let a_start = a.start().to_u128();
            let a_end = a.end().to_u128();
            // Skip other-ranges that end before this range starts.
            while j < other.ranges.len() && other.ranges[j].end().to_u128() < a_start {
                j += 1;
            }
            // No candidate, or candidate starts after a_start, or ends before a_end.
            if j >= other.ranges.len()
                || other.ranges[j].start().to_u128() > a_start
                || other.ranges[j].end().to_u128() < a_end
            {
                return false;
            }
        }
        true
    }

    /// Returns `true` if every address in `other` is also contained in `self`.
    ///
    /// Equivalent to `other.is_subset_of(self)`.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::Ipv4Addr;
    /// use ipnetx::ipset::IpSetBuilder;
    /// use ipnetx::range::IpRange;
    ///
    /// let mut ba = IpSetBuilder::<Ipv4Addr>::new();
    /// ba.add_range(IpRange::new(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 255)));
    /// let a = ba.build();
    ///
    /// let mut bb = IpSetBuilder::<Ipv4Addr>::new();
    /// bb.add_range(IpRange::new(Ipv4Addr::new(10, 0, 0, 50), Ipv4Addr::new(10, 0, 0, 100)));
    /// let b = bb.build();
    ///
    /// assert!(a.is_superset_of(&b));   // a ⊇ b
    /// assert!(!b.is_superset_of(&a));  // b ⊉ a
    /// ```
    #[must_use]
    pub fn is_superset_of(&self, other: &IpSet<A>) -> bool {
        other.is_subset_of(self)
    }

    /// Returns the number of distinct ranges in this set.
    ///
    /// This is the count of *ranges*, not individual IP addresses — a single
    /// range can span billions of addresses.  See [`count`](IpSet::count) for
    /// the total address cardinality.
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
    /// ```
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
        // Two-pointer walk — O(m + n).
        // Both sets are sorted and non-overlapping. We emit the portions of
        // self that are not covered by other.
        //
        // `cur` is the next address in the current self-range that we haven't
        // decided on yet. `j` advances through other.ranges and never resets.
        //
        // Overflow notes:
        //   `b_start - 1` is safe: we only compute it when `b_start > cur >= 0`,
        //     so b_start >= 1.
        //   `b_end + 1` is safe: we only compute it when `b_end < a_end`; since
        //     a_end is a valid address (≤ u128::MAX), b_end ≤ u128::MAX − 1.
        let mut result = Vec::new();
        let mut j = 0usize;

        for a in &self.ranges {
            let mut cur = a.start().to_u128();
            let a_end = a.end().to_u128();
            let mut consumed = false;

            // Skip removals that end before `cur` — they cannot affect this range.
            while j < other.ranges.len() && other.ranges[j].end().to_u128() < cur {
                j += 1;
            }

            while j < other.ranges.len() {
                let b_start = other.ranges[j].start().to_u128();
                let b_end = other.ranges[j].end().to_u128();

                if b_start > a_end {
                    // This and all later removals are past the current a-range.
                    break;
                }

                // Emit the gap between `cur` and the start of this removal.
                if b_start > cur {
                    result.push(IpRange::new(A::from_u128(cur), A::from_u128(b_start - 1)));
                }

                if b_end >= a_end {
                    // Removal reaches or passes the end of this a-range; no tail.
                    // Keep j here — b may still overlap the next a-range.
                    consumed = true;
                    break;
                }

                // Removal ends inside this a-range; advance past it and try the next.
                cur = b_end + 1;
                j += 1;
            }

            if !consumed {
                result.push(IpRange::new(A::from_u128(cur), A::from_u128(a_end)));
            }
        }

        IpSet::new(result)
    }

    /// Returns a new set containing every address that is in both `self` and
    /// `other` (A ∩ B).
    ///
    /// # Examples
    ///
    /// ```
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
        // Two-pointer merge — O(m + n).
        // Both sets are sorted and non-overlapping, so we walk them together.
        // When two ranges overlap their intersection is [max(start), min(end)].
        // We then advance whichever pointer ends first — it cannot contribute
        // further intersections with the other set's current range.
        // The output is produced in ascending order and is already non-overlapping,
        // so no normalize pass is needed.
        let mut result = Vec::new();
        let mut i = 0;
        let mut j = 0;

        while i < self.ranges.len() && j < other.ranges.len() {
            let a = &self.ranges[i];
            let b = &other.ranges[j];

            let a_start = a.start().to_u128();
            let a_end = a.end().to_u128();
            let b_start = b.start().to_u128();
            let b_end = b.end().to_u128();

            if a.overlaps(b) {
                let start = A::from_u128(a_start.max(b_start));
                let end = A::from_u128(a_end.min(b_end));
                result.push(IpRange::new(start, end));
            }

            // Advance the range that ends first; if tied, advance both.
            if a_end < b_end {
                i += 1;
            } else if b_end < a_end {
                j += 1;
            } else {
                i += 1;
                j += 1;
            }
        }

        IpSet::new(result)
    }

    /// Returns a new set containing every address that is *not* in `self`.
    ///
    /// For IPv4 the complement covers `0.0.0.0/0` minus `self`; for IPv6 it
    /// covers `::/0` minus `self`.
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
    /// let a = builder.build();
    ///
    /// let c = a.complement();
    /// assert!(!c.contains_ip(Ipv4Addr::new(10, 0, 0, 1)));     // was in a
    /// assert!(c.contains_ip(Ipv4Addr::new(192, 168, 1, 1)));    // not in a
    /// ```
    #[must_use]
    pub fn complement(&self) -> IpSet<A> {
        // MAX address for this address family:
        //   IPv4 → u32::MAX (low 32 bits of u128)
        //   IPv6 → u128::MAX
        // Computed as u128::MAX >> (128 - BITS).  When BITS == 128 the shift is
        // 0, giving u128::MAX.  When BITS == 32 the shift is 96, giving 0xFFFF_FFFF.
        let max_addr = u128::MAX >> (128u32.saturating_sub(A::BITS as u32));

        // Empty set — complement is the entire address space.
        if self.is_empty() {
            return IpSet::new(vec![IpRange::new(A::from_u128(0), A::from_u128(max_addr))]);
        }

        let mut result = Vec::new();

        // Head gap: [0 .. first.start - 1]
        let first_start = self.ranges[0].start().to_u128();
        if first_start > 0 {
            result.push(IpRange::new(A::from_u128(0), A::from_u128(first_start - 1)));
        }

        // Interior gaps: between every consecutive pair of stored ranges.
        // A normalised set is strictly non-overlapping and non-adjacent, so
        // next_start is always > prev_end + 1.
        for window in self.ranges.windows(2) {
            let prev_end = window[0].end().to_u128();
            let next_start = window[1].start().to_u128();
            result.push(IpRange::new(
                A::from_u128(prev_end + 1),
                A::from_u128(next_start - 1),
            ));
        }

        // Tail gap: [last.end + 1 .. MAX]
        let last_end = self.ranges.last().unwrap().end().to_u128();
        if last_end < max_addr {
            result.push(IpRange::new(
                A::from_u128(last_end + 1),
                A::from_u128(max_addr),
            ));
        }

        // Output is already sorted and non-overlapping — no normalize pass needed.
        IpSet::new(result)
    }
}

impl<'a, A: IpAddress> IntoIterator for &'a IpSet<A> {
    type Item = &'a IpRange<A>;
    type IntoIter = std::slice::Iter<'a, IpRange<A>>;

    fn into_iter(self) -> Self::IntoIter {
        self.ranges.iter()
    }
}

impl<A: IpAddress> IntoIterator for IpSet<A> {
    type Item = IpRange<A>;
    type IntoIter = std::vec::IntoIter<IpRange<A>>;

    fn into_iter(self) -> Self::IntoIter {
        self.ranges.into_iter()
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
        let b = make_v4_set(
            Ipv4Addr::new(192, 168, 1, 0),
            Ipv4Addr::new(192, 168, 1, 255),
        );
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
        let b = make_v4_set(
            Ipv4Addr::new(192, 168, 1, 0),
            Ipv4Addr::new(192, 168, 1, 255),
        );
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

    // --- Difference ---

    // cargo test ipset::tests::test_v4_difference_clips_left
    #[test]
    fn test_v4_difference_clips_left() {
        // Remove the first half of a range — right piece survives
        let a = make_v4_set(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 255));
        let b = make_v4_set(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 100));
        let d = a.difference(&b);
        assert_eq!(d.len(), 1);
        assert_eq!(d.ranges()[0].start(), Ipv4Addr::new(10, 0, 0, 101));
        assert_eq!(d.ranges()[0].end(), Ipv4Addr::new(10, 0, 0, 255));
    }

    // cargo test ipset::tests::test_v4_difference_clips_right
    #[test]
    fn test_v4_difference_clips_right() {
        // Remove the last portion of a range — left piece survives
        let a = make_v4_set(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 255));
        let b = make_v4_set(Ipv4Addr::new(10, 0, 0, 100), Ipv4Addr::new(10, 0, 0, 255));
        let d = a.difference(&b);
        assert_eq!(d.len(), 1);
        assert_eq!(d.ranges()[0].start(), Ipv4Addr::new(10, 0, 0, 0));
        assert_eq!(d.ranges()[0].end(), Ipv4Addr::new(10, 0, 0, 99));
    }

    // cargo test ipset::tests::test_v4_difference_punches_hole
    #[test]
    fn test_v4_difference_punches_hole() {
        // Remove from the middle — range splits into two
        let a = make_v4_set(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 255));
        let b = make_v4_set(Ipv4Addr::new(10, 0, 0, 50), Ipv4Addr::new(10, 0, 0, 100));
        let d = a.difference(&b);
        assert_eq!(d.len(), 2);
        assert_eq!(d.ranges()[0].start(), Ipv4Addr::new(10, 0, 0, 0));
        assert_eq!(d.ranges()[0].end(), Ipv4Addr::new(10, 0, 0, 49));
        assert_eq!(d.ranges()[1].start(), Ipv4Addr::new(10, 0, 0, 101));
        assert_eq!(d.ranges()[1].end(), Ipv4Addr::new(10, 0, 0, 255));
    }

    // cargo test ipset::tests::test_v4_difference_disjoint
    #[test]
    fn test_v4_difference_disjoint() {
        // b doesn't overlap a — result equals a unchanged
        let a = make_v4_set(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 255));
        let b = make_v4_set(
            Ipv4Addr::new(192, 168, 1, 0),
            Ipv4Addr::new(192, 168, 1, 255),
        );
        let d = a.difference(&b);
        assert_eq!(d, a);
    }

    // cargo test ipset::tests::test_v4_difference_equal
    #[test]
    fn test_v4_difference_equal() {
        // a minus itself is empty
        let a = make_v4_set(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 255));
        assert!(a.difference(&a).is_empty());
    }

    // cargo test ipset::tests::test_v4_difference_fully_covered
    #[test]
    fn test_v4_difference_fully_covered() {
        // b entirely contains a — result is empty
        let a = make_v4_set(Ipv4Addr::new(10, 0, 0, 50), Ipv4Addr::new(10, 0, 0, 100));
        let b = make_v4_set(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 255));
        assert!(a.difference(&b).is_empty());
    }

    // cargo test ipset::tests::test_v4_difference_with_empty
    #[test]
    fn test_v4_difference_with_empty() {
        // a minus empty is a; empty minus a is empty
        let a = make_v4_set(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 255));
        let empty = IpSetBuilder::<Ipv4Addr>::new().build();
        assert_eq!(a.difference(&empty), a);
        assert!(empty.difference(&a).is_empty());
    }

    // cargo test ipset::tests::test_v4_difference_not_symmetric
    #[test]
    fn test_v4_difference_not_symmetric() {
        // a ∖ b ≠ b ∖ a in general
        let a = make_v4_set(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 255));
        let b = make_v4_set(Ipv4Addr::new(10, 0, 0, 100), Ipv4Addr::new(10, 0, 1, 255));
        assert_ne!(a.difference(&b), b.difference(&a));
    }

    // cargo test ipset::tests::test_v4_difference_multi_range
    #[test]
    fn test_v4_difference_multi_range() {
        // a has two disjoint ranges; b overlaps only the first
        let mut ba = IpSetBuilder::<Ipv4Addr>::new();
        ba.add_range(IpRange::new(
            Ipv4Addr::new(10, 0, 0, 0),
            Ipv4Addr::new(10, 0, 0, 255),
        ));
        ba.add_range(IpRange::new(
            Ipv4Addr::new(192, 168, 1, 0),
            Ipv4Addr::new(192, 168, 1, 255),
        ));
        let a = ba.build();
        let b = make_v4_set(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 255));
        let d = a.difference(&b);
        // Only the 192.168.1.0/24 range survives
        assert_eq!(d.len(), 1);
        assert_eq!(d.ranges()[0].start(), Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(d.ranges()[0].end(), Ipv4Addr::new(192, 168, 1, 255));
    }

    // cargo test ipset::tests::test_v6_difference_punches_hole
    #[test]
    fn test_v6_difference_punches_hole() {
        let a = make_v6_set(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 255),
        );
        let b = make_v6_set(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 50),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 100),
        );
        let d = a.difference(&b);
        assert_eq!(d.len(), 2);
        assert_eq!(d.ranges()[0].start(), Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));
        assert_eq!(d.ranges()[0].end(), Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 49));
        assert_eq!(
            d.ranges()[1].start(),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 101)
        );
        assert_eq!(d.ranges()[1].end(), Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 255));
    }

    // cargo test ipset::tests::test_v6_difference_disjoint
    #[test]
    fn test_v6_difference_disjoint() {
        let a = make_v6_set(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xff),
        );
        let b = make_v6_set(
            Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 0),
            Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 0xff),
        );
        assert_eq!(a.difference(&b), a);
    }

    // --- Intersection ---

    // cargo test ipset::tests::test_v4_intersection_subset
    #[test]
    fn test_v4_intersection_subset() {
        // b ⊂ a — intersection equals b
        let a = make_v4_set(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 255));
        let b = make_v4_set(Ipv4Addr::new(10, 0, 0, 50), Ipv4Addr::new(10, 0, 0, 100));
        assert_eq!(a.intersection(&b), b);
    }

    // cargo test ipset::tests::test_v4_intersection_partial_overlap
    #[test]
    fn test_v4_intersection_partial_overlap() {
        // Ranges cross — only the overlapping portion is kept
        let a = make_v4_set(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 150));
        let b = make_v4_set(Ipv4Addr::new(10, 0, 0, 100), Ipv4Addr::new(10, 0, 0, 255));
        let inter = a.intersection(&b);
        assert_eq!(inter.len(), 1);
        assert_eq!(inter.ranges()[0].start(), Ipv4Addr::new(10, 0, 0, 100));
        assert_eq!(inter.ranges()[0].end(), Ipv4Addr::new(10, 0, 0, 150));
    }

    // cargo test ipset::tests::test_v4_intersection_disjoint
    #[test]
    fn test_v4_intersection_disjoint() {
        // No shared addresses — result is empty
        let a = make_v4_set(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 255));
        let b = make_v4_set(
            Ipv4Addr::new(192, 168, 1, 0),
            Ipv4Addr::new(192, 168, 1, 255),
        );
        assert!(a.intersection(&b).is_empty());
    }

    // cargo test ipset::tests::test_v4_intersection_equal
    #[test]
    fn test_v4_intersection_equal() {
        // a ∩ a == a
        let a = make_v4_set(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 255));
        assert_eq!(a.intersection(&a), a);
    }

    // cargo test ipset::tests::test_v4_intersection_with_empty
    #[test]
    fn test_v4_intersection_with_empty() {
        // a ∩ ∅ == ∅
        let a = make_v4_set(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 255));
        let empty = IpSetBuilder::<Ipv4Addr>::new().build();
        assert!(a.intersection(&empty).is_empty());
        assert!(empty.intersection(&a).is_empty());
    }

    // cargo test ipset::tests::test_v4_intersection_symmetric
    #[test]
    fn test_v4_intersection_symmetric() {
        // a ∩ b == b ∩ a
        let a = make_v4_set(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 200));
        let b = make_v4_set(Ipv4Addr::new(10, 0, 0, 100), Ipv4Addr::new(10, 0, 0, 255));
        assert_eq!(a.intersection(&b), b.intersection(&a));
    }

    // cargo test ipset::tests::test_v4_intersection_multiple_ranges
    #[test]
    fn test_v4_intersection_multiple_ranges() {
        // Both sets have multiple ranges — two-pointer correctly pairs them up
        // a: [10.0.0.0..10.0.0.100] and [192.168.0.0..192.168.0.255]
        // b: [10.0.0.50..10.0.0.200] and [192.168.0.100..192.168.1.50]
        // expected: [10.0.0.50..10.0.0.100] and [192.168.0.100..192.168.0.255]
        let mut ba = IpSetBuilder::<Ipv4Addr>::new();
        ba.add_range(IpRange::new(
            Ipv4Addr::new(10, 0, 0, 0),
            Ipv4Addr::new(10, 0, 0, 100),
        ));
        ba.add_range(IpRange::new(
            Ipv4Addr::new(192, 168, 0, 0),
            Ipv4Addr::new(192, 168, 0, 255),
        ));
        let a = ba.build();

        let mut bb = IpSetBuilder::<Ipv4Addr>::new();
        bb.add_range(IpRange::new(
            Ipv4Addr::new(10, 0, 0, 50),
            Ipv4Addr::new(10, 0, 0, 200),
        ));
        bb.add_range(IpRange::new(
            Ipv4Addr::new(192, 168, 0, 100),
            Ipv4Addr::new(192, 168, 1, 50),
        ));
        let b = bb.build();

        let inter = a.intersection(&b);
        assert_eq!(inter.len(), 2);
        assert_eq!(inter.ranges()[0].start(), Ipv4Addr::new(10, 0, 0, 50));
        assert_eq!(inter.ranges()[0].end(), Ipv4Addr::new(10, 0, 0, 100));
        assert_eq!(inter.ranges()[1].start(), Ipv4Addr::new(192, 168, 0, 100));
        assert_eq!(inter.ranges()[1].end(), Ipv4Addr::new(192, 168, 0, 255));
    }

    // cargo test ipset::tests::test_v4_intersection_tied_ends
    #[test]
    fn test_v4_intersection_tied_ends() {
        // Two ranges that end at exactly the same address — both pointers advance
        // a: [10.0.0.0..10.0.0.255] and [10.0.1.0..10.0.1.255]
        // b: [10.0.0.100..10.0.0.255] and [10.0.1.100..10.0.1.255]
        let mut ba = IpSetBuilder::<Ipv4Addr>::new();
        ba.add_range(IpRange::new(
            Ipv4Addr::new(10, 0, 0, 0),
            Ipv4Addr::new(10, 0, 0, 255),
        ));
        ba.add_range(IpRange::new(
            Ipv4Addr::new(10, 0, 1, 0),
            Ipv4Addr::new(10, 0, 1, 255),
        ));
        let a = ba.build();

        let mut bb = IpSetBuilder::<Ipv4Addr>::new();
        bb.add_range(IpRange::new(
            Ipv4Addr::new(10, 0, 0, 100),
            Ipv4Addr::new(10, 0, 0, 255),
        ));
        bb.add_range(IpRange::new(
            Ipv4Addr::new(10, 0, 1, 100),
            Ipv4Addr::new(10, 0, 1, 255),
        ));
        let b = bb.build();

        let inter = a.intersection(&b);
        assert_eq!(inter.len(), 2);
        assert_eq!(inter.ranges()[0].start(), Ipv4Addr::new(10, 0, 0, 100));
        assert_eq!(inter.ranges()[0].end(), Ipv4Addr::new(10, 0, 0, 255));
        assert_eq!(inter.ranges()[1].start(), Ipv4Addr::new(10, 0, 1, 100));
        assert_eq!(inter.ranges()[1].end(), Ipv4Addr::new(10, 0, 1, 255));
    }

    // cargo test ipset::tests::test_v6_intersection_subset
    #[test]
    fn test_v6_intersection_subset() {
        let a = make_v6_set(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xff),
        );
        let b = make_v6_set(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x40),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x80),
        );
        assert_eq!(a.intersection(&b), b);
    }

    // cargo test ipset::tests::test_v6_intersection_disjoint
    #[test]
    fn test_v6_intersection_disjoint() {
        let a = make_v6_set(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xff),
        );
        let b = make_v6_set(
            Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 0),
            Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 0xff),
        );
        assert!(a.intersection(&b).is_empty());
    }

    // --- Complement ---

    // cargo test ipset::tests::test_v4_complement_empty
    #[test]
    fn test_v4_complement_empty() {
        // complement(∅) == full address space
        let empty = IpSetBuilder::<Ipv4Addr>::new().build();
        let c = empty.complement();
        assert_eq!(c.len(), 1);
        assert_eq!(c.ranges()[0].start(), Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(c.ranges()[0].end(), Ipv4Addr::new(255, 255, 255, 255));
    }

    // cargo test ipset::tests::test_v4_complement_full_space
    #[test]
    fn test_v4_complement_full_space() {
        // complement(full) == ∅
        let mut b = IpSetBuilder::<Ipv4Addr>::new();
        b.add_range(IpRange::new(
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::new(255, 255, 255, 255),
        ));
        let full = b.build();
        assert!(full.complement().is_empty());
    }

    // cargo test ipset::tests::test_v4_complement_middle_range
    #[test]
    fn test_v4_complement_middle_range() {
        // complement([10.0.0.0..10.0.0.255]) == [0.0.0.0..9.255.255.255, 10.0.1.0..255.255.255.255]
        let a = make_v4_set(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 255));
        let c = a.complement();
        assert_eq!(c.len(), 2);
        assert_eq!(c.ranges()[0].start(), Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(c.ranges()[0].end(), Ipv4Addr::new(9, 255, 255, 255));
        assert_eq!(c.ranges()[1].start(), Ipv4Addr::new(10, 0, 1, 0));
        assert_eq!(c.ranges()[1].end(), Ipv4Addr::new(255, 255, 255, 255));
    }

    // cargo test ipset::tests::test_v4_complement_starts_at_zero
    #[test]
    fn test_v4_complement_starts_at_zero() {
        // Set starts at 0 — no head gap
        let a = make_v4_set(Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 255));
        let c = a.complement();
        assert_eq!(c.len(), 1);
        assert_eq!(c.ranges()[0].start(), Ipv4Addr::new(10, 0, 1, 0));
        assert_eq!(c.ranges()[0].end(), Ipv4Addr::new(255, 255, 255, 255));
    }

    // cargo test ipset::tests::test_v4_complement_ends_at_max
    #[test]
    fn test_v4_complement_ends_at_max() {
        // Set ends at 255.255.255.255 — no tail gap
        let a = make_v4_set(
            Ipv4Addr::new(10, 0, 0, 0),
            Ipv4Addr::new(255, 255, 255, 255),
        );
        let c = a.complement();
        assert_eq!(c.len(), 1);
        assert_eq!(c.ranges()[0].start(), Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(c.ranges()[0].end(), Ipv4Addr::new(9, 255, 255, 255));
    }

    // cargo test ipset::tests::test_v4_complement_double
    #[test]
    fn test_v4_complement_double() {
        // complement(complement(a)) == a
        let a = make_v4_set(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 255));
        assert_eq!(a.complement().complement(), a);
    }

    // cargo test ipset::tests::test_v4_complement_multiple_ranges
    #[test]
    fn test_v4_complement_multiple_ranges() {
        // Two stored ranges — complement fills head, interior gap, and tail.
        // a: [10.0.0.0..10.0.0.255] and [192.168.0.0..192.168.0.255]
        // complement: [0.0.0.0..9.255.255.255], [10.0.1.0..192.167.255.255], [192.168.1.0..255.255.255.255]
        let mut ba = IpSetBuilder::<Ipv4Addr>::new();
        ba.add_range(IpRange::new(
            Ipv4Addr::new(10, 0, 0, 0),
            Ipv4Addr::new(10, 0, 0, 255),
        ));
        ba.add_range(IpRange::new(
            Ipv4Addr::new(192, 168, 0, 0),
            Ipv4Addr::new(192, 168, 0, 255),
        ));
        let a = ba.build();

        let c = a.complement();
        assert_eq!(c.len(), 3);
        assert_eq!(c.ranges()[0].start(), Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(c.ranges()[0].end(), Ipv4Addr::new(9, 255, 255, 255));
        assert_eq!(c.ranges()[1].start(), Ipv4Addr::new(10, 0, 1, 0));
        assert_eq!(c.ranges()[1].end(), Ipv4Addr::new(192, 167, 255, 255));
        assert_eq!(c.ranges()[2].start(), Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(c.ranges()[2].end(), Ipv4Addr::new(255, 255, 255, 255));
    }

    // cargo test ipset::tests::test_v4_complement_union_is_full
    #[test]
    fn test_v4_complement_union_is_full() {
        // a ∪ complement(a) == full address space
        let a = make_v4_set(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 255));
        let c = a.complement();
        let full = a.union(&c);
        assert_eq!(full.len(), 1);
        assert_eq!(full.ranges()[0].start(), Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(full.ranges()[0].end(), Ipv4Addr::new(255, 255, 255, 255));
    }

    // cargo test ipset::tests::test_v4_complement_intersection_is_empty
    #[test]
    fn test_v4_complement_intersection_is_empty() {
        // a ∩ complement(a) == ∅
        let a = make_v4_set(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 255));
        assert!(a.intersection(&a.complement()).is_empty());
    }

    // cargo test ipset::tests::test_v6_complement_empty
    #[test]
    fn test_v6_complement_empty() {
        // complement(∅) == full IPv6 address space (single range)
        let empty = IpSetBuilder::<Ipv6Addr>::new().build();
        let c = empty.complement();
        assert_eq!(c.len(), 1);
        assert_eq!(c.ranges()[0].start(), Ipv6Addr::from(0u128));
        assert_eq!(c.ranges()[0].end(), Ipv6Addr::from(u128::MAX));
    }

    // cargo test ipset::tests::test_v6_complement_double
    #[test]
    fn test_v6_complement_double() {
        // complement(complement(a)) == a for IPv6
        let a = make_v6_set(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xff),
        );
        assert_eq!(a.complement().complement(), a);
    }

    // cargo test ipset::tests::test_v6_complement_middle_range
    #[test]
    fn test_v6_complement_middle_range() {
        // A mid-range produces exactly two complement ranges (head + tail)
        let start = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10);
        let end = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x20);
        let a = make_v6_set(start, end);
        let c = a.complement();
        assert_eq!(c.len(), 2);
        assert_eq!(c.ranges()[0].start(), Ipv6Addr::from(0u128));
        assert_eq!(c.ranges()[0].end(), Ipv6Addr::from(start.to_bits() - 1));
        assert_eq!(c.ranges()[1].start(), Ipv6Addr::from(end.to_bits() + 1));
        assert_eq!(c.ranges()[1].end(), Ipv6Addr::from(u128::MAX));
    }

    // --- Count ---

    // cargo test ipset::tests::test_v4_count_single_range
    #[test]
    fn test_v4_count_single_range() {
        // 10.0.0.0..10.0.0.9 is 10 addresses
        let a = make_v4_set(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 9));
        assert_eq!(a.count(), 10);
    }

    // cargo test ipset::tests::test_v4_count_empty
    #[test]
    fn test_v4_count_empty() {
        let empty = IpSetBuilder::<Ipv4Addr>::new().build();
        assert_eq!(empty.count(), 0);
    }

    // cargo test ipset::tests::test_v4_count_multiple_ranges
    #[test]
    fn test_v4_count_multiple_ranges() {
        // 10 + 5 = 15
        let mut b = IpSetBuilder::<Ipv4Addr>::new();
        b.add_range(IpRange::new(
            Ipv4Addr::new(10, 0, 0, 0),
            Ipv4Addr::new(10, 0, 0, 9),
        ));
        b.add_range(IpRange::new(
            Ipv4Addr::new(192, 168, 1, 0),
            Ipv4Addr::new(192, 168, 1, 4),
        ));
        assert_eq!(b.build().count(), 15);
    }

    // cargo test ipset::tests::test_v4_count_single_ip
    #[test]
    fn test_v4_count_single_ip() {
        let mut b = IpSetBuilder::<Ipv4Addr>::new();
        b.add_ip(Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(b.build().count(), 1);
    }

    // cargo test ipset::tests::test_v4_count_full_space
    #[test]
    fn test_v4_count_full_space() {
        let mut b = IpSetBuilder::<Ipv4Addr>::new();
        b.add_range(IpRange::new(
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::new(255, 255, 255, 255),
        ));
        assert_eq!(b.build().count(), u32::MAX as u128 + 1);
    }

    // cargo test ipset::tests::test_v6_count_single_ip
    #[test]
    fn test_v6_count_single_ip() {
        let mut b = IpSetBuilder::<Ipv6Addr>::new();
        b.add_ip(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        assert_eq!(b.build().count(), 1);
    }

    // --- is_subset_of / is_superset_of ---

    // cargo test ipset::tests::test_v4_subset_proper
    #[test]
    fn test_v4_subset_proper() {
        // a ⊂ b
        let a = make_v4_set(Ipv4Addr::new(10, 0, 0, 50), Ipv4Addr::new(10, 0, 0, 100));
        let b = make_v4_set(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 255));
        assert!(a.is_subset_of(&b));
        assert!(!b.is_subset_of(&a));
    }

    // cargo test ipset::tests::test_v4_superset_proper
    #[test]
    fn test_v4_superset_proper() {
        let a = make_v4_set(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 255));
        let b = make_v4_set(Ipv4Addr::new(10, 0, 0, 50), Ipv4Addr::new(10, 0, 0, 100));
        assert!(a.is_superset_of(&b));
        assert!(!b.is_superset_of(&a));
    }

    // cargo test ipset::tests::test_v4_subset_equal
    #[test]
    fn test_v4_subset_equal() {
        // a ⊆ a
        let a = make_v4_set(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 255));
        assert!(a.is_subset_of(&a));
        assert!(a.is_superset_of(&a));
    }

    // cargo test ipset::tests::test_v4_subset_disjoint
    #[test]
    fn test_v4_subset_disjoint() {
        // Disjoint sets — neither is a subset of the other
        let a = make_v4_set(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 255));
        let b = make_v4_set(
            Ipv4Addr::new(192, 168, 1, 0),
            Ipv4Addr::new(192, 168, 1, 255),
        );
        assert!(!a.is_subset_of(&b));
        assert!(!b.is_subset_of(&a));
    }

    // cargo test ipset::tests::test_v4_empty_subset_of_any
    #[test]
    fn test_v4_empty_subset_of_any() {
        // ∅ ⊆ everything
        let empty = IpSetBuilder::<Ipv4Addr>::new().build();
        let a = make_v4_set(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 255));
        assert!(empty.is_subset_of(&a));
        assert!(empty.is_subset_of(&empty));
        assert!(a.is_superset_of(&empty));
    }

    // --- FromIterator ---

    // cargo test ipset::tests::test_v4_from_iter_ranges
    #[test]
    fn test_v4_from_iter_ranges() {
        let ranges = vec![
            IpRange::new(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 255)),
            IpRange::new(
                Ipv4Addr::new(192, 168, 1, 0),
                Ipv4Addr::new(192, 168, 1, 255),
            ),
        ];
        let builder: IpSetBuilder<Ipv4Addr> = ranges.into_iter().collect();
        let set = builder.build();
        assert_eq!(set.len(), 2);
        assert!(set.contains_ip(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(set.contains_ip(Ipv4Addr::new(192, 168, 1, 1)));
    }

    // cargo test ipset::tests::test_v4_from_iter_prefixes
    #[test]
    fn test_v4_from_iter_prefixes() {
        let prefixes = vec![
            IpPrefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap(),
            IpPrefix::new(Ipv4Addr::new(192, 168, 0, 0), 16).unwrap(),
        ];
        let builder: IpSetBuilder<Ipv4Addr> = prefixes.into_iter().collect();
        let set = builder.build();
        assert!(set.contains_ip(Ipv4Addr::new(10, 1, 2, 3)));
        assert!(set.contains_ip(Ipv4Addr::new(192, 168, 1, 100)));
        assert!(!set.contains_ip(Ipv4Addr::new(172, 16, 0, 1)));
    }

    // cargo test ipset::tests::test_v4_from_iter_ranges_merges_adjacent
    #[test]
    fn test_v4_from_iter_ranges_merges_adjacent() {
        // Adjacent ranges should be merged during build
        let ranges = vec![
            IpRange::new(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 127)),
            IpRange::new(Ipv4Addr::new(10, 0, 0, 128), Ipv4Addr::new(10, 0, 0, 255)),
        ];
        let set: IpSetBuilder<Ipv4Addr> = ranges.into_iter().collect();
        let set = set.build();
        assert_eq!(set.len(), 1);
        assert_eq!(set.ranges()[0].start(), Ipv4Addr::new(10, 0, 0, 0));
        assert_eq!(set.ranges()[0].end(), Ipv4Addr::new(10, 0, 0, 255));
    }

    // cargo test ipset::tests::test_v6_from_iter_ranges
    #[test]
    fn test_v6_from_iter_ranges() {
        let ranges = vec![IpRange::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xff),
        )];
        let builder: IpSetBuilder<Ipv6Addr> = ranges.into_iter().collect();
        let set = builder.build();
        assert_eq!(set.len(), 1);
        assert!(set.contains_ip(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x42)));
    }

    // --- IntoIterator ---

    // cargo test ipset::tests::test_v4_into_iter_ref_yields_ranges
    #[test]
    fn test_v4_into_iter_ref_yields_ranges() {
        let set = make_v4_set(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 255));
        let collected: Vec<_> = (&set).into_iter().collect();
        assert_eq!(collected.len(), 1);
        assert_eq!(*collected[0], IpRange::new(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 255)));
    }

    // cargo test ipset::tests::test_v4_for_loop_ref
    #[test]
    fn test_v4_for_loop_ref() {
        let set = make_v4_set(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 255));
        let mut count = 0;
        for _range in &set {
            count += 1;
        }
        assert_eq!(count, 1);
    }

    // cargo test ipset::tests::test_v4_into_iter_consuming_yields_ranges
    #[test]
    fn test_v4_into_iter_consuming_yields_ranges() {
        let set = make_v4_set(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 255));
        let collected: Vec<IpRange<Ipv4Addr>> = set.into_iter().collect();
        assert_eq!(collected.len(), 1);
        assert_eq!(collected[0], IpRange::new(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 255)));
    }

    // cargo test ipset::tests::test_v4_into_iter_empty
    #[test]
    fn test_v4_into_iter_empty() {
        let set = IpSetBuilder::<Ipv4Addr>::new().build();
        assert_eq!((&set).into_iter().count(), 0);
        assert_eq!(set.into_iter().count(), 0);
    }

    // cargo test ipset::tests::test_v4_into_iter_multi_range
    #[test]
    fn test_v4_into_iter_multi_range() {
        let mut builder = IpSetBuilder::<Ipv4Addr>::new();
        builder.add_range(IpRange::new(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 10)));
        builder.add_range(IpRange::new(Ipv4Addr::new(192, 168, 1, 0), Ipv4Addr::new(192, 168, 1, 10)));
        let set = builder.build();
        let starts: Vec<Ipv4Addr> = (&set).into_iter().map(|r| r.start()).collect();
        assert_eq!(starts, vec![Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(192, 168, 1, 0)]);
    }

    // cargo test ipset::tests::test_v4_iter_adapter_chain
    #[test]
    fn test_v4_iter_adapter_chain() {
        // Verifies that &IpSet chains with standard iterator adapters.
        let mut builder = IpSetBuilder::<Ipv4Addr>::new();
        builder.add_range(IpRange::new(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 10)));
        builder.add_range(IpRange::new(Ipv4Addr::new(10, 0, 1, 0), Ipv4Addr::new(10, 0, 1, 5)));
        builder.add_range(IpRange::new(Ipv4Addr::new(192, 168, 1, 0), Ipv4Addr::new(192, 168, 1, 255)));
        let set = builder.build();
        let count = (&set).into_iter().filter(|r| r.start().octets()[0] == 10).count();
        assert_eq!(count, 2);
    }

    // cargo test ipset::tests::test_v6_into_iter_ref
    #[test]
    fn test_v6_into_iter_ref() {
        let range = IpRange::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xff),
        );
        let mut builder = IpSetBuilder::<Ipv6Addr>::new();
        builder.add_range(range);
        let set = builder.build();
        let collected: Vec<_> = (&set).into_iter().collect();
        assert_eq!(collected.len(), 1);
        assert_eq!(*collected[0], range);
    }

    // --- add_ipset / remove_ipset ---

    // cargo test ipset::tests::test_v4_add_ipset_disjoint
    #[test]
    fn test_v4_add_ipset_disjoint() {
        // Adding a disjoint set — both ranges survive unchanged
        let other = make_v4_set(
            Ipv4Addr::new(192, 168, 1, 0),
            Ipv4Addr::new(192, 168, 1, 255),
        );
        let mut builder = IpSetBuilder::<Ipv4Addr>::new();
        builder.add_range(IpRange::new(
            Ipv4Addr::new(10, 0, 0, 0),
            Ipv4Addr::new(10, 0, 0, 255),
        ));
        builder.add_ipset(&other);
        let set = builder.build();
        assert_eq!(set.len(), 2);
        assert!(set.contains_ip(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(set.contains_ip(Ipv4Addr::new(192, 168, 1, 1)));
    }

    // cargo test ipset::tests::test_v4_add_ipset_overlapping
    #[test]
    fn test_v4_add_ipset_overlapping() {
        // Adding an overlapping set — ranges merge into one
        let other = make_v4_set(Ipv4Addr::new(10, 0, 0, 100), Ipv4Addr::new(10, 0, 1, 255));
        let mut builder = IpSetBuilder::<Ipv4Addr>::new();
        builder.add_range(IpRange::new(
            Ipv4Addr::new(10, 0, 0, 0),
            Ipv4Addr::new(10, 0, 0, 200),
        ));
        builder.add_ipset(&other);
        let set = builder.build();
        assert_eq!(set.len(), 1);
        assert_eq!(set.ranges()[0].start(), Ipv4Addr::new(10, 0, 0, 0));
        assert_eq!(set.ranges()[0].end(), Ipv4Addr::new(10, 0, 1, 255));
    }

    // cargo test ipset::tests::test_v4_add_ipset_empty
    #[test]
    fn test_v4_add_ipset_empty() {
        // Adding an empty set is a no-op
        let empty = IpSetBuilder::<Ipv4Addr>::new().build();
        let mut builder = IpSetBuilder::<Ipv4Addr>::new();
        builder.add_range(IpRange::new(
            Ipv4Addr::new(10, 0, 0, 0),
            Ipv4Addr::new(10, 0, 0, 255),
        ));
        builder.add_ipset(&empty);
        let set = builder.build();
        assert_eq!(set.len(), 1);
    }

    // cargo test ipset::tests::test_v6_add_ipset
    #[test]
    fn test_v6_add_ipset() {
        let other = make_v6_set(
            Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 0),
            Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 0xff),
        );
        let mut builder = IpSetBuilder::<Ipv6Addr>::new();
        builder.add_range(IpRange::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xff),
        ));
        builder.add_ipset(&other);
        let set = builder.build();
        assert_eq!(set.len(), 2);
        assert!(set.contains_ip(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)));
        assert!(set.contains_ip(Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 1)));
    }

    // cargo test ipset::tests::test_v4_remove_ipset_exact
    #[test]
    fn test_v4_remove_ipset_exact() {
        // Removing a set that exactly matches stored ranges — result is empty
        let to_remove = make_v4_set(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 255));
        let mut builder = IpSetBuilder::<Ipv4Addr>::new();
        builder.add_range(IpRange::new(
            Ipv4Addr::new(10, 0, 0, 0),
            Ipv4Addr::new(10, 0, 0, 255),
        ));
        builder.remove_ipset(&to_remove);
        assert!(builder.build().is_empty());
    }

    // cargo test ipset::tests::test_v4_remove_ipset_partial
    #[test]
    fn test_v4_remove_ipset_partial() {
        // Removing a set that covers the first half — right piece survives
        let to_remove = make_v4_set(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 127));
        let mut builder = IpSetBuilder::<Ipv4Addr>::new();
        builder.add_range(IpRange::new(
            Ipv4Addr::new(10, 0, 0, 0),
            Ipv4Addr::new(10, 0, 0, 255),
        ));
        builder.remove_ipset(&to_remove);
        let set = builder.build();
        assert_eq!(set.len(), 1);
        assert_eq!(set.ranges()[0].start(), Ipv4Addr::new(10, 0, 0, 128));
        assert_eq!(set.ranges()[0].end(), Ipv4Addr::new(10, 0, 0, 255));
    }

    // cargo test ipset::tests::test_v4_remove_ipset_disjoint
    #[test]
    fn test_v4_remove_ipset_disjoint() {
        // Removing a set that doesn't overlap — stored ranges unchanged
        let to_remove = make_v4_set(
            Ipv4Addr::new(192, 168, 1, 0),
            Ipv4Addr::new(192, 168, 1, 255),
        );
        let mut builder = IpSetBuilder::<Ipv4Addr>::new();
        builder.add_range(IpRange::new(
            Ipv4Addr::new(10, 0, 0, 0),
            Ipv4Addr::new(10, 0, 0, 255),
        ));
        builder.remove_ipset(&to_remove);
        let set = builder.build();
        assert_eq!(set.len(), 1);
        assert_eq!(set.ranges()[0].start(), Ipv4Addr::new(10, 0, 0, 0));
        assert_eq!(set.ranges()[0].end(), Ipv4Addr::new(10, 0, 0, 255));
    }

    // cargo test ipset::tests::test_v4_remove_ipset_empty
    #[test]
    fn test_v4_remove_ipset_empty() {
        // Removing an empty set is a no-op
        let empty = IpSetBuilder::<Ipv4Addr>::new().build();
        let mut builder = IpSetBuilder::<Ipv4Addr>::new();
        builder.add_range(IpRange::new(
            Ipv4Addr::new(10, 0, 0, 0),
            Ipv4Addr::new(10, 0, 0, 255),
        ));
        builder.remove_ipset(&empty);
        let set = builder.build();
        assert_eq!(set.len(), 1);
    }

    // cargo test ipset::tests::test_v4_remove_ipset_multi_range
    #[test]
    fn test_v4_remove_ipset_multi_range() {
        // Removing a multi-range set punches multiple holes
        let mut rb = IpSetBuilder::<Ipv4Addr>::new();
        rb.add_range(IpRange::new(
            Ipv4Addr::new(10, 0, 0, 10),
            Ipv4Addr::new(10, 0, 0, 20),
        ));
        rb.add_range(IpRange::new(
            Ipv4Addr::new(10, 0, 0, 50),
            Ipv4Addr::new(10, 0, 0, 60),
        ));
        let to_remove = rb.build();

        let mut builder = IpSetBuilder::<Ipv4Addr>::new();
        builder.add_range(IpRange::new(
            Ipv4Addr::new(10, 0, 0, 0),
            Ipv4Addr::new(10, 0, 0, 255),
        ));
        builder.remove_ipset(&to_remove);
        let set = builder.build();
        assert_eq!(set.len(), 3);
        assert_eq!(set.ranges()[0].start(), Ipv4Addr::new(10, 0, 0, 0));
        assert_eq!(set.ranges()[0].end(), Ipv4Addr::new(10, 0, 0, 9));
        assert_eq!(set.ranges()[1].start(), Ipv4Addr::new(10, 0, 0, 21));
        assert_eq!(set.ranges()[1].end(), Ipv4Addr::new(10, 0, 0, 49));
        assert_eq!(set.ranges()[2].start(), Ipv4Addr::new(10, 0, 0, 61));
        assert_eq!(set.ranges()[2].end(), Ipv4Addr::new(10, 0, 0, 255));
    }
}
