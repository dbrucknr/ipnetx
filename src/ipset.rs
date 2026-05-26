use crate::{interfaces::IpAddress, prefix::IpPrefix, range::IpRange};

pub struct IpSetBuilder<A: IpAddress> {
    ranges: Vec<IpRange<A>>,
}

impl<A: IpAddress> IpSetBuilder<A> {
    pub fn new() -> Self {
        Self { ranges: Vec::new() }
    }

    pub fn add_range(&mut self, range: IpRange<A>) {
        if range.is_valid() {
            self.ranges.push(range);
        }
    }

    pub fn add_prefix(&mut self, prefix: IpPrefix<A>) {
        let range = prefix.to_range();
        self.add_range(range);
    }

    pub fn build(mut self) -> IpSet<A> {
        // Sort by Address
        self.ranges.sort_by_key(|range| range.start().to_u128());
        // Merge overlapping ranges
        let mut merged = Vec::<IpRange<A>>::new();
        for range in self.ranges {
            match merged.last_mut() {
                Some(last) if range.start().to_u128() <= last.end().to_u128().saturating_add(1) => {
                    // Extend if this range reaches further than the last merged range
                    if range.end().to_u128() > last.end().to_u128() {
                        *last = IpRange::new(last.start(), range.end());
                    }
                }
                _ => {
                    // Otherwise, add the new range
                    merged.push(range);
                }
            }
        }
        IpSet::new(merged)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpSet<A: IpAddress> {
    ranges: Vec<IpRange<A>>,
}

impl<A: IpAddress> IpSet<A> {
    fn new(ranges: Vec<IpRange<A>>) -> Self {
        Self { ranges }
    }

    pub fn ranges(&self) -> &[IpRange<A>] {
        &self.ranges
    }

    // This may be a very long vector...
    // NOTE: Must be normalized (sorted) first!
    pub fn prefixes(&self) -> Vec<IpPrefix<A>> {
        let mut prefixes = Vec::<IpPrefix<A>>::new();
        for range in &self.ranges {
            prefixes.extend(range.prefixes());
        }
        prefixes
    }

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

    // Answers the question:  "is this range entirely enclosed by the set?"
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

    pub fn overlaps_ip_set(&self, other: &IpSet<A>) -> bool {
        todo!()
    }

    pub fn len(&self) -> usize {
        self.ranges.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }
}
