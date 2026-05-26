use crate::{interfaces::IpAddress, range::IpRange};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpSet<A: IpAddress> {
    ranges: Vec<IpRange<A>>,
}

impl<A: IpAddress> IpSet<A> {
    pub fn new(ranges: Vec<IpRange<A>>) -> Self {
        Self { ranges }
    }

    pub fn prefixes(&self) -> &[IpRange<A>] {
        todo!()
    }

    pub fn contains_ip(&self, ip: A) -> bool {
        todo!()
    }

    // May necessitate the coveredBy method in Go's netipx IPRange
    pub fn contains_range(&self, range: IpRange<A>) -> bool {
        todo!()
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
