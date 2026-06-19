use crate::{interfaces::IpAddress, range::IpRange};

pub(crate) fn normalize<A: IpAddress>(mut ranges: Vec<IpRange<A>>) -> Vec<IpRange<A>> {
    // Sort by Address
    ranges.sort_unstable_by_key(|range| range.start());
    // Merge overlapping ranges
    let mut merged = Vec::<IpRange<A>>::new();
    for range in ranges {
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
    merged
}

