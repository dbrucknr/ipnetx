use crate::{interfaces::IpAddress, range::IpRange};

pub(crate) fn normalize<A: IpAddress>(mut ranges: Vec<IpRange<A>>) -> Vec<IpRange<A>> {
    // Sort by Address
    ranges.sort_by_key(|range| range.start().to_u128());
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

pub(crate) fn subtract_range<A: IpAddress>(
    mut ranges: Vec<IpRange<A>>,
    remove: IpRange<A>,
) -> Vec<IpRange<A>> {
    let start = remove.start().to_u128();
    let end = remove.end().to_u128();

    let mut result = Vec::new();

    for stored in ranges.drain(..) {
        let s = stored.start().to_u128();
        let e = stored.end().to_u128();

        if e < start || s > end {
            // No overlap - keep
            result.push(stored);
        } else {
            // Left piece stays if the stored range starts before the removal
            if s < start {
                result.push(IpRange::new(stored.start(), A::from_u128(start - 1)));
            }
            // Right piece stays if the stored range ends after the removal
            if e > end {
                result.push(IpRange::new(A::from_u128(end + 1), stored.end()));
            }
            // If neither condition was true, the stored range was fully covered. It is dropped.
        }
    }
    result
}
