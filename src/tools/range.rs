use crate::{interfaces::IpAddress, range::IpRange};

/// Collapses adjacent and overlapping spans in a **sorted** slice.
///
/// The caller must guarantee that `ranges` is sorted by start address.
/// `normalize` does this via `sort_unstable_by_key`; `IpSet::union` does it
/// via an explicit two-pointer merge, avoiding the O((m+n) log(m+n)) sort.
pub(crate) fn merge_sorted<A: IpAddress>(ranges: Vec<IpRange<A>>) -> Vec<IpRange<A>> {
    let mut merged = Vec::<IpRange<A>>::with_capacity(ranges.len());
    for range in ranges {
        match merged.last_mut() {
            Some(last) if range.start().to_u128() <= last.end().to_u128().saturating_add(1) => {
                if range.end().to_u128() > last.end().to_u128() {
                    *last = IpRange::new(last.start(), range.end());
                }
            }
            _ => {
                merged.push(range);
            }
        }
    }
    merged
}

pub(crate) fn normalize<A: IpAddress>(mut ranges: Vec<IpRange<A>>) -> Vec<IpRange<A>> {
    ranges.sort_unstable_by_key(|range| range.start());
    merge_sorted(ranges)
}

