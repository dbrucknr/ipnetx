use std::net::{Ipv4Addr, Ipv6Addr};

/// Sealed marker trait that restricts [`IpAddress`] implementations to
/// [`Ipv4Addr`] and [`Ipv6Addr`] defined within this crate.
///
/// This is the "sealed trait" pattern: `Sealed` is `pub` inside a private
/// module, so external crates cannot name it and therefore cannot implement
/// [`IpAddress`] on their own types — even ones that satisfy all the other
/// bounds like `Copy + PartialOrd + Display`.
pub trait IpAddress:
    crate::private::Sealed
    + PartialOrd
    + Copy
    + std::fmt::Display
    + std::fmt::Debug
    + PartialEq
    + Eq
    + std::hash::Hash
{
    fn is_unspecified(&self) -> bool;
}

impl IpAddress for Ipv4Addr {
    fn is_unspecified(&self) -> bool {
        Ipv4Addr::is_unspecified(self)
    }
}

impl IpAddress for Ipv6Addr {
    fn is_unspecified(&self) -> bool {
        Ipv6Addr::is_unspecified(self)
    }
}

pub struct IpRange<A: IpAddress> {
    start: A,
    end: A,
}

impl<A: IpAddress> IpRange<A> {
    pub fn new(start: A, end: A) -> Self {
        Self { start, end }
    }

    pub fn start(&self) -> A {
        self.start
    }

    pub fn end(&self) -> A {
        self.end
    }

    pub fn is_valid(&self) -> bool {
        self.start <= self.end
    }

    pub fn contains(&self, ip: A) -> bool {
        self.is_valid() && self.start <= ip && ip <= self.end
    }

    pub fn is_zero(&self) -> bool {
        self.start.is_unspecified() && self.end.is_unspecified()
    }

    pub fn overlaps(&self, other: &IpRange<A>) -> bool {
        self.is_valid() && other.is_valid() && self.end >= other.start && self.start <= other.end
    }

    pub fn prefix(&self) {
        todo!()
    }

    pub fn prefixes(&self) {
        todo!()
    }
}

impl<A: IpAddress> std::fmt::Display for IpRange<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}..{}", self.start, self.end)
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
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),
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
}
