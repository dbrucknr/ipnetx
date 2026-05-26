use std::net::{IpAddr, Ipv4Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpFamilyMismatch {
    V4V6,
    V6V4,
}

// I wonder if the IpRange should accept a generic type that is either an IpAddr::V4 or IpAddr::V6?
// Perhaps I should also consider prefix ranges?
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpRange {
    start: IpAddr,
    end: IpAddr,
}

impl Default for IpRange {
    fn default() -> Self {
        Self {
            start: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            end: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        }
    }
}

impl IpRange {
    pub fn new(start: IpAddr, end: IpAddr) -> Result<Self, IpFamilyMismatch> {
        match (&start, &end) {
            (IpAddr::V4(_), IpAddr::V6(_)) => return Err(IpFamilyMismatch::V4V6),
            (IpAddr::V6(_), IpAddr::V4(_)) => return Err(IpFamilyMismatch::V6V4),
            _ => {}
        }
        Ok(Self { start, end })
    }

    pub fn start(&self) -> IpAddr {
        self.start
    }

    pub fn end(&self) -> IpAddr {
        self.end
    }

    pub fn is_valid(&self) -> bool {
        self.start <= self.end
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        self.is_valid() && self.start <= ip && ip <= self.end
    }

    pub fn is_zero(&self) -> bool {
        match (self.start, self.end) {
            (IpAddr::V4(s), IpAddr::V4(e)) => s.is_unspecified() && e.is_unspecified(),
            (IpAddr::V6(s), IpAddr::V6(e)) => s.is_unspecified() && e.is_unspecified(),
            _ => false,
        }
    }

    pub fn overlaps(&self, other: &IpRange) -> bool {
        if !self.is_valid() || !other.is_valid() {
            return false;
        }
        match (&self.start, &other.start) {
            (IpAddr::V4(_), IpAddr::V6(_)) | (IpAddr::V6(_), IpAddr::V4(_)) => return false,
            _ => {}
        }
        self.end >= other.start && self.start <= other.end
    }

    pub fn prefixes(&self) {
        todo!()
    }

    pub fn prefix(&self) {
        todo!()
    }
}

impl std::fmt::Display for IpRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}..{}", self.start, self.end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_v4_new() {
        let range = IpRange::new(
            IpAddr::V4(Ipv4Addr::new(1, 0, 0, 0)),
            IpAddr::V4(Ipv4Addr::new(1, 255, 255, 255)),
        );
        assert!(range.is_ok());
    }

    #[test]
    fn test_new_v4v6() {
        let range = IpRange::new(
            IpAddr::V4(Ipv4Addr::new(1, 0, 0, 0)),
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
        );
        assert!(range.is_err());
        assert_eq!(range.unwrap_err(), IpFamilyMismatch::V4V6);
    }

    #[test]
    fn test_new_v6v4() {
        let range = IpRange::new(
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(1, 0, 0, 0)),
        );
        assert!(range.is_err());
        assert_eq!(range.unwrap_err(), IpFamilyMismatch::V6V4);
    }

    #[test]
    fn test_v4_start() {
        let range = IpRange::new(
            IpAddr::V4(Ipv4Addr::new(1, 0, 0, 0)),
            IpAddr::V4(Ipv4Addr::new(1, 255, 255, 255)),
        )
        .unwrap();

        assert_eq!(range.start(), IpAddr::V4(Ipv4Addr::new(1, 0, 0, 0)));
    }

    #[test]
    fn test_v4_end() {
        let range = IpRange::new(
            IpAddr::V4(Ipv4Addr::new(1, 0, 0, 0)),
            IpAddr::V4(Ipv4Addr::new(1, 255, 255, 255)),
        )
        .unwrap();

        assert_eq!(range.end(), IpAddr::V4(Ipv4Addr::new(1, 255, 255, 255)));
    }

    #[test]
    fn test_v4_valid() {
        let range = IpRange::new(
            IpAddr::V4(Ipv4Addr::new(1, 0, 0, 0)),
            IpAddr::V4(Ipv4Addr::new(1, 255, 255, 255)),
        )
        .unwrap();

        assert!(range.is_valid());
    }

    #[test]
    fn test_v4_invalid() {
        let range = IpRange::new(
            IpAddr::V4(Ipv4Addr::new(1, 255, 255, 255)),
            IpAddr::V4(Ipv4Addr::new(1, 0, 0, 0)),
        )
        .unwrap();

        assert!(!range.is_valid());
    }

    #[test]
    fn test_v4_contains() {
        let range = IpRange::new(
            IpAddr::V4(Ipv4Addr::new(1, 0, 0, 0)),
            IpAddr::V4(Ipv4Addr::new(1, 255, 255, 255)),
        )
        .unwrap();

        assert!(range.contains(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        assert!(!range.contains(IpAddr::V4(Ipv4Addr::new(2, 0, 0, 0))));
    }

    #[test]
    fn test_v4_contains_start_eq_end() {
        let range = IpRange::new(
            IpAddr::V4(Ipv4Addr::new(1, 0, 0, 0)),
            IpAddr::V4(Ipv4Addr::new(1, 0, 0, 0)),
        )
        .unwrap();

        assert!(range.contains(IpAddr::V4(Ipv4Addr::new(1, 0, 0, 0))));
    }

    #[test]
    fn test_v4_invalid_contains() {
        let range = IpRange::new(
            IpAddr::V4(Ipv4Addr::new(1, 255, 255, 255)),
            IpAddr::V4(Ipv4Addr::new(1, 0, 0, 0)),
        )
        .unwrap();

        assert!(!range.contains(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        assert!(!range.contains(IpAddr::V4(Ipv4Addr::new(2, 0, 0, 0))));
    }

    #[test]
    fn test_v4_overlaps() {
        let range = IpRange::new(
            IpAddr::V4(Ipv4Addr::new(1, 0, 0, 0)),
            IpAddr::V4(Ipv4Addr::new(1, 255, 255, 255)),
        )
        .unwrap();

        assert!(
            range.overlaps(
                &IpRange::new(
                    IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                    IpAddr::V4(Ipv4Addr::new(1, 255, 255, 255)),
                )
                .unwrap()
            )
        );
    }

    #[test]
    fn test_v4_overlaps_no_overlap() {
        let range = IpRange::new(
            IpAddr::V4(Ipv4Addr::new(1, 0, 0, 0)),
            IpAddr::V4(Ipv4Addr::new(1, 255, 255, 255)),
        )
        .unwrap();

        assert!(
            !range.overlaps(
                &IpRange::new(
                    IpAddr::V4(Ipv4Addr::new(2, 0, 0, 0)),
                    IpAddr::V4(Ipv4Addr::new(2, 255, 255, 255)),
                )
                .unwrap()
            )
        );
    }

    #[test]
    fn test_v6_overlaps() {
        let range = IpRange::new(
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 255)),
        )
        .unwrap();

        assert!(
            range.overlaps(
                &IpRange::new(
                    IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
                    IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 255)),
                )
                .unwrap()
            )
        );
    }

    #[test]
    fn test_v6_overlaps_no_overlap() {
        let range = IpRange::new(
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 255)),
        )
        .unwrap();

        assert!(
            !range.overlaps(
                &IpRange::new(
                    IpAddr::V6(Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 1)),
                    IpAddr::V6(Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 255)),
                )
                .unwrap()
            )
        );
    }

    #[test]
    fn test_v4_is_zero() {
        let range = IpRange::new(
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        )
        .unwrap();

        assert!(range.is_zero());
    }

    #[test]
    fn test_v6_is_zero() {
        let range = IpRange::new(
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)),
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)),
        )
        .unwrap();

        assert!(range.is_zero());
    }

    #[test]
    fn test_v4_display() {
        let range = IpRange::new(
            IpAddr::V4(Ipv4Addr::new(1, 0, 0, 0)),
            IpAddr::V4(Ipv4Addr::new(1, 255, 255, 255)),
        )
        .unwrap();

        assert_eq!(format!("{}", range), "1.0.0.0..1.255.255.255");
    }

    #[test]
    fn test_v6_display() {
        let range = IpRange::new(
            IpAddr::V6(Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 255)),
        )
        .unwrap();

        assert_eq!(format!("{}", range), "1::1..1::ff");
    }
}
