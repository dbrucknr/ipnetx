use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpFamilyMismatch {
    V4V6,
    V6V4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpRange {
    start: IpAddr,
    end: IpAddr,
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
        self.start <= ip && ip <= self.end
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
    fn test_v4_display() {
        let range = IpRange::new(
            IpAddr::V4(Ipv4Addr::new(1, 0, 0, 0)),
            IpAddr::V4(Ipv4Addr::new(1, 255, 255, 255)),
        )
        .unwrap();

        assert_eq!(format!("{}", range), "1.0.0.0..1.255.255.255");
    }
}
