use std::net::IpAddr;

pub struct IpRange {
    start: IpAddr,
    end: IpAddr,
}

impl IpRange {
    pub fn new(start: IpAddr, end: IpAddr) -> Self {
        Self { start, end }
    }

    pub fn start(&self) -> IpAddr {
        self.start
    }

    pub fn end(&self) -> IpAddr {
        self.end
    }

    pub fn valid(&self) -> bool {
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
    use std::net::Ipv4Addr;

    #[test]
    fn test_start() {
        let range = IpRange::new(
            IpAddr::V4(Ipv4Addr::new(1, 0, 0, 0)),
            IpAddr::V4(Ipv4Addr::new(1, 255, 255, 255)),
        );
        assert_eq!(range.start(), IpAddr::V4(Ipv4Addr::new(1, 0, 0, 0)));
    }

    #[test]
    fn test_end() {
        let range = IpRange::new(
            IpAddr::V4(Ipv4Addr::new(1, 0, 0, 0)),
            IpAddr::V4(Ipv4Addr::new(1, 255, 255, 255)),
        );
        assert_eq!(range.end(), IpAddr::V4(Ipv4Addr::new(1, 255, 255, 255)));
    }

    #[test]
    fn test_valid() {
        let range = IpRange::new(
            IpAddr::V4(Ipv4Addr::new(1, 0, 0, 0)),
            IpAddr::V4(Ipv4Addr::new(1, 255, 255, 255)),
        );
        assert!(range.valid());
    }

    #[test]
    fn test_invalid() {
        let range = IpRange::new(
            IpAddr::V4(Ipv4Addr::new(1, 255, 255, 255)),
            IpAddr::V4(Ipv4Addr::new(1, 0, 0, 0)),
        );
        assert!(!range.valid());
    }

    #[test]
    fn test_contains() {
        let range = IpRange::new(
            IpAddr::V4(Ipv4Addr::new(1, 0, 0, 0)),
            IpAddr::V4(Ipv4Addr::new(1, 255, 255, 255)),
        );
        assert!(range.contains(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        assert!(!range.contains(IpAddr::V4(Ipv4Addr::new(2, 0, 0, 0))));
    }
}
