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
