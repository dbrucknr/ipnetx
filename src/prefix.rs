use crate::{interfaces::IpAddress, range::IpRange};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpPrefix<A: IpAddress> {
    ip: A,
    mask: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidPrefixLen;

impl<A: IpAddress> IpPrefix<A> {
    /// Returns `None` if `mask` exceeds the address bit width
    /// (> 32 for IPv4, > 128 for IPv6).
    pub fn new(ip: A, mask: u8) -> Result<Self, InvalidPrefixLen> {
        if mask > A::BITS {
            return Err(InvalidPrefixLen);
        }
        Ok(Self { ip, mask })
    }

    pub fn ip(&self) -> A {
        self.ip
    }

    pub fn mask(&self) -> u8 {
        self.mask
    }

    pub fn contains(&self, ip: A) -> bool {
        // Two addresses share the same /mask prefix iff their top `mask` bits
        // are identical — mask the host bits of both and compare.
        let network = self.network_mask();
        self.ip.to_u128() & network == ip.to_u128() & network
    }

    pub fn to_range(&self) -> IpRange<A> {
        let ip = self.ip.to_u128();
        let network = self.network_mask();
        let host = self.host_mask();
        // start: zero out the host bits (network address)
        // end:   set all the host bits (broadcast / last address)
        IpRange::new(A::from_u128(ip & network), A::from_u128(ip | host))
    }

    // ── helpers ────────────────────────────────────────────────────────────

    /// Bit mask covering the network portion (top `mask` bits within the
    /// address width). e.g. /24 on IPv4 → 0xFFFFFF00.
    fn network_mask(&self) -> u128 {
        // addr_max isolates the relevant bits for this address family:
        //   IPv4 → 0x00000000_...._FFFFFFFF
        //   IPv6 → 0xFFFFFFFF_...._FFFFFFFF
        let addr_max: u128 = u128::MAX >> (128 - A::BITS as u32);
        let shift = A::BITS - self.mask;
        addr_max & (u128::MAX << shift as u32)
    }

    /// Bit mask covering the host portion (bottom `BITS - mask` bits).
    /// e.g. /24 on IPv4 → 0x000000FF.
    fn host_mask(&self) -> u128 {
        let addr_max: u128 = u128::MAX >> (128 - A::BITS as u32);
        addr_max & !self.network_mask()
    }
}

impl<A: IpAddress> std::fmt::Display for IpPrefix<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.ip, self.mask)
    }
}
