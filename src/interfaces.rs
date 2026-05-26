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
    /// Number of bits in this address type: 32 for IPv4, 128 for IPv6.
    const BITS: u8;

    fn is_unspecified(&self) -> bool;

    /// Convert this address to a u128. IPv4 uses the low 32 bits.
    fn to_u128(self) -> u128;

    /// Construct an address from a u128. IPv4 reads the low 32 bits.
    fn from_u128(bits: u128) -> Self;
}

impl IpAddress for Ipv4Addr {
    const BITS: u8 = 32;

    fn is_unspecified(&self) -> bool {
        Ipv4Addr::is_unspecified(self)
    }

    fn to_u128(self) -> u128 {
        self.to_bits() as u128
    }

    fn from_u128(bits: u128) -> Self {
        Ipv4Addr::from_bits(bits as u32)
    }
}

impl IpAddress for Ipv6Addr {
    const BITS: u8 = 128;

    fn is_unspecified(&self) -> bool {
        Ipv6Addr::is_unspecified(self)
    }

    fn to_u128(self) -> u128 {
        self.to_bits()
    }

    fn from_u128(bits: u128) -> Self {
        Ipv6Addr::from_bits(bits)
    }
}
