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
