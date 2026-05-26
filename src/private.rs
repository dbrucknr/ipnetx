// The Sealed trait is a library contract.
// - It stops users of the crate from implementing it for their own types.
pub trait Sealed {}
impl Sealed for std::net::Ipv4Addr {}
impl Sealed for std::net::Ipv6Addr {}
