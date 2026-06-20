#![doc = include_str!("../README.md")]
//! IP address range, prefix, and set operations for IPv4 and IPv6.
//!
//! `ipnetx` provides three core types built on a single generic
//! [`interfaces::IpAddress`] trait that is sealed to [`std::net::Ipv4Addr`]
//! and [`std::net::Ipv6Addr`]:
//!
//! | Type | Description |
//! |------|-------------|
//! | [`range::IpRange`] | An inclusive `[start, end]` address span |
//! | [`prefix::IpPrefix`] | A CIDR prefix (`ip/mask`) |
//! | [`ipset::IpSet`] | An immutable, normalized set of address ranges |
//!
//! Sets are constructed through [`ipset::IpSetBuilder`], which accepts
//! arbitrary ranges and prefixes in any order and produces a sorted,
//! non-overlapping [`ipset::IpSet`] on [`build`](ipset::IpSetBuilder::build).
//!
//! # Quick start
//!
//! ```rust
//! use std::net::Ipv4Addr;
//! use ipnetx::prefix::IpPrefix;
//! use ipnetx::ipset::IpSetBuilder;
//!
//! let mut builder = IpSetBuilder::<Ipv4Addr>::new();
//! builder.add_prefix(IpPrefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap());
//! builder.add_prefix(IpPrefix::new(Ipv4Addr::new(192, 168, 0, 0), 16).unwrap());
//! let set = builder.build();
//!
//! assert!(set.contains_ip(Ipv4Addr::new(10, 1, 2, 3)));
//! assert!(set.contains_ip(Ipv4Addr::new(192, 168, 1, 100)));
//! assert!(!set.contains_ip(Ipv4Addr::new(172, 16, 0, 1)));
//! ```

pub mod interfaces;
pub mod ipset;
pub mod prefix;
mod private;
pub mod range;
mod tools;

#[cfg(test)]
mod proptests;
