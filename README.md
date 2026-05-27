# ipnetx

IP address range, prefix, and set operations for IPv4 and IPv6.

[![Crates.io](https://img.shields.io/crates/v/ipnetx.svg)](https://crates.io/crates/ipnetx)
[![Docs.rs](https://docs.rs/ipnetx/badge.svg)](https://docs.rs/ipnetx)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## What is this?

Working with IP addresses in network programming often means more than checking
whether two addresses are equal. Real questions look like:

- "Is this IP inside the `10.0.0.0/8` corporate network?"
- "Do any of the ranges in this allow-list overlap with the ranges in this block-list?"
- "I have 50 000 IPs in my firewall rules — can I reduce them to the minimal set of CIDR prefixes?"

`ipnetx` gives you three composable building blocks for answering those questions,
for both IPv4 and IPv6, using the address types already in `std::net`:

| Type | What it represents |
|------|--------------------|
| `IpRange<A>` | A contiguous span of addresses: `10.0.0.0 – 10.255.255.255` |
| `IpPrefix<A>` | A CIDR block: `10.0.0.0/8` |
| `IpSet<A>` | An arbitrary collection of addresses built from any mix of ranges and prefixes |

> **Background: what is a CIDR prefix?**
>
> A CIDR prefix like `192.168.1.0/24` is shorthand for "all addresses whose
> first 24 bits match `192.168.1`". The number after the `/` is the *prefix
> length* (also called the *mask*). `/24` means 24 fixed bits and 8 free bits,
> giving 2⁸ = 256 addresses. `/32` (IPv4) or `/128` (IPv6) is a single host.
> `/0` covers the entire address space.

---

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
ipnetx = "0.1"
```

---

## IpRange — working with address spans

An `IpRange` is the simplest primitive: a start address and an end address,
both inclusive. Any two addresses of the same family form a valid range as long
as `start <= end`.

```rust
use std::net::Ipv4Addr;
use ipnetx::range::IpRange;

// Create a range covering 10.0.0.0 through 10.0.0.255
let range = IpRange::new(
    Ipv4Addr::new(10, 0, 0, 0),
    Ipv4Addr::new(10, 0, 0, 255),
);

assert!(range.is_valid());
assert_eq!(range.start(), Ipv4Addr::new(10, 0, 0, 0));
assert_eq!(range.end(),   Ipv4Addr::new(10, 0, 0, 255));
```

### Containment

```rust
use std::net::Ipv4Addr;
use ipnetx::range::IpRange;

let range = IpRange::new(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 255));

assert!(range.contains(Ipv4Addr::new(10, 0, 0,   1)));  // inside
assert!(range.contains(Ipv4Addr::new(10, 0, 0,   0)));  // start — inclusive
assert!(range.contains(Ipv4Addr::new(10, 0, 0, 255)));  // end — inclusive
assert!(!range.contains(Ipv4Addr::new(10, 0, 1,  0)));  // just outside
```

### Overlap

Two ranges overlap if they share at least one address. Ranges that merely
*touch* at a single boundary point are still considered overlapping.

```rust
use std::net::Ipv4Addr;
use ipnetx::range::IpRange;

let a = IpRange::new(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 10));
let b = IpRange::new(Ipv4Addr::new(10, 0, 0, 5), Ipv4Addr::new(10, 0, 0, 20));
let c = IpRange::new(Ipv4Addr::new(10, 0, 1, 0), Ipv4Addr::new(10, 0, 1, 255));

assert!(a.overlaps(&b));   // share addresses 5–10
assert!(!a.overlaps(&c));  // completely separate
```

### Converting a range to CIDR prefixes

A contiguous range of addresses can always be expressed as one or more CIDR
prefixes. If the range happens to be exactly CIDR-aligned (power-of-two size,
aligned start), it collapses to a single prefix.

```rust
use std::net::Ipv4Addr;
use ipnetx::range::IpRange;

// Aligned range → exactly one prefix
let aligned = IpRange::new(
    Ipv4Addr::new(192, 168, 1,   0),
    Ipv4Addr::new(192, 168, 1, 255),
);
let prefixes = aligned.prefixes();
assert_eq!(prefixes.len(), 1);
assert_eq!(prefixes[0].mask(), 24);  // 192.168.1.0/24

// Unaligned range → multiple prefixes
let unaligned = IpRange::new(
    Ipv4Addr::new(10, 0, 0,   1),
    Ipv4Addr::new(10, 0, 0, 254),
);
assert!(unaligned.prefixes().len() > 1);
```

Use `prefix()` (singular) when you only want to know *whether* the range is
already a single CIDR block, without allocating the full list:

```rust
use std::net::Ipv4Addr;
use ipnetx::range::IpRange;

let aligned = IpRange::new(
    Ipv4Addr::new(10, 0, 0, 0),
    Ipv4Addr::new(10, 0, 0, 255),
);
let not_aligned = IpRange::new(
    Ipv4Addr::new(10, 0, 0, 1),
    Ipv4Addr::new(10, 0, 0, 10),
);

assert!(aligned.prefix().is_some());      // 10.0.0.0/24
assert!(not_aligned.prefix().is_none());  // not CIDR-aligned
```

### Invalid ranges

A range where `start > end` is considered invalid. `IpRange::new` always
succeeds — validity is checked lazily by `is_valid()`. Invalid ranges are
treated as empty by all operations.

```rust
use std::net::Ipv4Addr;
use ipnetx::range::IpRange;

let bad = IpRange::new(
    Ipv4Addr::new(10, 0, 0, 255),
    Ipv4Addr::new(10, 0, 0,   0),  // end < start
);

assert!(!bad.is_valid());
assert!(!bad.contains(Ipv4Addr::new(10, 0, 0, 1)));
assert!(bad.prefixes().is_empty());
```

### IPv6

Every method works identically for IPv6. Swap `Ipv4Addr` for `Ipv6Addr`:

```rust
use std::net::Ipv6Addr;
use ipnetx::range::IpRange;

let range = IpRange::new(
    Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x0000),
    Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0xffff),
);

assert!(range.is_valid());
assert!(range.contains(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x1234)));
```

---

## IpPrefix — working with CIDR blocks

An `IpPrefix` pairs an IP address with a prefix length. The constructor
validates the mask length but does **not** zero host bits — `192.168.1.100/24`
is a valid prefix. Use `masked()` to get the canonical network address form.

```rust
use std::net::Ipv4Addr;
use ipnetx::prefix::IpPrefix;

// Ok: mask 24 is within [0, 32] for IPv4
let prefix = IpPrefix::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap();

// Err: mask 33 exceeds 32 bits
assert!(IpPrefix::new(Ipv4Addr::new(192, 168, 1, 0), 33).is_err());
```

### Containment

```rust
use std::net::Ipv4Addr;
use ipnetx::prefix::IpPrefix;

let prefix = IpPrefix::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap();

assert!(prefix.contains(Ipv4Addr::new(192, 168, 1,   0)));  // network address
assert!(prefix.contains(Ipv4Addr::new(192, 168, 1, 255)));  // broadcast address
assert!(prefix.contains(Ipv4Addr::new(192, 168, 1,  50)));  // somewhere in the middle
assert!(!prefix.contains(Ipv4Addr::new(192, 168, 2,   0))); // different /24
```

### Converting a prefix to a range

```rust
use std::net::Ipv4Addr;
use ipnetx::prefix::IpPrefix;

let prefix = IpPrefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap();
let range = prefix.to_range();

assert_eq!(range.start(), Ipv4Addr::new(10,   0, 0,   0));
assert_eq!(range.end(),   Ipv4Addr::new(10, 255, 255, 255));
```

### Masking host bits

If you receive a prefix like `192.168.1.100/24` (a host address with a mask
attached) and want the canonical network address `192.168.1.0/24`, use
`masked()`:

```rust
use std::net::Ipv4Addr;
use ipnetx::prefix::IpPrefix;

let sloppy  = IpPrefix::new(Ipv4Addr::new(192, 168, 1, 100), 24).unwrap();
let clean   = sloppy.masked();

assert_eq!(clean.ip(),  Ipv4Addr::new(192, 168, 1, 0));
assert_eq!(clean.mask(), 24);
```

### Checking for a single host

```rust
use std::net::Ipv4Addr;
use ipnetx::prefix::IpPrefix;

let host    = IpPrefix::new(Ipv4Addr::new(10, 0, 0, 1), 32).unwrap();
let network = IpPrefix::new(Ipv4Addr::new(10, 0, 0, 0), 24).unwrap();

assert!(host.is_single_ip());
assert!(!network.is_single_ip());
```

### Overlap between prefixes

Two CIDR prefixes either nest (one is a sub-prefix of the other) or are
completely disjoint — they cannot partially overlap the way arbitrary ranges can.

```rust
use std::net::Ipv4Addr;
use ipnetx::prefix::IpPrefix;

let slash8  = IpPrefix::new(Ipv4Addr::new(10, 0, 0, 0),  8).unwrap();
let slash24 = IpPrefix::new(Ipv4Addr::new(10, 0, 0, 0), 24).unwrap();
let other   = IpPrefix::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap();

assert!(slash8.overlaps(&slash24));   // /24 is nested inside /8
assert!(slash24.overlaps(&slash8));   // symmetric
assert!(!slash8.overlaps(&other));    // completely separate
```

### IPv6

```rust
use std::net::Ipv6Addr;
use ipnetx::prefix::IpPrefix;

// 2001:db8::/32 — the documentation prefix (RFC 3849)
let prefix = IpPrefix::new(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0), 32).unwrap();

assert!(prefix.contains(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)));
assert!(!prefix.contains(Ipv6Addr::new(0x2001, 0x0db9, 0, 0, 0, 0, 0, 0)));
```

---

## IpSet — working with sets of addresses

`IpSet` is for when you have an arbitrary collection of ranges and prefixes and
need to answer membership or overlap questions efficiently. You build one through
`IpSetBuilder`, which accepts ranges and prefixes in any order, then call
`build()` to get a normalized, immutable `IpSet`.

Normalization means `build()` sorts all ranges by start address and merges
any that are adjacent or overlapping. The result is always a minimal list of
non-overlapping ranges, which makes binary-search lookups possible.

### Building a set

```rust
use std::net::Ipv4Addr;
use ipnetx::prefix::IpPrefix;
use ipnetx::range::IpRange;
use ipnetx::ipset::IpSetBuilder;

let mut builder = IpSetBuilder::<Ipv4Addr>::new();

// Add a /8 block
builder.add_prefix(IpPrefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap());

// Add a separate /16
builder.add_prefix(IpPrefix::new(Ipv4Addr::new(192, 168, 0, 0), 16).unwrap());

// Add an arbitrary range
builder.add_range(IpRange::new(
    Ipv4Addr::new(172, 16, 0, 0),
    Ipv4Addr::new(172, 31, 255, 255),
));

let set = builder.build();
assert_eq!(set.len(), 3); // three disjoint ranges, stored in sorted order
```

### Adding and removing individual IPs

```rust
use std::net::Ipv4Addr;
use ipnetx::prefix::IpPrefix;
use ipnetx::ipset::IpSetBuilder;

let mut builder = IpSetBuilder::<Ipv4Addr>::new();
builder.add_prefix(IpPrefix::new(Ipv4Addr::new(10, 0, 0, 0), 24).unwrap());

// Punch a hole: remove a single IP from the middle of the range
builder.remove_ip(Ipv4Addr::new(10, 0, 0, 100));

let set = builder.build();

assert!(!set.contains_ip(Ipv4Addr::new(10, 0, 0, 100))); // removed
assert!(set.contains_ip(Ipv4Addr::new(10, 0, 0,  99)));  // still present
assert!(set.contains_ip(Ipv4Addr::new(10, 0, 0, 101)));  // still present
assert_eq!(set.len(), 2); // split into [0..99] and [101..255]
```

### Membership queries

```rust
use std::net::Ipv4Addr;
use ipnetx::prefix::IpPrefix;
use ipnetx::range::IpRange;
use ipnetx::ipset::IpSetBuilder;

let mut builder = IpSetBuilder::<Ipv4Addr>::new();
builder.add_prefix(IpPrefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap());
let set = builder.build();

// Single IP lookup — O(log n)
assert!(set.contains_ip(Ipv4Addr::new(10, 42, 0, 1)));
assert!(!set.contains_ip(Ipv4Addr::new(11, 0, 0, 1)));

// Range containment — the entire range must fit inside a single stored range
let inner = IpRange::new(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 255));
let outer = IpRange::new(Ipv4Addr::new(9, 0, 0, 0),  Ipv4Addr::new(10, 0, 0, 255));

assert!(set.contains_range(inner));  // fully inside 10/8
assert!(!set.contains_range(outer)); // starts before 10/8 — not contained
```

### Overlap between two sets

```rust
use std::net::Ipv4Addr;
use ipnetx::prefix::IpPrefix;
use ipnetx::ipset::IpSetBuilder;

let mut allow = IpSetBuilder::<Ipv4Addr>::new();
allow.add_prefix(IpPrefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap());
let allow_set = allow.build();

let mut block = IpSetBuilder::<Ipv4Addr>::new();
block.add_prefix(IpPrefix::new(Ipv4Addr::new(10, 0, 0, 0), 24).unwrap()); // inside allow
let block_set = block.build();

let mut clean = IpSetBuilder::<Ipv4Addr>::new();
clean.add_prefix(IpPrefix::new(Ipv4Addr::new(192, 168, 0, 0), 16).unwrap()); // outside allow
let clean_set = clean.build();

assert!(allow_set.overlaps_ip_set(&block_set));  // conflict — 10/24 is inside 10/8
assert!(!allow_set.overlaps_ip_set(&clean_set)); // no conflict
```

### Inspecting a set

```rust
use std::net::Ipv4Addr;
use ipnetx::prefix::IpPrefix;
use ipnetx::ipset::IpSetBuilder;

let mut builder = IpSetBuilder::<Ipv4Addr>::new();
builder.add_prefix(IpPrefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap());
builder.add_prefix(IpPrefix::new(Ipv4Addr::new(192, 168, 0, 0), 16).unwrap());
let set = builder.build();

// Iterate over the stored ranges
for range in set.ranges() {
    println!("{} – {}", range.start(), range.end());
}

// Decompose back to CIDR prefixes
for prefix in set.prefixes() {
    println!("{}/{}", prefix.ip(), prefix.mask());
}
```

### Overlapping inputs are merged automatically

You don't need to pre-sort or de-duplicate your inputs — `build()` handles it:

```rust
use std::net::Ipv4Addr;
use ipnetx::prefix::IpPrefix;
use ipnetx::ipset::IpSetBuilder;

let mut builder = IpSetBuilder::<Ipv4Addr>::new();
builder.add_prefix(IpPrefix::new(Ipv4Addr::new(10, 0, 0, 0),  8).unwrap()); // 10/8
builder.add_prefix(IpPrefix::new(Ipv4Addr::new(10, 0, 0, 0), 24).unwrap()); // 10.0.0/24 — inside 10/8
builder.add_prefix(IpPrefix::new(Ipv4Addr::new(10, 0, 0, 0), 16).unwrap()); // 10.0/16 — also inside 10/8

let set = builder.build();
assert_eq!(set.len(), 1); // all three collapse into a single 10/8 range
```

### IPv6

```rust
use std::net::Ipv6Addr;
use ipnetx::prefix::IpPrefix;
use ipnetx::ipset::IpSetBuilder;

let mut builder = IpSetBuilder::<Ipv6Addr>::new();
builder.add_prefix(IpPrefix::new(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0), 32).unwrap());
let set = builder.build();

assert!(set.contains_ip(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)));
assert!(!set.contains_ip(Ipv6Addr::new(0x2001, 0x0db9, 0, 0, 0, 0, 0, 0)));
```

---

## API reference

Full documentation is available on [docs.rs/ipnetx](https://docs.rs/ipnetx).

---

## License

MIT — see [LICENSE](LICENSE).
