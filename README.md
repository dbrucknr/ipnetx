# ipnetx

IP address range, prefix, and set operations for IPv4 and IPv6.

[![Crates.io](https://img.shields.io/crates/v/ipnetx.svg)](https://crates.io/crates/ipnetx)
[![Docs.rs](https://docs.rs/ipnetx/badge.svg)](https://docs.rs/ipnetx/latest/ipnetx/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![codecov](https://codecov.io/gh/dbrucknr/ipnetx/graph/badge.svg)](https://codecov.io/gh/dbrucknr/ipnetx)

---

## What is ipnetx?

Working with IP addresses in network programming often means more than checking
whether two addresses are equal. Real questions look like:

- "Is this IP inside the `10.0.0.0/8` corporate network?"
- "Do any of the ranges in this allow-list overlap with the ranges in this block-list?"
- "I have 50,000 IPs in my firewall rules. Can I reduce them to the minimal set of CIDR prefixes?"

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

## Why ipnetx?

The Rust ecosystem already has solid building blocks for IP address work:

- **`std::net`** gives you `Ipv4Addr` and `Ipv6Addr` — address types and nothing else.
- **`ipnet`** adds CIDR prefix and subnet handling and is the right choice if that is all you need.

`ipnetx` picks up where those leave off. The gap it fills is **`IpSet` as a proper mathematical set type** — something no mainstream Rust IP crate implements today. When your problem is not just "does this IP belong to this prefix?" but instead involves combining, subtracting, or inverting collections of addresses, you need set algebra:

| Question | Operation |
|---|---|
| Merge two ACLs without duplicating rules | `union` |
| Which IPs appear in both our network and this threat feed? | `intersection` |
| Everything in the allow-list that isn't also in the block-list | `difference` |
| Every IP *not* covered by this ruleset — for deny-by-default logic | `complement` |

These are the kinds of questions that come up in firewall tooling, BGP route analysis, threat intelligence ingestion, and network auditing. Without set algebra you end up writing nested loops and hoping the edge cases are right. `ipnetx` gives you correct, tested, O(m + n) implementations out of the box.

If you only need to check whether an address or prefix falls inside a CIDR block, `ipnet` is a perfectly fine choice and you may not need this crate. If you need to *combine or compare collections of addresses*, `ipnetx` is built for that.

---

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
ipnetx = "0.1"
```

Or: `cargo add ipnetx`

> **A note on error handling in examples**
>
> All code snippets below use `.unwrap()` for brevity. In production code,
> handle errors explicitly — propagate with `?`, match on `Result`/`Option`,
> or use a crate like [`anyhow`](https://docs.rs/anyhow) for ergonomic error
> context. The only fallible constructors in this crate are `IpPrefix::new`
> (rejects out-of-range masks) and `.parse()` on `IpPrefix`/`IpRange`
> (rejects malformed strings); the set operations themselves are infallible.

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

### Parsing from a string

Use `.parse()` to create an `IpRange` from a string. The separator is `..`
(two dots) — the same token that `Display` produces, so a round-trip always
reconstructs the original string. The separator is unambiguous for IPv6 because
no valid IPv6 address contains consecutive dots.

```rust
use std::net::{Ipv4Addr, Ipv6Addr};
use ipnetx::range::IpRange;

// IPv4 — parse, then verify the round-trip
let r: IpRange<Ipv4Addr> = "10.0.0.0..10.0.0.255".parse().unwrap();
assert_eq!(r.start(), Ipv4Addr::new(10, 0, 0,   0));
assert_eq!(r.end(),   Ipv4Addr::new(10, 0, 0, 255));
assert_eq!(r.to_string(), "10.0.0.0..10.0.0.255");

// IPv6 — works identically
let r6: IpRange<Ipv6Addr> = "2001:db8::1..2001:db8::ff".parse().unwrap();
assert!(r6.is_valid());

// Wrong separator → error
assert!("10.0.0.0-10.0.0.255".parse::<IpRange<Ipv4Addr>>().is_err());
// Bad address → error
assert!("999.0.0.0..10.0.0.255".parse::<IpRange<Ipv4Addr>>().is_err());
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

### Parsing from a string

Use `.parse()` to create an `IpPrefix` from the standard `"<address>/<length>"`
notation. Host bits in the address are preserved just like `IpPrefix::new` —
`"192.168.1.100/24"` parses successfully. Use `.masked()` on the result if you
need the canonical network-address form.

```rust
use std::net::{Ipv4Addr, Ipv6Addr};
use ipnetx::prefix::IpPrefix;

// IPv4 — parse, then verify the round-trip
let p: IpPrefix<Ipv4Addr> = "192.168.1.0/24".parse().unwrap();
assert_eq!(p.ip(),   Ipv4Addr::new(192, 168, 1, 0));
assert_eq!(p.mask(), 24);
assert_eq!(p.to_string(), "192.168.1.0/24");

// IPv6 — works identically
let p6: IpPrefix<Ipv6Addr> = "2001:db8::/32".parse().unwrap();
assert_eq!(p6.mask(), 32);

// Missing '/' → error
assert!("192.168.1.0".parse::<IpPrefix<Ipv4Addr>>().is_err());
// Mask out of range → error
assert!("192.168.1.0/33".parse::<IpPrefix<Ipv4Addr>>().is_err());
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

### Set algebra

`IpSet` supports four mathematical set operations. All four return a new,
normalized `IpSet` and are infallible — no `unwrap` required on the result.

**Union** — every address in either set:

```rust
use std::net::Ipv4Addr;
use ipnetx::prefix::IpPrefix;
use ipnetx::ipset::IpSetBuilder;

let mut b1 = IpSetBuilder::<Ipv4Addr>::new();
b1.add_prefix(IpPrefix::new(Ipv4Addr::new(10, 0, 0, 0), 24).unwrap());
let a = b1.build();

let mut b2 = IpSetBuilder::<Ipv4Addr>::new();
b2.add_prefix(IpPrefix::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap());
let b = b2.build();

let u = a.union(&b);
assert!(u.contains_ip(Ipv4Addr::new(10, 0, 0, 1)));       // from a
assert!(u.contains_ip(Ipv4Addr::new(192, 168, 1, 1)));    // from b
assert_eq!(u.len(), 2);                                    // two disjoint ranges
```

**Intersection** — only addresses present in both sets:

```rust
use std::net::Ipv4Addr;
use ipnetx::prefix::IpPrefix;
use ipnetx::ipset::IpSetBuilder;

let mut b1 = IpSetBuilder::<Ipv4Addr>::new();
b1.add_prefix(IpPrefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap());
let a = b1.build(); // 10.0.0.0 – 10.255.255.255

let mut b2 = IpSetBuilder::<Ipv4Addr>::new();
b2.add_prefix(IpPrefix::new(Ipv4Addr::new(10, 0, 0, 0), 24).unwrap());
let b = b2.build(); // 10.0.0.0 – 10.0.0.255

let inter = a.intersection(&b);
assert!(inter.contains_ip(Ipv4Addr::new(10, 0, 0, 1)));   // in both
assert!(!inter.contains_ip(Ipv4Addr::new(10, 0, 1, 1)));  // only in a
```

**Difference** — addresses in `a` but not in `b`:

```rust
use std::net::Ipv4Addr;
use ipnetx::prefix::IpPrefix;
use ipnetx::ipset::IpSetBuilder;

let mut b1 = IpSetBuilder::<Ipv4Addr>::new();
b1.add_prefix(IpPrefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap());
let a = b1.build();

let mut b2 = IpSetBuilder::<Ipv4Addr>::new();
b2.add_prefix(IpPrefix::new(Ipv4Addr::new(10, 0, 0, 0), 24).unwrap());
let b = b2.build();

let diff = a.difference(&b);
assert!(!diff.contains_ip(Ipv4Addr::new(10, 0, 0, 1))); // carved out by b
assert!(diff.contains_ip(Ipv4Addr::new(10, 0, 1, 1)));  // still in a
```

**Complement** — every address *not* in the set. For IPv4 this covers the
entire `0.0.0.0/0` space minus `self`; for IPv6 it covers `::/0` minus `self`.

```rust
use std::net::Ipv4Addr;
use ipnetx::prefix::IpPrefix;
use ipnetx::ipset::IpSetBuilder;

let mut builder = IpSetBuilder::<Ipv4Addr>::new();
builder.add_prefix(IpPrefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap());
let a = builder.build();

let c = a.complement();
assert!(!c.contains_ip(Ipv4Addr::new(10, 0, 0, 1)));    // was in a
assert!(c.contains_ip(Ipv4Addr::new(192, 168, 1, 1)));  // not in a

// a and its complement are disjoint and together cover the whole space
assert!(a.intersection(&c).is_empty());
assert_eq!(a.union(&c).len(), 1); // merges into 0.0.0.0/0
```

### Cardinality and subset tests

**`count()`** returns the total number of individual IP addresses in the set
as a `u128` (large enough to represent an entire IPv6 address space exactly):

```rust
use std::net::Ipv4Addr;
use ipnetx::ipset::IpSetBuilder;
use ipnetx::range::IpRange;

let mut b = IpSetBuilder::<Ipv4Addr>::new();
b.add_range(IpRange::new(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 9)));   // 10
b.add_range(IpRange::new(Ipv4Addr::new(192, 168, 1, 0), Ipv4Addr::new(192, 168, 1, 4))); // 5
let set = b.build();

assert_eq!(set.count(), 15);
assert_eq!(set.len(), 2);  // two ranges, but 15 addresses total
```

**`is_subset_of`** and **`is_superset_of`** — test containment between sets.
An empty set is a subset of every set:

```rust
use std::net::Ipv4Addr;
use ipnetx::ipset::IpSetBuilder;
use ipnetx::range::IpRange;

let mut ba = IpSetBuilder::<Ipv4Addr>::new();
ba.add_range(IpRange::new(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 255)));
let a = ba.build(); // wider range

let mut bb = IpSetBuilder::<Ipv4Addr>::new();
bb.add_range(IpRange::new(Ipv4Addr::new(10, 0, 0, 50), Ipv4Addr::new(10, 0, 0, 100)));
let b = bb.build(); // narrower range, fully inside a

assert!(b.is_subset_of(&a));    // b ⊆ a
assert!(a.is_superset_of(&b));  // a ⊇ b
assert!(!a.is_subset_of(&b));   // a is strictly larger
```

### Collecting from iterators

`IpSetBuilder` implements `FromIterator` for both `IpRange` and `IpPrefix`,
so you can build a set from any iterator using `.collect()`:

```rust
use std::net::Ipv4Addr;
use ipnetx::ipset::IpSetBuilder;
use ipnetx::prefix::IpPrefix;
use ipnetx::range::IpRange;

// From a Vec of ranges
let ranges = vec![
    IpRange::new(Ipv4Addr::new(10, 0, 0, 0),    Ipv4Addr::new(10, 0, 0, 255)),
    IpRange::new(Ipv4Addr::new(192, 168, 1, 0), Ipv4Addr::new(192, 168, 1, 255)),
];
let set = ranges.into_iter().collect::<IpSetBuilder<Ipv4Addr>>().build();
assert_eq!(set.len(), 2);

// From a Vec of prefixes — useful when loading CIDR lists from config
let prefixes = vec![
    IpPrefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap(),
    IpPrefix::new(Ipv4Addr::new(192, 168, 0, 0), 16).unwrap(),
];
let set = prefixes.into_iter().collect::<IpSetBuilder<Ipv4Addr>>().build();
assert!(set.contains_ip(Ipv4Addr::new(10, 1, 2, 3)));
assert!(set.contains_ip(Ipv4Addr::new(192, 168, 1, 100)));
```

---

## API reference

Full documentation is available on [docs.rs/ipnetx](https://docs.rs/ipnetx).

---

## License

MIT — see [LICENSE](LICENSE).
