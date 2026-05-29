# TODO

## General
- Return to public modules and start thinking about Result / Option handling.
- Consider errors when necessary.

---

## Feature parity with Go's netipx

### `IpRange`

| Go `netipx.IPRange` | Status | Notes |
|---|---|---|
| `From()` / `To()` | ✅ `start()` / `end()` | |
| `Contains(ip)` | ✅ `contains(ip)` | |
| `Overlaps(range)` | ✅ `overlaps(range)` | |
| `Prefixes()` | ✅ `prefixes()` | |
| `IsZero()` | ✅ `is_zero()` | |
| `Valid()` | ✅ `is_valid()` | |
| `String()` | ✅ `Display` | |
| `Prefix() (Prefix, bool)` | ✅ | Returns a single CIDR prefix if the range is exactly CIDR-aligned, `None` otherwise |

### `IpPrefix`

| Go `netip.Prefix` | Status | Notes |
|---|---|---|
| `Addr()` / `Bits()` | ✅ `ip()` / `mask()` | |
| `Contains(ip)` | ✅ `contains(ip)` | |
| `Range()` | ✅ `to_range()` | |
| `String()` | ✅ `Display` | |
| `Masked()` | ✅ | Zeroes host bits — `192.168.1.100/24` → `192.168.1.0/24` |
| `IsSingleIP()` | ✅ | `mask == A::BITS` — trivial once added |
| `Overlaps(prefix)` | ✅ | Can be expressed via `to_range()` + `IpRange::overlaps` but a direct method would be cleaner |

### `IpSetBuilder`

| Go `netipx.IPSetBuilder` | Status | Notes |
|---|---|---|
| `AddRange(r)` | ✅ `add_range(r)` | |
| `AddPrefix(p)` | ✅ `add_prefix(p)` | |
| `Add(ip)` | ✅ `add_ip(ip)` | Convenience — equivalent to `add_range` with `start == end` |
| `RemoveRange(r)` | ✅ | Requires splitting stored ranges — see note below |
| `RemovePrefix(p)` | ✅ | Convert to range, then `remove_range` |
| `Remove(ip)` | ✅ | Single-address removal — special case of `remove_range` |

> **Note on remove operations:** removing from the middle of a stored range requires splitting it into up to two
> pieces. Five cases arise per stored range: no overlap (keep), fully covered (drop), clips left end (trim start),
> clips right end (trim end), removal in the middle (split into two).

### `IpSet`

| Go `netipx.IPSet` | Status | Notes |
|---|---|---|
| `Contains(ip)` | ✅ `contains_ip(ip)` | |
| `ContainsRange(r)` | ✅ `contains_range(r)` | |
| `Overlaps(set)` | ✅ `overlaps_ip_set(set)` | |
| `Ranges()` | ✅ `ranges()` | |
| `Prefixes()` | ✅ `prefixes()` | |

---

## Beyond netipx — ergonomics for Rust

- **`FromStr` / parsing** — `"192.168.1.0/24".parse::<IpPrefix<Ipv4Addr>>()` and
  `"10.0.0.1-10.0.0.255".parse::<IpRange<Ipv4Addr>>()`. Biggest ergonomics gap for real-world use. ✅
- **Serde support** — gate behind a `serde` feature flag; standard practice for Rust networking crates.

---

## Positioning — what makes ipnetx distinct from `ipnet`

The core differentiator is `IpSet` as a **proper mathematical set type**. No mainstream Rust IP crate
implements set algebra. With these operations, `ipnetx` becomes the go-to for firewall tooling, BGP
route analysis, threat intelligence ingestion, and network auditing.

### Tier 1 — set algebra (biggest gap in the ecosystem)

| Operation | Status | Example use case |
|---|---|---|
| `a.union(&b) -> IpSet` | ✅ | Merge two ACLs into one |
| `a.intersection(&b) -> IpSet` | ✅ | "Which IPs are in both our network and this threat feed?" |
| `a.difference(&b) -> IpSet` | ✅ | "Everything in the allow-list that isn't also in the block-list" |
| `a.complement() -> IpSet` | ✅ | "Every IP *not* covered by this set" — deny-by-default rules |

### Tier 2 — useful additions

| Feature | Status | Notes |
|---|---|---|
| `IpSet::count() -> u128` | ✅ | Total address cardinality, not just number of stored ranges |
| `IpSet::is_subset_of(&other)` | ✅ | Expressible via intersection but worth a named method |
| `IpSet::is_superset_of(&other)` | ✅ | Symmetric counterpart to `is_subset_of` |
| `FromIterator<IpPrefix<A>>` for `IpSetBuilder` | ✅ | `prefixes.into_iter().collect::<IpSetBuilder<_>>()` |
| `FromIterator<IpRange<A>>` for `IpSetBuilder` | ✅ | Same ergonomics for ranges |

### Tier 3 — table stakes

| Feature | Status | Notes |
|---|---|---|
| Serde support | ❌ | Gate behind a `serde` feature flag; expected by anyone using JSON/TOML config |

---

## Known deficits and improvements

### Priority 1 — correctness debt

- **Fix `difference()` to O(m+n)** ✅ — replaced the O(m×n) `subtract_range` loop with a two-pointer walk matching the approach used in `intersection()`.

### Priority 2 — ecosystem reach

- **Serde support** — gate behind a `serde` feature flag. Required by anyone loading sets from JSON/TOML config, serializing to Redis, or deserializing threat intel from an API. Most commonly requested feature for networking crates. (Also tracked in Tier 3 above.)

### Priority 3 — ergonomics

- **`IntoIterator` for `&IpSet`** — users cannot currently do `for range in &set { ... }` or chain `IpSet` into iterator adapters. `impl IntoIterator for &IpSet<A>` is a small addition that makes the type feel complete.
- **`PartialOrd` / `Ord` on `IpRange` and `IpPrefix`** — these types have a natural ordering by start address but the traits are not implemented. Needed to sort a `Vec<IpRange>` without a custom comparator or use them in a `BTreeSet`.
- **Builder introspection** — `IpSetBuilder` is append-only until `build()` is called. A `len()` or `is_empty()` on the builder would occasionally be useful without requiring a full `build()`.

---

## Before publishing to crates.io

- Add `description`, `license`, `repository`, `keywords`, `categories`, `readme` to `Cargo.toml` ✅
- Add a `LICENSE` file ✅
- Rewrite `README.md` as user-facing documentation with a usage example~~ ✅
- Add `///` doc comments to all public items (`cargo doc --open` to preview)~~ ✅
- Add `#[must_use]` to all predicate methods (`contains_ip`, `contains_range`, `is_valid`, `is_empty`, `overlaps`, etc.)~~ ✅
- Implement `Default` for `IpSetBuilder` (Clippy will warn otherwise)~~ ✅
- Run `cargo clippy -- -D warnings` and resolve all findings~~ ✅
- Run `cargo publish --dry-run` to catch any remaining crates.io rejections
