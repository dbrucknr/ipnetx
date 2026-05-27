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
| `Prefix() (Prefix, bool)` | ❌ | Returns a single CIDR prefix if the range is exactly CIDR-aligned, `None` otherwise |

### `IpPrefix`

| Go `netip.Prefix` | Status | Notes |
|---|---|---|
| `Addr()` / `Bits()` | ✅ `ip()` / `mask()` | |
| `Contains(ip)` | ✅ `contains(ip)` | |
| `Range()` | ✅ `to_range()` | |
| `String()` | ✅ `Display` | |
| `Masked()` | ❌ | Zeroes host bits — `192.168.1.100/24` → `192.168.1.0/24` |
| `IsSingleIP()` | ❌ | `mask == A::BITS` — trivial once added |
| `Overlaps(prefix)` | ❌ | Can be expressed via `to_range()` + `IpRange::overlaps` but a direct method would be cleaner |

### `IpSetBuilder`

| Go `netipx.IPSetBuilder` | Status | Notes |
|---|---|---|
| `AddRange(r)` | ✅ `add_range(r)` | |
| `AddPrefix(p)` | ✅ `add_prefix(p)` | |
| `Add(ip)` | ❌ | Convenience — equivalent to `add_range` with `start == end` |
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
  `"10.0.0.1-10.0.0.255".parse::<IpRange<Ipv4Addr>>()`. Biggest ergonomics gap for real-world use.
- **Serde support** — gate behind a `serde` feature flag; standard practice for Rust networking crates.

---

## Before publishing to crates.io

- Add `description`, `license`, `repository`, `keywords`, `categories`, `readme` to `Cargo.toml` (Done)
- Add a `LICENSE` file (Done)
- Rewrite `README.md` as user-facing documentation with a usage example
- Add `///` doc comments to all public items (`cargo doc --open` to preview)
- Add `#[must_use]` to all predicate methods (`contains_ip`, `contains_range`, `is_valid`, `is_empty`, `overlaps`, etc.)
- Implement `Default` for `IpSetBuilder` (Clippy will warn otherwise)
- Run `cargo clippy -- -D warnings` and resolve all findings
- Run `cargo publish --dry-run` to catch any remaining crates.io rejections
