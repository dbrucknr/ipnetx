# Design: prefix-length-aware matching

**Status:** proposal — nothing here is implemented.
**Motivation:** route-policy prefix lists (`pathvector-policy`) and RPKI
origin validation (`pathvector-rpki`) both need to ask a question `IpSet`
cannot answer.

## 1. Problem

`IpSet` answers *address-coverage* questions: "is every address in this
prefix covered by the set?" Its `build()` normalizes by merging touching
ranges, which is exactly right for that question and exactly wrong for
*prefix-identity* questions.

Concrete example. A prefix list contains `10.0.0.0/25` and `10.0.0.128/25`
(exact match). Is the route `10.0.0.0/24` permitted?

| Question | Answer |
|---|---|
| `IpSet::contains_prefix(10.0.0.0/24)` — are all its addresses covered? | **true** — the two /25s merge into one `10.0.0.0/24` range |
| Prefix-list exact match of `10.0.0.0/24` | **false** — no entry is `10.0.0.0/24` |

Both answers are correct; they are different questions. Routing policy asks
the second one, and also needs length windows ("anything inside `10/8`
between /16 and /24"). That needs a separate abstraction that **never merges
across prefix boundaries**.

## 2. Semantics

### 2.1 Entry

An entry is a triple `(P, ge, le)` where `P` is a prefix of length `p`
(host bits zeroed — see §4.3) and:

```
p ≤ ge ≤ le ≤ BITS          (BITS = 32 for IPv4, 128 for IPv6)
```

### 2.2 Match

A route prefix `R` of length `L` matches the entry iff **all** hold:

1. `L ≥ p` — a route cannot be shorter than the entry it sits inside.
2. The top `p` bits of `R` equal those of `P` — i.e. `R ⊆ P`.
3. `ge ≤ L ≤ le`.

Host bits of `R` are ignored (`R` is compared as if masked), consistent with
`IpSet::contains_prefix`.

### 2.3 Defaults and constructors

| Intent | `ge` | `le` | Constructor (sketch) |
|---|---|---|---|
| exact | `p` | `p` | `PrefixMatch::exact(P)` |
| `ge N` only | `N` | `BITS` | `PrefixMatch::range(P, N, BITS)` |
| `le N` only | `p` | `N` | `PrefixMatch::up_to(P, N)` |
| `ge N le M` | `N` | `M` | `PrefixMatch::range(P, N, M)` |
| P and everything inside it ("or-longer") | `p` | `BITS` | `PrefixMatch::or_longer(P)` |
| strictly inside P ("longer") | `p+1` | `BITS` | `PrefixMatch::longer(P)` — error if `p == BITS` |
| RPKI ROA `(P, maxLength = m)` | `p` | `m` | `PrefixMatch::up_to(P, m)` |

Vendor conventions this is intended to line up with (**to be verified
against current vendor docs before the semantics are frozen** — see §8):
Cisco `ip prefix-list … ge/le`; Juniper route-filter match types
(`exact`, `orlonger`, `longer`, `upto`, `prefix-length-range`); GoBGP
`masklength-range`; RFC 6811 `maxLength`.

### 2.4 Edge cases (each becomes a test)

| Case | Expected |
|---|---|
| `0.0.0.0/0` exact | matches only the default route `0.0.0.0/0` |
| `0.0.0.0/0 le 32` | matches every IPv4 prefix |
| `ge == le` | single-length window |
| `le == BITS` | open-ended on the long side |
| `ge < p` | **rejected** (`InvalidLengthRange`): no route can satisfy it, so it is a config mistake, not a window to clamp silently |
| `le < ge`, `le > BITS` | rejected |
| `/32` or `/128` exact | matches that host route only |
| entry has host bits (`10.1.2.3/8`) | see §4.3 |
| route has host bits (`10.1.2.3/24`) | masked before comparison |
| v4 entry vs v6 route | unrepresentable — `A` is a type parameter |

## 3. Preserving prefix boundaries

The rule: **normalization may only be applied where it cannot change the
match function.**

Allowed (lossless for matching):

- Entries with the same `P` are merged by **unioning their length windows**.
  `(10/8, 16..16)` ∪ `(10/8, 24..24)` ⇒ lengths `{16, 24}` under `10/8`.
  The result is a *set of lengths*, not necessarily one contiguous window,
  so storage is a length bitset, not a `(ge, le)` pair.

Not allowed:

- Merging across different prefixes (sibling /25s → /24). This is the
  `IpSet` behavior we are deliberately *not* reproducing.
- Dropping an entry because another entry "subsumes" it
  (`10/8 le 24` subsumes `10.1/16 exact`). Matching is unchanged, but the
  user's configured entries are lost, which hurts config round-tripping and
  `show` output. Offer it as an explicit, opt-in `compact()`; never do it in
  `build()`.

Property to test: for any entry list, `build()` followed by `matches` equals
a naive linear scan of the original entries.

## 4. API sketch

```rust
// SKETCH — not implemented.

/// One prefix-list entry. Invariant: p <= min_len <= max_len <= A::BITS.
pub struct PrefixMatch<A: IpAddress> {
    prefix: IpPrefix<A>,   // canonical (host bits zero); see §4.3
    min_len: u8,
    max_len: u8,
}

#[derive(Debug, PartialEq, Eq)]
pub enum InvalidLengthRange { BelowPrefixLen, MinAboveMax, AboveAddrBits }

impl<A: IpAddress> PrefixMatch<A> {
    pub fn exact(prefix: IpPrefix<A>) -> Self;
    pub fn or_longer(prefix: IpPrefix<A>) -> Self;
    pub fn longer(prefix: IpPrefix<A>) -> Result<Self, InvalidLengthRange>;
    pub fn up_to(prefix: IpPrefix<A>, le: u8) -> Result<Self, InvalidLengthRange>;
    pub fn range(prefix: IpPrefix<A>, ge: u8, le: u8) -> Result<Self, InvalidLengthRange>;

    pub fn prefix(&self) -> IpPrefix<A>;
    pub fn min_len(&self) -> u8;
    pub fn max_len(&self) -> u8;

    /// The §2.2 predicate.
    pub fn matches(&self, route: IpPrefix<A>) -> bool;
}

/// Unordered collection of entries with a payload.
/// `PrefixMatchSet<A>` would be `PrefixMatchMap<A, ()>`.
pub struct PrefixMatchMap<A: IpAddress, V> { /* see §5 */ }

impl<A: IpAddress, V> PrefixMatchMap<A, V> {
    pub fn insert(&mut self, entry: PrefixMatch<A>, value: V);
    pub fn matches(&self, route: IpPrefix<A>) -> bool;
    /// Every entry matching `route`, with its payload. Needed by RPKI (§6).
    pub fn matching(&self, route: IpPrefix<A>) -> impl Iterator<Item = (&PrefixMatch<A>, &V)>;
    pub fn len(&self) -> usize;
}
```

Optional: `FromStr` for the textual form `10.0.0.0/8 ge 16 le 24`.

### 4.3 Host bits on the entry side

Two choices: mask silently, or reject. Recommendation: **take a canonical
prefix** (see `canonical-prefix.md`) so the question is answered at the
type boundary, and until that exists, have the constructors mask (matching
`IpPrefix::to_range` and `routemap`) and document it. Rejecting is better
for config validation (pathvector's `BlackholeScope` already rejects host
bits, `blackhole.rs:101-108`) — that is a caller policy, not a matcher one.

## 5. Data-structure options

Let `n` = entries, `G` = distinct entry prefix lengths present (real lists:
typically ≤ ~10; worst case 33 / 129), `L` = route length.

| Option | Structure | Query | Notes |
|---|---|---|---|
| A. Linear | `Vec<(PrefixMatch, V)>` | O(n) | Trivial; keep as the **test oracle** and for small/ordered lists |
| B. Tuple-space | per-`p` group: sorted `Vec<(net_bits, LenSet, V)>`; query masks `R` to each `p ≤ L` and binary-searches | O(G · log n) | No trie, no dependency, self-contained in ipnetx. Good fit for large unordered lists (e.g. IRR-generated, tens of thousands of entries) |
| C. Trie with inherited length sets | `routemap` node value = `LenSet`; each node's *effective* set = own ∪ ancestors' | O(depth) | Needs a "deepest stored prefix covering this **prefix**" lookup in routemap, which does not exist today (`longest_match` is per-address). Natural once routemap grows a `covering` API (§6) |

`LenSet` needs 129 bits for IPv6 (lengths 0..=128): e.g. `[u64; 3]`. For IPv4
a `u64` suffices.

**Recommendation:** ship A (oracle) + B in ipnetx; revisit C when routemap
has `covering`, gated by a benchmark. Benchmarks must use separated entries
and assert stored counts (the lesson of the `make_set` bug fixed in the
`contains_prefix` PR), at 100 / 1k / 10k plus a 50k "IRR-shaped" list with
`le 24`.

## 6. Relationship to the rest of the stack

- **Ordered permit/deny prefix lists** (sequence numbers, first match wins)
  stay in `pathvector-policy`. `PrefixMatch::matches` is the per-entry
  primitive they iterate. `PrefixMatchMap` is for *large unordered* sets
  where order is irrelevant.
- **RPKI route origin validation** is the same predicate:
  a ROA `(P, maxLength, ASN)` is `(P, ge = p, le = maxLength)` and RFC 6811
  needs **every** covering entry (a less-specific ROA can validate where the
  most-specific one does not), not a boolean. Today
  `pathvector-rpki/src/table.rs:99-139` does an `longest_match_entry`
  short-circuit then up to `prefix_len + 1` exact `get()` calls, each
  building a host-bit-carrying `IpPrefix::new(prefix, len)`. A
  `matching()` iterator (option B or C) replaces that loop. This is why the
  map carries a payload `V` from the start.
- **`IpSet`** remains the tool for address-space algebra. A lossy
  `PrefixMatchMap::covered_space() -> IpSet<A>` is possible but must be named
  to make the loss obvious; it is not part of the first cut.

## 7. Test plan

1. Proptest: `PrefixMatchMap::matches` ≡ linear scan over inserted entries
   (random entries, random routes, both families, lengths including 0 and
   BITS).
2. Table-driven edge cases from §2.4.
3. Vendor-convention conformance cases (after §8 verification).
4. Property: inserting entries in any order yields the same match function.
5. Extend `fuzz/` with a target for construct-then-match (no panics; invalid
   ranges rejected, never clamped).
6. Benchmarks per §5.

## 8. Open questions

1. **Vendor semantics** — confirm `ge`/`le`, Juniper modifiers, GoBGP
   `masklength-range` and RFC 6811 behavior from primary docs before
   freezing §2.3; I wrote the table from memory of those conventions.
2. **Map vs set first** — `PrefixMatchMap<A, V>` with `()` as the set case
   (recommended, because RPKI needs payloads) or a set now and a map later.
3. **Where it lives** — ipnetx (recommended: pure data, no trie needed for
   option B) vs `routemap` (only needed for option C).
4. **Strictness** — reject `ge < p` (recommended) vs clamp.
5. **Textual form** — whether `FromStr` for `P ge N le M` is in scope.

## 9. Staging

1. `PrefixMatch` + `InvalidLengthRange` + tests (additive, semver-compatible
   with 0.3.x).
2. `PrefixMatchMap` option A, then B behind the same API; benchmarks.
3. `pathvector-policy` adopts for large lists; `pathvector-rpki` adopts
   `matching()`.
