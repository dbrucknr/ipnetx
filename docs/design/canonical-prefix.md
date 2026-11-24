# Design sketch: opt-in canonical prefix type

**Status:** proposal — nothing here is implemented.
**Scope:** how an opt-in `CanonicalPrefix<A>` would integrate with
pathvector's hash-map keys and `routemap`'s API, and — honestly — where
normalization work can and cannot be removed.

Line references are from a read-through of `pathvector` and `routemap` on
2026-11-24 and will drift.

## 1. Problem

`IpPrefix<A>` preserves host bits and derives `PartialEq`/`Eq`/`Hash` over
the raw address, so `192.168.1.100/24` and `192.168.1.0/24` are *different
values* that denote the *same network*. Every consumer that treats a prefix
as a network identity must therefore canonicalize by convention. Today that
convention is enforced in some places and merely assumed in others.

### 1.1 Where canonical form is enforced at runtime

| Site | What it does |
|---|---|
| `pathvector-session/src/message/update.rs:292-293, 307-308` | wire decode: `Nlri::new(..).map(Nlri::masked)` |
| `pathvectord/src/blackhole.rs:101-108` | parses `Nlri`, rejects if `n.masked() != n` |
| `routemap/src/treebitmap/mod.rs:132, 296, 338, 422` | `insert`/`remove`/`get`/`contains` all call `prefix.masked()` |
| `routemap/src/treebitmap/mod.rs:218` | `longest_match_entry` rebuilds then `.masked()` |
| `routemap/src/arena/table.rs:19, 62, 74` | same, arena layout |
| `pathvector-policy/src/condition.rs:97` | `prefix().masked().to_range()` (already redundant: `to_range` masks) |
| `pathvector-policy/src/testutil.rs:50` | a test fixture exists to verify conditions call `.masked()` |

### 1.2 Where canonical form is assumed, not enforced

`Nlri<A>` derives `Hash`/`Eq` over a host-bit-preserving `IpPrefix`
(`pathvector-types/src/nlri.rs:57`) and is the key of:

- `AdjRibIn` — `adj_rib_in.rs:45`; `AdjRibOut` — `adj_rib_out.rs:80`
- `LocRib` — `CandidateMap` `(Nlri, PeerId)` at `loc_rib.rs:185`, `PeerIndex`
  at `loc_rib.rs:192`
- `FibManager` pending maps — `pathvectord/src/fib.rs:150-151, 270-271,
  402-403, 999-1000`

`Nlri::new` is public and documents that host bits are preserved
(`nlri.rs`, constructor docs), and `Nlri::from_prefix` wraps any `IpPrefix`
unchanged.

### 1.3 A latent inconsistency this allows (by code reading — not reproduced)

`LocRib::insert` (`loc_rib.rs:247-258`) stores `candidates` and `peer_index`
under the **raw** `route.nlri`, but reads/writes `best` through `RouteMap`,
which **masks**. `best_routes()` and `longest_match()`
(`loc_rib.rs:348-364`) then take the *masked* prefix coming back out of
`RouteMap`, wrap it with `Nlri::from_prefix`, and look it up in
`candidates`. If a route with host bits ever reached `LocRib::insert`, the
`candidates.get` would miss and the route would silently vanish from
`best_routes()` and forwarding lookups.

Wire decode masks, so this is not reachable from a peer today. It is
reachable from any other path that builds an `Nlri` with host bits (the
public constructor, tests, a future API/static-route injector). The point is
that correctness currently depends on a convention the type system does not
express.

## 2. Proposed type

```rust
// SKETCH — not implemented.

/// A prefix whose host bits are guaranteed zero. Same layout as IpPrefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CanonicalPrefix<A: IpAddress> { ip: A, mask: u8 }   // fields private

pub enum CanonicalPrefixError { InvalidLen, HostBitsSet }

impl<A: IpAddress> CanonicalPrefix<A> {
    /// Strict: rejects host bits.
    pub fn new(ip: A, mask: u8) -> Result<Self, CanonicalPrefixError>;
    /// Lenient: zeroes host bits (the `IpPrefix::masked` behavior).
    pub fn new_masked(ip: A, mask: u8) -> Result<Self, InvalidPrefixLen>;

    pub fn ip(&self) -> A;
    pub fn mask(&self) -> u8;
    pub fn to_range(&self) -> IpRange<A>;       // no masking needed
    pub fn as_prefix(&self) -> IpPrefix<A>;
}

impl<A: IpAddress> IpPrefix<A> {
    pub fn canonical(&self) -> CanonicalPrefix<A>;            // masks
}
impl<A> From<CanonicalPrefix<A>> for IpPrefix<A> { .. }      // free
impl<A> TryFrom<IpPrefix<A>> for CanonicalPrefix<A> { .. }   // strict
impl<A> FromStr for CanonicalPrefix<A> { .. }                // strict
```

Design choices and why:

- **Private fields, no `unsafe`, no unchecked constructor.** The invariant is
  the whole point; an escape hatch defeats it. A consumer that already holds
  masked bits just calls `new_masked`, whose cost is the masking we are
  discussing in §4.
- **`FromStr` is strict.** A canonical type that silently accepts
  `10.0.0.1/8` is not canonical-by-construction in a useful sense. Callers
  wanting leniency parse `IpPrefix` then `.canonical()`.
- **Derive `Ord`.** `IpPrefix` has none today. A canonical type can have a
  total order `(ip, mask)`, giving `BTreeMap` keys and deterministic RIB
  dumps for free. (Ordering is meaningful only because equal networks are
  equal values.)
- **No `Deref` to `IpPrefix`**; explicit `as_prefix()` / `From`.
- **Layout is unchanged** (same two fields), so no memory cost in a RIB.
- **Opt-in.** `IpPrefix` behavior is unchanged; nothing breaks for existing
  users of `ipnetx`.

## 3. Integration

### 3.1 pathvector `Nlri`

Make `Nlri<A>` wrap `CanonicalPrefix<A>` instead of `IpPrefix<A>`. Its
derived `Hash`/`Eq` then mean "same network" by construction, and every map
in §1.2 is correct by type instead of by convention (and §1.3 becomes
unrepresentable). pathvector is pre-1.0, so a workspace-internal breaking
change is cheap.

Constructors need to separate two intents that `Nlri::new` currently blurs:

- strict (config, CLI): `Nlri::new` → `Result`, rejecting host bits
- tolerant (wire decode): `Nlri::from_wire(octets, len)` → masks once

### 3.2 routemap

Today every mutating/query method masks its argument. Two ways to adopt the
type:

| Option | Shape | Verdict |
|---|---|---|
| (a) Take `CanonicalPrefix<A>` only; iterators/`longest_match_entry` return it | breaking → routemap 0.2.0 | **Recommended.** Clean; `"10.0.0.0/8".parse().unwrap()` still infers (target type is `CanonicalPrefix`) |
| (b) Generic `impl Into<CanonicalPrefix<A>>` for source compatibility | additive | **Likely breaks type inference** for the pervasive `table.get("…".parse().unwrap())` pattern in routemap's own doctests and user code (the `parse` target becomes ambiguous). I have not compiled this — a spike should confirm before ruling it out |
| (c) Parallel `*_canonical` methods | additive | Doubles the API surface; only worth it as a transition |

Under (a), routemap's tests that deliberately insert host-bit prefixes to
prove masking (e.g. `unmasked_insert_equals_masked_insert`,
`remove_with_unmasked_prefix_finds_entry`) move to
`IpPrefix::new(..).canonical()` at the call site — the property they test
becomes "`canonical()` is idempotent and routemap never sees host bits".

### 3.3 pathvector-rpki

`validate` (`table.rs:99-139`) builds `IpPrefix::new(prefix, len)` for every
`len` from `prefix_len` down to 0 and calls `get` on each. Those prefixes
**carry host bits** (`prefix` is the query's base address), so routemap's
masking on `get` is doing real work on every iteration. A canonical type
alone fixes the typing; combined with the `covering`/`matching` iteration
discussed in `prefix-length-matching.md` §6, the loop disappears and the
ancestors are canonical by construction.

## 4. Where normalization can actually be removed

Being precise here matters; the earlier `contains_prefix` work showed that
plausible-looking redundancy can already be optimized away by the compiler.

| Site | Today | With `CanonicalPrefix` | Net |
|---|---|---|---|
| routemap input paths (`insert/get/remove/contains`) | always masks | no-op when caller already holds canonical | **Removed** for canonical callers (pathvector `Nlri`); it moves to `canonical()` for anyone still starting from `IpPrefix` |
| routemap output (`iter`, `longest_match_entry`, `treebitmap/mod.rs:218`) | constructs canonical, then `.masked()` | return type becomes `CanonicalPrefix` | **Not removed** — the mask *is* the construction; the type now just records what was already true |
| wire decode (`update.rs:292,307`) | `Nlri::new` then `masked` | single `Nlri::from_wire` | **Not removed** — wire bytes may legally carry garbage trailing bits, so one mask per decoded NLRI remains. Consolidated, not eliminated |
| `blackhole.rs:101-108` | parse, compare `masked()`, reject | strict `FromStr` error | **Removed** as code; validation becomes type-level |
| `condition.rs:97` | `masked().to_range()` | `IpSet::contains_prefix(prefix)` | Already addressed by `contains_prefix`; canonical type adds only a skipped AND inside `to_range` |
| `testutil.rs:50` fixture | verifies conditions call `.masked()` | unrepresentable | **Removed** |
| RIB hash keys (§1.2) | convention | guaranteed | No runtime work removed; removes a failure mode (§1.3) |
| rpki `validate` loop (§3.3) | up to `prefix_len + 1` masked `get`s | canonical ancestors, ideally one walk | **Removed**, mostly via the `covering` API rather than the type |

**Performance is unmeasured.** Masking a prefix is a handful of integer ops
(`network_mask` uses one `checked_shl`), against a trie walk of tens of
nanoseconds. I expect the per-call saving in routemap to be small and will
not claim a speedup without a routemap benchmark comparing `get` on
`IpPrefix` (masks) vs `CanonicalPrefix` (does not). The defensible value
today is correctness-by-construction (§1.3), not speed.

## 5. Staging

Each stage is independently shippable and reviewable:

1. **ipnetx** (additive; a 0.3.x release): `CanonicalPrefix`, conversions,
   tests (idempotence, strict/lenient, `Ord`, `Hash` agrees with network
   identity).
2. **routemap** 0.2.0: option (a) from §3.2; benchmark per §4. Add the
   `covering` iteration here if the length-matching design is pursued.
3. **pathvector-types / -rib / -session**: `Nlri` over `CanonicalPrefix`;
   `from_wire`; delete `blackhole.rs` host-bit check and the `testutil`
   fixture. Add a `LocRib` regression test for §1.3 *first*, on the current
   code, to confirm the inconsistency is real before relying on it as
   motivation.
4. **pathvector-rpki**: switch `validate` to the covering iteration.

## 6. Risks and open questions

- **Two prefix types** in the public surface of `ipnetx`; guidance on which
  to use must be clear in the README.
- **Naming:** `CanonicalPrefix` vs `Network` vs `NetPrefix`.
- **Strict vs lenient `FromStr`** (recommended strict) and what that does to
  user-facing config errors.
- **Serde** (if ever added): `Deserialize` must validate, not trust.
- **`IpSetBuilder::add_prefix` / `IpSet::contains_prefix`** take `IpPrefix`;
  accepting `Into<IpPrefix>` would let canonical values flow in without
  `.as_prefix()` noise, but should be checked for the same inference
  hazard as §3.2(b).
- **Verify §1.3** with a reproducing test before it is cited as a bug
  rather than a latent hazard.
