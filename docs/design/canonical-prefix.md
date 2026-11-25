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

### 1.3 A reproduced inconsistency in `LocRib` (pathvector #71)

`LocRib::insert` (`loc_rib.rs:247-258`) stores `candidates` and `peer_index`
under the **raw** `route.nlri`, but reads/writes `best` through `RouteMap`,
which **masks**. `best_routes()` and `longest_match()`
(`loc_rib.rs:348-364`) then take the *masked* prefix coming back out of
`RouteMap`, wrap it with `Nlri::from_prefix`, and look it up in
`candidates`, which misses.

**Reproduced** (public API, pathvector commit `4b5cf3a6`, no production
code changed — see
[pathvector #71](https://github.com/dbrucknr/pathvector/issues/71#issuecomment-7145528693)):
inserting a route for `192.0.2.129/24` leaves `len=1`, `best(raw)=true`,
but `best_routes()` yields `0` routes and `longest_match(192.0.2.1)` is
`None`.

Scope, as stated in the issue: this is a **public-library defect**, not a
demonstrated peer-triggerable bug — the session's IPv4/IPv6 NLRI decoders
mask their input — and it predates the canonical-prefix discussion. The
issue's position is that it **should be fixed independently of** a
`CanonicalPrefix` type; this design does not depend on that fix and the fix
does not depend on this design. The type would make the *class* of bug
unrepresentable; it is not the remedy for #71.

## 2. Proposed type

```rust
// SKETCH — not implemented.

/// A prefix whose host bits are guaranteed zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CanonicalPrefix<A: IpAddress> { ip: A, mask: u8 }   // fields private

pub enum CanonicalPrefixError { InvalidLen, HostBitsSet }

impl<A: IpAddress> CanonicalPrefix<A> {
    /// Normalizing constructor: zeroes host bits (the `IpPrefix::masked`
    /// behavior). This ALONE guarantees the invariant — every value of the
    /// type is canonical regardless of how it was built.
    pub fn new(ip: A, mask: u8) -> Result<Self, InvalidPrefixLen>;

    /// Validation helper (optional, a caller-policy convenience): like `new`
    /// but returns `HostBitsSet` instead of masking. Does not strengthen the
    /// invariant; it only lets a caller reject non-canonical *input*.
    pub fn try_new_strict(ip: A, mask: u8) -> Result<Self, CanonicalPrefixError>;

    pub fn ip(&self) -> A;
    pub fn mask(&self) -> u8;
    pub fn to_range(&self) -> IpRange<A>;       // no masking needed
    pub fn as_prefix(&self) -> IpPrefix<A>;
}

impl<A: IpAddress> IpPrefix<A> {
    pub fn canonical(&self) -> CanonicalPrefix<A>;            // masks
}
impl<A> From<CanonicalPrefix<A>> for IpPrefix<A> { .. }      // free
impl<A> FromStr for CanonicalPrefix<A> { .. }                // policy: see below
```

Design choices and why:

- **Private fields, no `unsafe`, no unchecked constructor.** The invariant is
  the whole point; an escape hatch defeats it. A consumer that already holds
  masked bits just calls `new`, whose cost is the masking we are
  discussing in §4.
- **Normalization and validation are different things.** A constructor that
  masks input still yields canonical output, so canonical-by-construction
  storage does **not** require strict parsing. Rejecting host bits is a
  *configuration policy* (useful where a user typing `10.0.0.1/8` has
  probably made a mistake, irrelevant for wire decode where trailing bits
  are legal and must simply be dropped). The type supplies both tools
  (`new`, `try_new_strict`) and callers choose.
- **`FromStr` policy is an open question** (§6), not a requirement of the
  design: masking `FromStr` keeps routemap-style call sites such as
  `table.get("10.0.0.1/8".parse().unwrap())` working; strict `FromStr`
  surfaces mistakes earlier but would turn today's masking-dependent
  doctests/tests into runtime failures. Either choice preserves the
  invariant.
- **Derive `Ord`.** `IpPrefix` has none today. A canonical type can have a
  total order `(ip, mask)`, giving `BTreeMap` keys and deterministic RIB
  dumps for free. (Ordering is meaningful only because equal networks are
  equal values.)
- **No `Deref` to `IpPrefix`**; explicit `as_prefix()` / `From`.
- **Representation:** the proposed type has the same fields as `IpPrefix`.
  Rust layout and downstream RIB memory costs must be checked before making
  a size or ABI guarantee.
- **Opt-in.** `IpPrefix` behavior is unchanged; nothing breaks for existing
  users of `ipnetx`.

## 3. Integration

### 3.1 pathvector `Nlri`

One possible, separately decided adoption would make `Nlri<A>` wrap
`CanonicalPrefix<A>` instead of `IpPrefix<A>`. Its
derived `Hash`/`Eq` then mean "same network" by construction, and every map
in §1.2 is correct by type instead of by convention (and §1.3 becomes
unrepresentable). This is a semantic API migration whose costs have not
been established; being pre-1.0 does not establish that it is cheap. It is
not proposed as part of the standalone predicate or as the fix for #71.

Because the wrapped type masks on construction, **`Nlri::new` can keep its
signature** (`Result<_, InvalidPrefixLen>`) while its documented behavior
changes from "host bits are preserved" to "host bits are zeroed" — a
semantic change that must be called out in the pathvector changelog. Callers
that need *rejection* (config, CLI) opt in explicitly via the strict helper;
wire decode keeps masking via the normal constructor and can drop its
separate `.map(Nlri::masked)` step.

### 3.2 routemap — options stay open

Today every mutating/query method masks its argument. Candidate adoptions:

| Option | Shape | Status |
|---|---|---|
| (a) Take `CanonicalPrefix<A>` only; iterators/`longest_match_entry` return it | breaking → routemap 0.2.0 | **Undecided.** Requires validation against real signatures and callers |
| (b) Generic `impl Into<CanonicalPrefix<A>>` for source compatibility | additive | **Inference breakage confirmed on a minimal model** (below); may still be viable with annotations or a different shape |
| (c) Parallel `*_canonical` methods | additive | Doubles the API surface; only worth it as a transition |

**Compatibility spike (minimal model, not routemap itself).** A scratch crate
with `Raw`/`Canon` types, `impl From<Raw> for Canon`, and both signatures
(`fn get_canon(&self, p: Canon)` and `fn get_generic<P: Into<Canon>>(&self, p: P)`):

| Call | Result |
|---|---|
| `get_canon("10.0.0.0/8".parse().unwrap())` | compiles — `parse` target inferred as `Canon` |
| `get_generic("10.0.0.0/8".parse().unwrap())` | **E0283 type annotations needed** — `parse`'s target is ambiguous under an `Into` bound |
| `get_generic("10.0.0.0/8".parse::<Raw>().unwrap())` | compiles — needs an annotation at every call site |

So (b) is source-compatible for typed arguments but **not** for the bare
`.parse().unwrap()` pattern. What this does *not* establish: the real
migration cost. Remaining spike work before choosing:

1. Repeat the check against routemap's actual signatures (generic
   `A: IpAddress`, `V`), including its doctests.
2. **Size the migration.** Rough greps (to be tightened, not authoritative):
   about 245 routemap source/README/docs lines pass `.parse()` into
   `insert`/`get`/`remove`/`contains`; 4 tests deliberately exercise
   unmasked input; about 23 non-test `RouteMap` call sites in
   `pathvector-rib` and `pathvector-rpki`; three pathvector crates depend on
   routemap (`policy`, `rib`, `rpki`). Under (a) the `.parse()` sites keep
   compiling (the target infers as `CanonicalPrefix`), so the cost
   concentrates in tests that rely on masking and in call sites that build
   `IpPrefix` values explicitly. Under (b) each bare `.parse()` site needs
   an annotation.
3. Decide the `FromStr` policy (§6), since it determines whether those
   `.parse()` sites with host bits keep working under (a).
4. Measure per §4 so a performance argument, if any, is based on data.

Do not cut routemap 0.2.0 until 1–4 are done.

If (a) is chosen, the routemap tests that deliberately insert host-bit
prefixes to prove masking (e.g. `unmasked_insert_equals_masked_insert`,
`remove_with_unmasked_prefix_finds_entry`) move the property to the type:
"`CanonicalPrefix::new` is idempotent and routemap never sees host bits".

### 3.3 pathvector-rpki

`validate` (`table.rs:99-139`) builds `IpPrefix::new(prefix, len)` for every
`len` from `prefix_len` down to 0 and calls `get` on each. Those prefixes
**carry host bits** (`prefix` is the query's base address), so routemap's
masking on `get` is doing real work on every iteration. A canonical type
alone fixes the typing. Removing the loop needs **covering enumeration** —
the generic `RouteMap::covering` explored in
`routemap-covering-iterator.md`, with `pathvector-rpki` applying its own
RFC 6811 predicate to every covering entry. A window-filtered iterator would
drop covering VRPs whose `maxLength` excludes the route and turn `Invalid`
into `NotFound` (RFC 6811 §2). With a covering iteration the ancestors are
canonical by construction and the per-length masked `get` calls disappear.

## 4. Where normalization can actually be removed

Being precise here matters; the earlier `contains_prefix` work showed that
plausible-looking redundancy can already be optimized away by the compiler.

| Site | Today | With `CanonicalPrefix` | Net |
|---|---|---|---|
| routemap input paths (`insert/get/remove/contains`) | always masks | no-op when caller already holds canonical | **Removed** for canonical callers (pathvector `Nlri`); it moves to `canonical()` for anyone still starting from `IpPrefix` |
| routemap output (`iter`, `longest_match_entry`, `treebitmap/mod.rs:218`) | constructs canonical, then `.masked()` | return type becomes `CanonicalPrefix` | **Not removed** — the mask *is* the construction; the type now just records what was already true |
| wire decode (`update.rs:292,307`) | `Nlri::new` then `masked` | single `Nlri::from_wire` | **Not removed** — wire bytes may legally carry garbage trailing bits, so one mask per decoded NLRI remains. Consolidated, not eliminated |
| `blackhole.rs:101-108` | parse, compare `masked()`, reject | `try_new_strict` (or a strict parse) returns `HostBitsSet` | **Moved, not eliminated.** The host-bit check still runs once per configured prefix; only the ad-hoc `n.masked() != n` comparison is replaced by the type's validation helper. Strictness here is a config policy the blackhole loader keeps |
| `condition.rs:97` | `masked().to_range()` | `IpSet::contains_prefix(prefix)` | Already addressed by `contains_prefix`; canonical type adds only a skipped AND inside `to_range` |
| `testutil.rs:50` fixture | verifies conditions call `.masked()` | unrepresentable | **Removed** |
| RIB hash keys (§1.2) | convention | guaranteed | No runtime work removed; removes a failure mode (§1.3) |
| rpki `validate` loop (§3.3) | up to `prefix_len + 1` masked `get`s | canonical ancestors from a covering enumeration | **Removed**, via the covering API rather than the type; requires covering (not just matching) entries to preserve `Invalid` vs `NotFound` |

**Performance is unmeasured.** Masking a prefix is a handful of integer ops
(`network_mask` uses one `checked_shl`), against a trie walk of tens of
nanoseconds. I expect the per-call saving in routemap to be small and will
not claim a speedup without a routemap benchmark comparing `get` on
`IpPrefix` (masks) vs `CanonicalPrefix` (does not). The defensible value
today is correctness-by-construction (§1.3), not speed.

## 5. Staging

These are independent proposals, not an approved migration sequence. The
standalone `PrefixMatch` implementation is in ipnetx PR #7; none of the
decisions below is required for it:

1. **ipnetx** (additive; a 0.3.x release): `CanonicalPrefix`, conversions,
   tests (idempotence, strict/lenient, `Ord`, `Hash` agrees with network
   identity).
2. **routemap**: **decision gate** — complete the §3.2 spike items 1–4
   first, then choose (a)/(b)/(c). Any breaking release (0.2.0) follows
   that decision, not the other way round. Add an ancestor-walk/`covering`
   API through its own proposal in `routemap-covering-iterator.md`,
   independently of canonical-type adoption.
3. **Possible pathvector-types / -rib / -session adoption**, separately
   reviewed: `Nlri` over `CanonicalPrefix`;
   `from_wire`; delete `blackhole.rs` host-bit check and the `testutil`
   fixture. The `LocRib` inconsistency (§1.3) is already reproduced and
   tracked as pathvector #71, with acceptance criteria (IPv4/IPv6,
   non-octet-aligned prefixes, host-bit variants, lookup/withdrawal through
   canonical and non-canonical forms); it is fixed independently and is not
   a prerequisite or a justification for this stage.
4. **Possible pathvector-rpki adoption**, separately reviewed: switch
   `validate` to covering iteration only after differential validation
   against the current consumer. It does not require a canonical type.

## 6. Risks and open questions

- **Two prefix types** in the public surface of `ipnetx`; guidance on which
  to use must be clear in the README.
- **Naming:** `CanonicalPrefix` vs `Network` vs `NetPrefix`.
- **`FromStr` policy** — masking vs strict — and its effect on user-facing
  config errors and on the §3.2 migration cost. Independent of whether the
  type is canonical-by-construction (it is either way).
- **Serde** (if ever added): `Deserialize` must validate, not trust.
- **`IpSetBuilder::add_prefix` / `IpSet::contains_prefix`** take `IpPrefix`;
  accepting `Into<IpPrefix>` would let canonical values flow in without
  `.as_prefix()` noise, but the §3.2 spike shows the same `.parse()`
  inference hazard applies.
- **Scope of ipnetx:** per the current direction, canonical prefixes and
  the standalone length-window predicate (`PrefixMatch`) both live in ipnetx
  but are separate decisions with separate PRs; collections of entries stay
  deferred.
