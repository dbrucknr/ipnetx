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
(host bits zeroed — see §4.3). The typed constructor enforces:

```
p ≤ ge ≤ le ≤ BITS          (BITS = 32 for IPv4, 128 for IPv6)
```

Whether `ge < p` should be an error is a separate decision — see §2.5.

### 2.2 Covering and matching (two distinct relations)

For a route prefix `R` of length `L`:

- **`R` is *covered by* the entry** iff `L ≥ p` and the top `p` bits of `R`
  equal those of `P` (i.e. `R ⊆ P`). **The length window plays no part.**
- **`R` *matches* the entry** iff it is covered **and** `ge ≤ L ≤ le`.

Matching implies covering, never the reverse. Boolean prefix-list evaluation
only needs "matches". RPKI origin validation needs **both** — see §6 — and
conflating them is the central pitfall for any API in this area: an
iterator that yields only *matching* entries has already thrown away the
information RFC 6811 uses to distinguish `Invalid` from `NotFound`.

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
| `le < p` | **rejected** (`EmptyWindow`): a route must have `L ≥ p` to be covered, so `L ≤ le < p` is unsatisfiable — the entry could never match anything |
| `le < ge`, `le > BITS` | rejected (`EmptyWindow` / `AboveAddrBits`) |
| `ge < p ≤ le` (e.g. `10.0.0.0/8 ge 4 le 24`) | **not unsatisfiable** — `/16`s inside `10/8` can match. Lengths `4..7` are simply dead because coverage already forces `L ≥ 8`, so the entry behaves as `ge 8 le 24`. Accept-and-clamp vs reject is a policy decision, see §2.5 |
| `/32` or `/128` exact | matches that host route only |
| entry has host bits (`10.1.2.3/8`) | see §4.3 |
| route has host bits (`10.1.2.3/24`) | masked before comparison |
| v4 entry vs v6 route | unrepresentable — `A` is a type parameter |

### 2.5 `ge < p`: what the rule is actually for

An entry like `10.0.0.0/8 ge 4 le 24` is *satisfiable*; the sub-`p` part of
the window is just unreachable. So rejecting it is **not** justified by
"no route can match". The honest reasons to reject it are API-level:

1. **The stored window should say what it means.** If `ge = 4` is accepted
   and `min_len()` returns 4, callers reading it will believe lengths 4–7
   are matchable. Either clamp on construction (so `min_len()` returns 8)
   or reject.
2. **Round-tripping.** Clamping silently changes what the user wrote; to
   keep config fidelity the original value would have to be retained
   alongside the effective one.
3. **Likely a mistake.** `ge` below the prefix length usually signals a
   confused config, which an error surfaces earlier than a silent clamp.

None of these is a correctness argument, so this stays an **intentional API
rule, not a semantic necessity**. Options: (i) reject in the typed
constructor (recommended default: the stored window always means what it
says) while a config-layer parser may choose to clamp; (ii) clamp and
expose both values. Which vendors accept `ge ≤ p` syntax is a **separate
verification task** (§8.1) and must not be used to justify this rule until
checked.

## 3. Preserving prefix boundaries

The rule: **normalization may only be applied where it cannot change the
answers the type promises to give.** What is promised differs by type, so
the rule is applied differently:

| Type | Mutability | Promises | Normalization allowed |
|---|---|---|---|
| `PrefixMatchSet<A>` (boolean) | immutable, built via a builder (mirrors `IpSetBuilder` → `IpSet`) | `matches(R)` only | Entries sharing the same `P` are merged by **unioning length windows** into a length bitset. Lossless for membership |
| `PrefixMatchMap<A, V>` (payload) | mutable | `covering(R)` / `matching(R)` **with payloads**, and removal | **None.** Every `(entry, V)` pair stays independent (§4.1) |

Never allowed in either:

- Merging across different prefixes (sibling /25s → /24). This is the
  `IpSet` behavior we are deliberately *not* reproducing.
- Dropping an entry because another "subsumes" it (`10/8 le 24` subsumes
  `10.1/16 exact`). Matching is unchanged but configured entries are lost,
  which hurts round-tripping and `show` output. Offer it only as an explicit
  `compact()`, never in `build()`.

Why the map cannot union windows: after `(P, ..20, AS1)` and `(P, ..24, AS1)`
are unioned into one window, removing the `..24` entry could not restore the
`..20` entry. The same collapse across different payloads is worse — it
destroys which ASN authorizes which length. The boolean set avoids the
problem by having no removal and no payload.

Property to test: for any entry list, the built set's `matches` equals a
naive linear scan of the original entries.

## 4. API sketch

```rust
// SKETCH — not implemented.

/// One prefix-list entry. Invariant: p <= min_len <= max_len <= A::BITS
/// (see §2.5 for the open question on accepting ge < p).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PrefixMatch<A: IpAddress> {
    prefix: IpPrefix<A>,   // host bits zero; see §4.3
    min_len: u8,
    max_len: u8,
}

#[derive(Debug, PartialEq, Eq)]
pub enum InvalidLengthRange {
    BelowPrefixLen, // ge < p — policy rule, §2.5 (omit if clamping is chosen)
    EmptyWindow,    // le < p, or le < ge: can never match anything
    AboveAddrBits,  // le > BITS
}

impl<A: IpAddress> PrefixMatch<A> {
    pub fn exact(prefix: IpPrefix<A>) -> Self;
    pub fn or_longer(prefix: IpPrefix<A>) -> Self;
    pub fn longer(prefix: IpPrefix<A>) -> Result<Self, InvalidLengthRange>;
    pub fn up_to(prefix: IpPrefix<A>, le: u8) -> Result<Self, InvalidLengthRange>;
    pub fn range(prefix: IpPrefix<A>, ge: u8, le: u8) -> Result<Self, InvalidLengthRange>;

    pub fn prefix(&self) -> IpPrefix<A>;
    pub fn min_len(&self) -> u8;
    pub fn max_len(&self) -> u8;

    /// §2.2: covered AND window contains route.mask().
    pub fn matches(&self, route: IpPrefix<A>) -> bool;
    /// §2.2: covered only; ignores the window.
    pub fn covers(&self, route: IpPrefix<A>) -> bool;
}
```

### 4.1 Boolean set: immutable, window-union

```rust
pub struct PrefixMatchSetBuilder<A: IpAddress> { /* entries */ }
impl<A: IpAddress> PrefixMatchSetBuilder<A> {
    pub fn add(&mut self, entry: PrefixMatch<A>);
    pub fn build(self) -> PrefixMatchSet<A>;   // unions windows per prefix (§3)
}
pub struct PrefixMatchSet<A: IpAddress> { /* prefix -> LenSet */ }
impl<A: IpAddress> PrefixMatchSet<A> {
    pub fn matches(&self, route: IpPrefix<A>) -> bool;
}
```

Mirrors `IpSetBuilder` → `IpSet`. No removal, no payload, so the union is
safe.

### 4.2 Payload map: mutable, entries never merged

**Entry identity.** The map holds a *set of `(PrefixMatch, V)` pairs*, with
`V: Eq`. Two pairs are the same pair iff both the entry (prefix **and**
window) and the payload are equal.

```rust
pub struct PrefixMatchMap<A: IpAddress, V> { /* see §5 */ }

impl<A: IpAddress, V: Eq> PrefixMatchMap<A, V> {
    /// Idempotent. Returns true if the pair was newly inserted.
    /// Re-inserting an identical pair is a no-op (RTR Serial Query replay,
    /// today deduplicated by hand in pathvector-rpki `FamilyTable::insert`).
    pub fn insert(&mut self, entry: PrefixMatch<A>, value: V) -> bool;

    /// Removes exactly that pair. Returns true if it was present.
    /// Never disturbs other pairs sharing the prefix, the window, or the payload.
    pub fn remove(&mut self, entry: &PrefixMatch<A>, value: &V) -> bool;

    pub fn len(&self) -> usize;   // number of pairs

    /// Every entry that COVERS `route` (§2.2), regardless of its window,
    /// with a precomputed `matches` flag. Needed for RPKI (§6.1).
    pub fn covering(&self, route: IpPrefix<A>) -> impl Iterator<Item = Covering<'_, A, V>>;

    /// Convenience: `covering` filtered to entries whose window matches.
    pub fn matching(&self, route: IpPrefix<A>) -> impl Iterator<Item = (&PrefixMatch<A>, &V)>;

    pub fn matches(&self, route: IpPrefix<A>) -> bool;   // any(matching)
}

pub struct Covering<'a, A: IpAddress, V> { /* entry, value, matches: bool */ }
```

Consequences, each of which is a test:

| Scenario | Required behavior |
|---|---|
| Same prefix, **different ASNs** (`(P,..16,AS1)`, `(P,..16,AS2)`) | two pairs; each independently queryable and removable |
| Same prefix, same ASN, **different windows** (`(P,..20,AS1)`, `(P,..24,AS1)`) | two pairs; removing the `..24` pair leaves `..20` still matching `/20` and no longer matching `/24` |
| Same prefix, same window, **different payloads** | two pairs; `covering` yields both |
| Identical pair inserted twice | `len()` unchanged; second `insert` returns `false` |
| Remove a pair that is absent | returns `false`; nothing else changes |
| Iteration order | unspecified, **or** pin it (ascending prefix length, then insertion order) if a consumer needs determinism — decide before implementation |

### 4.3 Host bits on the entry side

Two independent questions, which should not be conflated:

- **Normalization** (mask on the way in) is enough to guarantee the stored
  prefix is canonical. A masking constructor therefore satisfies the
  invariant by itself.
- **Validation** (reject input that had host bits) is a *caller policy*:
  config loaders usually want it (pathvector's `BlackholeScope` rejects host
  bits at `blackhole.rs:101-108`), wire decoders do not.

Recommendation: `PrefixMatch` constructors take a prefix and mask it (matching
`IpPrefix::to_range` and `routemap`); once `CanonicalPrefix` exists they take
that instead. Strictness stays with the caller. See `canonical-prefix.md` §2.

## 5. Data-structure options

Let `n` = entries, `G` = distinct entry prefix lengths present (real lists:
typically ≤ ~10; worst case 33 / 129), `L` = route length. The structure
must support **covering enumeration with payloads** (§4.2), not just
boolean `matches`.

| Option | Structure | `covering` / `matching` | Boolean `matches` | Notes |
|---|---|---|---|---|
| A. Linear | `Vec<(PrefixMatch, V)>` | O(n) | O(n) | Trivial; the **test oracle**; fine for small/ordered lists |
| B. Tuple-space | per-`p` group: sorted `Vec<(net_bits, [(window, V)…])>`; query masks `R` to each `p ≤ L` and binary-searches | O(G · log n + k) for k results | O(G · log n) | No trie, no dependency. Coverage falls out of the construction (every probed group has `p ≤ L` and matching network bits ⇒ covered). Entries stay independent, so removal is local |
| C. Trie (routemap) | node value = list of `(window, V)` pairs; covering = **all ancestors** of `R` with `p ≤ L` | O(depth + k) | O(depth) | Needs a "walk ancestors of this **prefix**" API in routemap, which does not exist today (`longest_match` is per-address). The *inherited length-set* shortcut (effective set = own ∪ ancestors') accelerates **boolean** `matches` only; it **cannot** enumerate per-payload coverage and must not be used for the map |

`LenSet` (boolean set only) needs 129 bits for IPv6: e.g. `[u64; 3]`; IPv4
fits a `u64`.

**Recommendation:** ship A (oracle) + B in ipnetx; revisit C when routemap
has an ancestor-walk API, gated by a benchmark. Benchmarks must use separated
entries and assert stored counts (the lesson of the `make_set` bug fixed in
the `contains_prefix` PR), at 100 / 1k / 10k plus a 50k "IRR-shaped" list
with `le 24`.

## 6. Relationship to the rest of the stack

- **Ordered permit/deny prefix lists** (sequence numbers, first match wins)
  stay in `pathvector-policy`. `PrefixMatch::matches` is the per-entry
  primitive they iterate. `PrefixMatchSet` is for *large unordered* lists
  where order is irrelevant.
- **`IpSet`** remains the tool for address-space algebra. A lossy
  `covered_space() -> IpSet<A>` is possible but must be named to make the
  loss obvious; it is not part of the first cut.

### 6.1 RPKI route origin validation (RFC 6811 §2)

RFC 6811 §2 defines the states in terms of two relations that map onto §2.2:

| RFC 6811 term | Definition (verify wording against the RFC when writing tests) | Here |
|---|---|---|
| VRP **covers** route | VRP prefix length ≤ route prefix length **and** the VRP prefix bits match | `covers` / `covering` |
| VRP **matches** route | covers **and** route length ≤ maxLength **and** origin AS equals the VRP ASN | `matches` + payload check |
| `NotFound` | **no** VRP covers the route | `covering` is empty |
| `Valid` | at least one VRP matches | some covering entry has `matches` and the right ASN |
| `Invalid` | at least one VRP covers, **none** match | `covering` non-empty, no match |

The distinction that matters: a route **longer than every covering VRP's
maxLength is `Invalid`, not `NotFound`**. Those VRPs cover the route but
their windows exclude it, so a `matching()`-only iterator drops exactly the
entries that make the answer `Invalid` and would report `NotFound`.
Therefore:

- `matching()` alone **cannot** replace the loop in
  `pathvector-rpki/src/table.rs:99-139`.
- `covering()` with the `matches` flag can: the existing loop's
  `saw_covering` is `covering().next().is_some()`, and its
  `prefix_len <= e.max_len && e.asn == origin` test is the `matches` flag
  plus the payload comparison. The `longest_match_entry` NotFound
  short-circuit becomes unnecessary (it was only a fast path).
- The AS0 exclusion stays in `pathvector-rpki`, as it does today; it is a
  payload rule, not a length rule. An AS0 VRP still **covers**, so it still
  contributes to `Invalid`.

**Open point:** `PrefixMatch` rejects `le < p` (§2.4), but today
`table.rs` accepts any `max_len`, so a malformed VRP with `maxLength < p`
is currently *covering and never matching*. `pathvector-rpki` must either
reject such VRPs at ingress (confirm against the RTR protocol text, RFC
8210, before relying on that) or the API needs a way to represent a
covering-only entry. Decide before migrating; do not let it change
validation results silently.

## 7. Test plan

1. **Oracle proptests.** `PrefixMatchSet::matches` and
   `PrefixMatchMap::{covering, matching, matches}` ≡ linear scan over the
   inserted entries (random entries and routes, both families, lengths
   including 0 and BITS).
2. **Table-driven edge cases** from §2.4, including `ge < p ≤ le`
   (behaves as `ge = p` if accepted; rejected if the §2.5 rule is chosen).
3. **Payload and removal** — every row of the §4.2 consequences table.
4. **RFC 6811 §2 distinction** (these are the migration-critical cases).
   Using VRPs written `(prefix, maxLength, ASN)`:

   | VRPs | Route (origin) | Expected |
   |---|---|---|
   | `(10.0.0.0/16, 16, AS1)` | `10.0.0.0/24` (AS1) | **Invalid** — covered, longer than maxLength; *not* `NotFound` |
   | same | `10.0.0.0/16` (AS1) | Valid |
   | same | `10.0.0.0/16` (AS2) | Invalid |
   | same | `11.0.0.0/16` | NotFound |
   | same | `10.0.0.0/8` (AS1) | NotFound — the VRP is *more specific* than the route, so it does not cover |
   | `(10.0.0.0/8, 24, AS1)`, `(10.1.0.0/16, 16, AS2)` | `10.1.0.0/24` (AS1) | **Valid** via the *less-specific* VRP although the most-specific covering VRP does not match |
   | `(10.0.0.0/16, 16, AS1)`, `(10.0.0.0/16, 24, AS2)` | `10.0.0.0/24` (AS2) | Valid; (AS1) → Invalid |
   | previous, after removing the AS2 VRP | `10.0.0.0/24` (AS2) | **Invalid** (still covered by AS1's VRP), not NotFound |
   | previous, after removing both | `10.0.0.0/24` | NotFound |
   | `(10.0.0.0/16, 16, AS0)` | `10.0.0.0/16` (any origin) | Invalid — AS0 covers but never matches |
   | any | route with host bits (`10.0.0.7/24`) | same as the masked route |

5. **Differential test for the migration.** Proptest comparing the new
   covering-based `validate` against the current `table.rs` loop on random
   VRP sets (including duplicates, shared prefixes and `maxLength` edge
   values) and random routes. They must agree on every input before the old
   loop is deleted.
6. **Vendor-convention conformance** — only after §8.1 verification.
7. **Fuzz target** in `fuzz/` for construct-then-query (no panics; invalid
   windows rejected per the chosen §2.5 rule).
8. **Benchmarks** per §5.

## 8. Open questions

1. **Vendor syntax and semantics (separate verification task).** Confirm,
   from primary documentation: Cisco `ge`/`le` and whether `ge` ≤ prefix
   length is accepted or rejected; Juniper route-filter match types
   (`exact`, `orlonger`, `longer`, `upto`, `prefix-length-range`); GoBGP
   `masklength-range`; RFC 6811 §2 wording. §2.3 was written from memory
   of these conventions and is **unverified**; §2.5 deliberately does not
   lean on vendor behavior.
2. **`ge < p`:** reject vs clamp-and-expose-both (§2.5).
3. **Set vs map first.** The set (§4.1) and map (§4.2) now have different
   semantics (union vs independent pairs) and are different types. RPKI needs
   the map; policy lists need the set. Sequence them by consumer.
4. **Iteration order** of `covering`/`matching` (§4.2).
5. **Malformed `maxLength < p` VRPs** (§6.1).
6. **Where it lives** — ipnetx (recommended: pure data; option B needs no
   trie) vs `routemap` (option C only).
7. **Textual form** — whether `FromStr` for `P ge N le M` is in scope.

## 9. Staging

1. `PrefixMatch` (+ `covers`/`matches`) and `InvalidLengthRange`, with tests
   (additive, semver-compatible with 0.3.x).
2. `PrefixMatchSetBuilder`/`PrefixMatchSet` (option A oracle + B).
3. `PrefixMatchMap` (option A oracle + B) with `covering`; RFC 6811 test
   table and the differential test against `table.rs`.
4. `pathvector-rpki` migrates behind the differential test;
   `pathvector-policy` adopts the set for large lists.
