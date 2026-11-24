# Design: standalone prefix length-window predicate (`PrefixMatch`)

**Status:** proposal. Only `PrefixMatch` (§3) is proposed for implementation;
everything else here is context, a division of responsibility, or explicitly
deferred.

## 1. Problem

`IpSet` answers *address-coverage* questions: "is every address in this
prefix covered by the set?" Its `build()` merges touching ranges, which is
right for that question and wrong for *prefix-identity* questions.

Example (checked against the current code): a list holds `10.0.0.0/25` and
`10.0.0.128/25`.

| Question | Answer |
|---|---|
| `IpSet` — are all addresses of `10.0.0.0/24` covered? | **true** — the two /25s merge into one stored range |
| Is `10.0.0.0/24` one of the listed prefixes? | **false** |

Routing policy asks the second kind of question, plus length windows
("anything inside `10/8` between /16 and /24"). That needs a primitive that
never merges across prefix boundaries.

## 2. Scope and division of responsibility

| Layer | Owns | Does **not** own |
|---|---|---|
| **ipnetx** | `PrefixMatch`: one prefix plus a numeric length window, with `covers` and `matches` (§3). Later, and separately, a canonical prefix type (`canonical-prefix.md`) | Vendor syntax; RPKI rules; any collection of entries |
| **routemap** | *Exploration only (see `routemap-covering-iterator.md`)*: a generic "all stored prefixes that cover this prefix" iterator | What a caller does with those entries |
| **pathvector-policy** | Vendor syntax (`ge`/`le`, `orlonger`, …), permit/deny and ordering, composing entries into lists; applies `PrefixMatch` to the entries routemap returns | — |
| **pathvector-rpki** | RFC 6811 validation: `maxLength`, origin-ASN comparison, AS0, `NONE`, the three states; applies its **own** predicate to the entries routemap returns | — |

Consequences of this split:

- ipnetx makes **no vendor-compatibility claim**. The first API takes
  explicit numeric bounds (`min_len`, `max_len`); any `ge`/`le` mapping lives
  in `pathvector-policy`.
- ipnetx contains **no RPKI rules**. `PrefixMatch` is never an RFC VRP.
- Collections (`PrefixMatchSet`, `PrefixMatchMap`) are **deferred** (§7);
  composing a routemap covering iteration with per-prefix `PrefixMatch`
  values may make them unnecessary.

## 3. `PrefixMatch`

### 3.1 Definitions

An entry is `(P, min_len, max_len)`, `P` a prefix of length `p`. For a route
prefix `R` of length `L`:

- **covers:** `L ≥ p` and the first `p` bits of `R` equal those of `P`
  (`R ⊆ P`). The window plays no part.
- **matches:** covers **and** `min_len ≤ L ≤ max_len`.

Matching implies covering, never the reverse. Host bits of `R` are ignored.

**Terminology warning.** `PrefixMatch::matches` is a *length-window* match.
It is **not** RFC 6811's "Matched", which additionally requires the origin
ASN to equal the VRP's ASN (§5). The API docs must say so, and the RPKI
consumer must not call `matches` and conclude "matched".

### 3.2 Constructor rules

```rust
// SKETCH — mirrors the proposed implementation.
pub struct PrefixMatch<A: IpAddress> { prefix: IpPrefix<A>, min_len: u8, max_len: u8 }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidLengthRange {
    MaxAboveAddrBits, // max_len > A::BITS
    MinAboveMax,      // min_len > max_len
    MinBelowPrefixLen // min_len < p
}

impl<A: IpAddress> PrefixMatch<A> {
    pub fn new(prefix: IpPrefix<A>, min_len: u8, max_len: u8) -> Result<Self, InvalidLengthRange>;
    pub fn exact(prefix: IpPrefix<A>) -> Self;          // min_len = max_len = p
    pub fn prefix(&self) -> IpPrefix<A>;                // host bits zeroed
    pub fn min_len(&self) -> u8;
    pub fn max_len(&self) -> u8;
    pub fn covers(&self, route: IpPrefix<A>) -> bool;
    pub fn matches(&self, route: IpPrefix<A>) -> bool;
}
```

Checks run in this order and the first failure is reported:
`MaxAboveAddrBits`, then `MinAboveMax`, then `MinBelowPrefixLen`.

- **Host bits on the entry are masked.** `new` stores the zeroed prefix, so
  entries built from `10.1.2.3/8` and `10.0.0.0/8` are equal and hash
  equal. (Masking is enough to make the stored prefix canonical; whether to
  *reject* host bits is a caller policy — `canonical-prefix.md` §2.)
- **`min_len < p` is rejected, and the reason is an API rule, not a
  semantic necessity.** An entry like `10.0.0.0/8` with `min_len = 4` is
  satisfiable: `/16`s inside `10/8` match it. Lengths 4–7 are simply dead,
  because covering already forces `L ≥ 8`, so it behaves exactly like
  `min_len = 8`. Rejecting it keeps `min_len()` meaning what it says (no
  caller reads "4" and believes `/6` routes can match) and surfaces probable
  config mistakes. It is also the conservative choice for a new API:
  **loosening to clamp-and-accept later is non-breaking; tightening later is
  breaking.** `max_len < p` needs no separate check: with `min_len ≥ p` it
  already implies `min_len > max_len`.
- **No vendor mapping and no `or_longer`/`longer`/`up_to` helpers in the
  first cut.** Those names encode vendor conventions; callers build them
  from `new` (e.g. "or-longer" is `new(P, p, BITS)`).

### 3.3 Edge cases (each is a test)

| Case | Expected |
|---|---|
| `0.0.0.0/0` exact | matches only the default route; covers everything |
| `0.0.0.0/0`, window `0..=32` | matches every IPv4 prefix |
| `min_len == max_len` | single-length window |
| `max_len == BITS` | open-ended on the long side |
| `min_len < p` | `Err(MinBelowPrefixLen)` (e.g. `/8`, min 4, max 24) |
| `min_len > max_len` | `Err(MinAboveMax)` |
| `max_len > BITS` | `Err(MaxAboveAddrBits)` — checked first, so `(min 40, max 33)` on IPv4 is `MaxAboveAddrBits` |
| `/32`, `/128` exact | matches that host route only |
| entry has host bits | masked on construction |
| route has host bits | ignored |
| route shorter than `p` | never covered, never matched |
| IPv4 entry, IPv6 route | unrepresentable (`A` is a type parameter) |

### 3.4 Test plan (independent derivation)

Expected values must not be computed by the code under test, so:

1. **Hand-derived tables** for IPv4 and IPv6, written from §3.1 by reasoning
   about bits (non-octet boundaries such as `/9`, `/23`, `/65`; `/0`;
   `/32`; `/128`).
2. **Bit-string oracle:** expand both addresses to explicit bit sequences
   from their *octets* (never `to_u128`), compare the first `p` bits
   element-wise. Shares no arithmetic with the implementation.
3. **Range-containment oracle:** `covers ⇔ P.to_range() ⊇ R.masked().to_range()`
   using the already-tested `IpRange` primitives — a different derivation
   from bit comparison.
4. **Truncation oracle:** for `L ≥ p`, `covers ⇔ IpPrefix::new(R.ip, p).masked() == P`.
5. **Properties** (random prefixes and windows, both families, biased so
   covered routes are common): `matches ⇒ covers`; `covers` is independent
   of the window; widening the window never loses a match; `exact(P).matches(R)`
   ⇔ `R.masked() == P`; `matches(R) == matches(R.masked())`; entries from
   host-bit variants are `==` and hash equal.
6. **Constructor table:** every error variant, precedence, and the
   accept boundaries (`min = p`, `max = BITS`, `min = max`).

## 4. Why not just reuse `IpSet`

See §1: merging changes the answer. `IpSet::contains_prefix` stays the
address-coverage query; `PrefixMatch` is the prefix-identity query. Both
are needed and neither replaces the other.

## 5. RPKI origin validation (RFC 6811): what ipnetx does and does not do

**Sources and provenance.** RFC 6811 (§2, full text), RFC 8481, RFC 8893,
RFC 6482/9582 and RFC 8210/6810 §5 were read via a fetch tool (some pages
were returned in part; RFC 8210 §12 and RFC 6810 §10 came back only as a
summary and are *not* relied on below). Where this section depends on text
that was only summarized, it says so.

### 5.1 The RFC definitions (RFC 6811 §2, paraphrased)

| Term | Condition |
|---|---|
| VRP | (IP prefix, prefix length, maxLength, origin ASN) |
| VRP **covers** route | VRP length ≤ route length **and** the first VRP-length bits agree. No maxLength or ASN test |
| VRP **Matched** route | covers **and** route length ≤ maxLength **and** route origin ASN = VRP ASN |
| `NotFound` | no VRP covers the route |
| `Valid` | at least one VRP Matched |
| `Invalid` | at least one VRP covers, none Matched |

Special values: a route whose origin is `NONE` (final AS_PATH segment is an
AS_SET and similar) cannot be Matched; no route can be Matched by a VRP whose
ASN is 0. The §2.1 pseudo-code sets "covering exists" *before* the ASN
checks, so a covering AS0 VRP yields `Invalid`, not `NotFound` — an
inference from the pseudo-code, not explicit prose.

RFC 6811 contains **no worked examples**. RFC 8481 (updates 6811) and
RFC 8893 (updates 6811) do **not** redefine these terms: 8481 concerns which
routes are evaluated and "set state, don't act"; 8893 concerns applying
validation on export using the effective origin AS and states that it does
not change 6811's semantics.

### 5.2 Mapping onto `PrefixMatch`

| RFC concept | ipnetx |
|---|---|
| VRP covers route | `PrefixMatch::covers` — **same relation** (VRP prefix = `P`) |
| route length ≤ maxLength | `PrefixMatch::matches` with `min_len = p`, `max_len = maxLength` — **length half only** |
| origin ASN equality, AS0, `NONE`, the three states | **not in ipnetx**; stay in `pathvector-rpki` |

So `PrefixMatch` could express a VRP's *prefix-and-length half*, but
`pathvector-rpki` is **not required to use it** and, under §2, applies its
own predicate. The key RFC behavior ipnetx must not obscure: a route longer
than every covering VRP's `maxLength` is `Invalid`, **not** `NotFound`. That
is preserved only if the consumer sees every *covering* entry, which is why
the routemap work is a *covering* iterator (`routemap-covering-iterator.md`),
not a window-filtered one.

### 5.3 Examples (derived from the §5.1 definitions, not from the RFC)

These belong in `pathvector-rpki`'s tests. Each VRP is
`(prefix, maxLength, ASN)`. The ASN column is exactly what ipnetx cannot
decide.

| VRPs | Route (origin) | covers? | length ≤ maxLength? | ASN equal? | State |
|---|---|---|---|---|---|
| `(10.0.0.0/16, 16, AS1)` | `10.0.0.0/24` (AS1) | yes | **no** | yes | **Invalid** (not NotFound) |
| same | `10.0.0.0/16` (AS1) | yes | yes | yes | Valid |
| same | `10.0.0.0/16` (AS2) | yes | yes | **no** | Invalid |
| same | `11.0.0.0/16` | no | — | — | NotFound |
| same | `10.0.0.0/8` (AS1) | **no** (VRP is more specific) | — | — | NotFound |
| `(10.0.0.0/8, 24, AS1)`, `(10.1.0.0/16, 16, AS2)` | `10.1.0.0/24` (AS1) | both | /8 yes, /16 no | /8 yes | **Valid** via the less-specific VRP |
| `(10.0.0.0/16, 16, AS1)`, `(10.0.0.0/16, 24, AS2)` | `10.0.0.0/24` (AS2) | both | AS1's no, AS2's yes | AS2's yes | Valid |
| same, AS2's VRP then withdrawn | `10.0.0.0/24` (AS2) | AS1's | no | no | **Invalid** (still covered) |
| both withdrawn | `10.0.0.0/24` | no | — | — | NotFound |
| `(10.0.0.0/16, 16, AS0)` | `10.0.0.0/16` (any) | yes | yes | never (AS0) | Invalid |

### 5.4 Malformed `maxLength`: resolved against the actual ingestion contract

What the standards say (as read):

- ROA profile (RFC 9582 §4.3.2.2, obsoleting RFC 6482 §3.3): `maxLength`, if
  present, **MUST** be ≥ the prefix length and ≤ the address-family width.
- RTR (RFC 8210 §5.1, same wording in RFC 6810 §5.1): Max Length **MUST NOT**
  be less than the Prefix Length. This binds the sender/cache.
- RFC 6811 itself says nothing about out-of-range `maxLength`.
- **Not found:** any text, in the portions read verbatim, telling a *router*
  what to do on receiving a violating Prefix PDU, or which RTR error code
  applies. (RFC 8210 §12 was available only as a summary, so this is
  "not found", not "absent".)

What `pathvector-rpki` actually does today:

- `pdu.rs` decodes `max_len` with no validation.
- `table.rs::VrpOp::from_pdu` rejects only a `prefix_len` the address family
  cannot represent (such records are *skipped*); `max_len` is stored
  unvalidated. The code comment names the open question — "whether it
  should instead be reported as corrupt data" — and points at the separate
  prefix-bounds validation issue (#91 in pathvector).
- Effect of malformed `max_len`: `max_len < prefix_len` ⇒ the VRP covers
  but can never match (it contributes to `Invalid`); `max_len > BITS` ⇒
  behaves like `BITS` for every real route.

**Resolution.** Because `pathvector-rpki` applies its own predicate
(`route_len <= max_len`) to *covering* entries (§2), the migration to a
routemap covering iterator **needs no decision about malformed `maxLength`
and changes no validation result**. `PrefixMatch`'s stricter constructor
(§3.2) is not on that path. Whether to *reject* malformed VRPs at ingress is
a behavior change owned by pathvector #91 and must cite the RTR error
handling verified verbatim from RFC 8210 §12 — which this work did not obtain.
It is deliberately not proposed here.

## 6. Vendor syntax: deferred to consumers

Cisco `ge`/`le`, Juniper route-filter match types, GoBGP `masklength-range`
and similar are **not** verified and **no compatibility claim is made**.
`pathvector-policy` owns that mapping and its verification. When it does,
the §3.2 `min_len < p` rule is one decision it may want to relax (clamping
is a non-breaking relaxation for ipnetx).

## 7. Deferred: collections and payload maps

Not proposed now. Recorded so the semantics are not lost.

- **`PrefixMatchSet`** (immutable, boolean): could union length windows per
  prefix into a length bitset, because it has no payload and no removal.
- **`PrefixMatchMap<A, V>`** (mutable, payload): entries must **never be
  merged**; every `(entry, V)` pair stays independently queryable and
  removable. Window-union would make "remove the `..24` entry, keep the
  `..20` entry" impossible and would destroy which payload authorized which
  length.
  - **Entry identity.** The map is a *set of `(PrefixMatch, V)` pairs*.
    Two pairs are the same pair iff their `PrefixMatch` values are equal
    (prefix after masking, `min_len`, `max_len`) **and** their payloads are
    equal.
  - **Required bound: `V: Eq`.** `Eq` (not just `PartialEq`) is required
    because identity must be an equivalence relation: reflexive, so a pair
    can always find and remove itself. Payloads containing floats or other
    non-reflexive fields are therefore excluded. `Hash` would be an optional
    additional bound for O(1) duplicate detection; without it, duplicates
    are found by scanning the pairs stored under the same entry.
  - **Payload equality is the caller's identity decision.** A payload that
    includes volatile data (a timestamp, a serial number) makes
    otherwise-identical records distinct pairs. A caller wanting
    "same record, refreshed metadata" must keep that data out of `Eq` or
    remove-then-insert.
  - **Operations.** `insert(entry, v) -> bool` is idempotent (false if the
    identical pair exists); `remove(&entry, &v) -> bool` removes exactly
    that pair. This mirrors the hand-written deduplication in
    `pathvector-rpki`'s `FamilyTable::insert`/`remove` today.

The routemap-based composition (`routemap-covering-iterator.md`) stores
the per-prefix list as routemap's *value*, so these duplicate/removal rules
become the consumer's responsibility there.

## 8. Open questions

1. **`min_len < p`:** reject (proposed, relaxable) vs clamp-and-expose-both.
2. **`matches` naming** given the RFC "Matched" overlap (§3.1) — keep and
   document, or choose a name that avoids the clash (e.g. `window_matches`).
3. **Verbatim RTR error handling** (RFC 8210 §12) for pathvector #91.
4. **Whether collections are ever needed** once the routemap covering
   iterator exists (§7).

## 9. Staging

1. `PrefixMatch` + `InvalidLengthRange` + tests (additive; this document's
   implementation scope).
2. Separately decided: canonical prefix type; routemap covering iterator;
   consumer adoption in `pathvector-policy` and `pathvector-rpki`.
