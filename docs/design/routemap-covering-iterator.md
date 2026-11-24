# Exploration: a generic covering-prefix iterator in `routemap`

**Status:** exploration. Nothing here is implemented, and adopting it is a
separate decision from `PrefixMatch` (ipnetx) and from any canonical prefix
type. This document lives in the ipnetx repo only because the design set
does; the change it describes is in `routemap`.

Facts about `routemap` below were read from `src/treebitmap/mod.rs` and
`node.rs` (routemap 0.1.4) and may drift.

## 1. Goal

Give consumers *"every stored prefix that covers this prefix"* as a single
generic query, and let them apply their **own** predicate to what comes
back:

- `pathvector-policy`: vendor syntax and `PrefixMatch` windows.
- `pathvector-rpki`: RFC 6811 (`maxLength`, origin ASN, AS0, `NONE`, states).

`routemap` must know about neither. It returns coverage, nothing else.

## 2. Why now: what the consumers do today

`routemap` has exact `get`, per-address `longest_match`/`longest_match_entry`,
and full `iter`. It has no "all ancestors of a prefix" query, so
`pathvector-rpki/src/table.rs` (`FamilyTable::validate`) composes one:

1. `longest_match_entry(addr)` as a `NotFound` short-circuit (valid only in
   the `None` direction — a `Some` can be a *more specific* entry).
2. For `len` from `prefix_len` down to 0: build `IpPrefix::new(addr, len)`
   (host bits present) and call `get`, which masks and walks root→node again.

For a `/24` that is up to 25 independent trie walks. The short-circuit and the
loop exist only to emulate the missing primitive; the module docs already
call a future covering API "a follow-up".

## 3. Semantics

```
covering(R) = every stored (P, &V) with len(P) <= len(R)
              and the first len(P) bits of P equal those of R
```

- **Includes** an entry equal to `R`.
- **Excludes** entries more specific than `R` (so it is *not* a substitute
  for `longest_match_entry`, which can return a more specific entry).
- Host bits of `R` are ignored.
- **No filtering of any kind.** In particular, no length-window or payload
  filter: RFC 6811 needs covering entries *even when* they would not match,
  because a route longer than every covering VRP's `maxLength` is `Invalid`,
  not `NotFound`. A window-filtering iterator would erase that distinction.
- Yielded prefixes are canonical (host bits zero) by construction.
- Order: ascending prefix length (shortest first) — falls out of the walk.
  Whether to *promise* the order is an open question (§8).

### 3.1 Reference semantics (the test oracle)

The existing public API already defines the answer, and it is exactly what
`table.rs` does today:

```rust
// oracle, expressed with today's public API
(0..=R.mask()).filter_map(|len| {
    let p = IpPrefix::new(R.ip(), len).unwrap().masked();
    table.get(p).map(|v| (p, v))
})
```

The new iterator must produce the same sequence for every table and query.

## 4. Algorithm sketch (against the real layout)

`RouteMap` is a stride-4 treebitmap. A node has:

- `internal: u32` — bitmap of stored prefixes *within the node's stride*;
  bit index `(1 << rel_len) + nibble_prefix` for `rel_len` in `0..=3`
  (this is the `bpos` that `get_at` computes);
- `external: u32` — bitmap of which of the 16 children exist;
- `values`/`children` — dense vectors indexed by `rank` of the set bits.

To enumerate coverage of `R` (length `L`, `full_hops = L / 4`,
`rem = L % 4`):

```
node = root
for hop in 0..=full_hops:
    n = nibble(R.addr, hop)
    max_rel = if hop < full_hops { 3 } else { rem }
    for rel in 0..=max_rel:
        bpos = (1 << rel) + (n >> (4 - rel))          // as in get_at
        if node.internal bit bpos set: yield (prefix of length 4*hop + rel, &node.values[rank(...)])
    if hop == full_hops: stop
    if node.external bit n unset: stop
    node = node.children[rank(node.external, n)]
```

Visits at most `L/4 + 1` nodes and does at most 4 bit tests per node, in a
single root→leaf pass, with no allocation (a small struct holding the node
reference, `hop`, and a `rel` cursor implements `Iterator`). The `get`-loop
does up to `L + 1` separate walks of up to `L/4 + 1` nodes each. That is a
**predicted** improvement from the structure of the algorithm; it is
unmeasured (§7).

The reconstructed prefix for each yield is `R.addr & mask(4*hop + rel)` —
canonical without a separate `masked()` call.

## 5. API sketch

```rust
// SKETCH — not implemented. Additive to routemap 0.1.x.
impl<A: IpAddress, V> RouteMap<A, V> {
    /// All stored prefixes that cover `prefix` (including an equal entry),
    /// shortest first. Host bits of `prefix` are ignored.
    pub fn covering(&self, prefix: IpPrefix<A>) -> Covering<'_, A, V>;
}
pub struct Covering<'a, A: IpAddress, V> { /* node, hop, rel cursor */ }
impl<'a, A: IpAddress, V> Iterator for Covering<'a, A, V> {
    type Item = (IpPrefix<A>, &'a V);
}
```

- It takes `IpPrefix` (host bits ignored, like `get`), so it is **independent
  of the canonical-prefix decision**; if routemap later moves to a canonical
  type, this method follows with the others.
- Only the default `treebitmap` layout is in scope; the arena/experimental
  layouts do not need it unless they are promoted.
- Name alternatives: `ancestors`, `supernets`. `covering` matches RFC 6811
  terminology and is recommended.

## 6. Consumer composition

**pathvector-rpki** keeps `RouteMap<A, Vec<RoaEntry>>` and all RFC rules:

```rust
// sketch
let mut covered = false;
for (_prefix, entries) in map.covering(route) {
    covered = true;                                  // RFC 6811 "covers"
    if entries.iter().any(|e| e.asn != 0 && e.asn == origin
                              && route.mask() <= e.max_len) {
        return Valid;                                // RFC 6811 "Matched"
    }
}
if covered { Invalid } else { NotFound }
```

The `longest_match_entry` short-circuit becomes unnecessary. One property to
preserve: a node holding an empty `Vec` would count as covering, exactly as
a `get` hit does in the existing loop; `table.rs` already removes the node
when the last entry goes. Malformed `max_len` handling is unchanged
(`prefix-length-matching.md` §5.4).

**pathvector-policy** stores whatever per-prefix value suits its syntax —
for example the windows attached to each configured prefix — and applies
`PrefixMatch::matches` (or its own rule) to the returned entries. Ordered
permit/deny semantics stay in policy: the iterator only narrows the
candidates; policy still picks the first entry in sequence order.

Duplicate and removal semantics for per-prefix lists are the consumer's
(`rpki` already deduplicates identical `(max_len, asn)` and removes empty
nodes). This is why the deferred `PrefixMatchMap` may prove unnecessary
(`prefix-length-matching.md` §7).

## 7. Validation plan

1. **Oracle proptests:** random tables built from random insert/remove
   sequences (both families, lengths `0..=BITS` including non-stride-aligned
   ones, `/0`, host-bit queries); `covering(R)` equals the §3.1 oracle,
   including order.
2. **Unit cases:** `/0` entry covers everything; query shorter than every
   stored prefix yields nothing; equal prefix included; more-specific
   entries excluded; removal and re-insertion reflected; empty table.
3. **Differential test in pathvector-rpki** before deleting the old loop:
   old `validate` vs covering-based `validate` on random VRP sets
   (duplicates, shared prefixes, edge `max_len` values including the
   malformed ones) and random routes — identical results required. Include
   the §5.3 cases from `prefix-length-matching.md`.
4. **Benchmarks** (separated tables; assert entry counts — the earlier
   `make_set` lesson): 100 / 1k / 10k entries, plus an RPKI-shaped table;
   covering vs the `get`-loop for `/8`, `/24`, `/32`, `/48`, `/64`, `/128`
   queries. No adoption without a measured result.

## 8. Open questions

1. **Promise the ascending-length order** or leave it unspecified? Policy
   and RPKI do not need it, but a stable order simplifies testing.
2. **Name** (`covering` vs alternatives).
3. **Yield type** — `(IpPrefix<A>, &V)` now; a canonical type if/when that
   lands.
4. **Mutable variant** (`covering_mut`) — no consumer needs one; omit.
5. **Whether the arena/experimental layouts** need parity.

## 9. Non-goals

Filtering by length or payload; any vendor or RPKI rule; payload-aware maps;
changing `insert`/`get` semantics; the canonical-prefix migration.
