# Fuzz Testing

`ipnetx` uses [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) (libFuzzer) for fuzz testing. Four targets cover the public API surface:

| Target | What it tests |
|---|---|
| `parse_range` | `IpRange::from_str` for IPv4 and IPv6 — verifies no panics and that successful parses round-trip through `Display` |
| `parse_prefix` | `IpPrefix::from_str` for IPv4 and IPv6 — same round-trip + `masked()` idempotency |
| `ipset_ops` | Set algebra (`union`, `intersection`, `difference`, `complement`) — verifies commutativity, De Morgan's laws, inclusion–exclusion, and the normalization invariant |
| `ipset_builder` | `IpSetBuilder` add/remove operations — verifies the normalization invariant holds after arbitrary sequences of mutations |

## Prerequisites

`cargo-fuzz` requires a nightly Rust toolchain (libFuzzer uses nightly-only flags):

```sh
rustup toolchain install nightly
cargo +nightly install cargo-fuzz --locked
```

## Running fuzz targets

From the repository root:

```sh
# Run a single target indefinitely (Ctrl-C to stop)
cargo +nightly fuzz run parse_range

# Run with a time limit (seconds)
cargo +nightly fuzz run ipset_ops -- -max_total_time=300

# Run with a length limit (bytes) — useful on resource-constrained machines
cargo +nightly fuzz run ipset_builder -- -max_total_time=60 -max_len=4096

# List all targets
cargo +nightly fuzz list
```

On macOS (Apple Silicon), libFuzzer's AddressSanitizer is not supported.
Add `-s none` to disable it:

```sh
cargo +nightly fuzz run parse_range -s none -- -max_total_time=300
```

## Seed corpus

`fuzz/corpus/<target>/` contains seed inputs that give the fuzzer a head start.
Seeds are checked in and cover boundary cases (full address space, single IPs, host-bits-set prefixes, etc.).

libFuzzer automatically saves any inputs that increase code coverage into the
corpus directory, so the corpus grows over time as you fuzz.

## Investigating a crash

When a crash is found, libFuzzer writes the reproducer to
`fuzz/artifacts/<target>/crash-<hash>`. To reproduce it:

```sh
cargo +nightly fuzz run parse_range fuzz/artifacts/parse_range/crash-<hash>
```

To get a full stack trace, build with the address sanitizer enabled (Linux only):

```sh
cargo +nightly fuzz run parse_range
```

Then minimize the input to the smallest case that still crashes:

```sh
cargo +nightly fuzz tmin parse_range fuzz/artifacts/parse_range/crash-<hash>
```

## Extending coverage

To add a new target:

```sh
cargo +nightly fuzz add <target_name>
# then edit fuzz/fuzz_targets/<target_name>.rs
```

Add representative seed inputs in `fuzz/corpus/<target_name>/`.

## CI integration

The `fuzz.yml` workflow runs a 30-second smoke session for each target on
every push to `main` and on demand via `workflow_dispatch`. This catches
obvious panics and regressions against the seed corpus quickly.

For sustained coverage, run fuzz targets locally overnight or on a dedicated
machine — 30 seconds is not enough time to explore deep paths.
