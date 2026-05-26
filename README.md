# ipnetx

Before publishing to crates.io
1. Fix overlaps_ip_set (implement or hide it)
2. Add #[must_use] to predicates
3. Fill in IpSet test gaps (especially contains_range)
4. Write /// doc comments — run cargo doc --open until it looks good
5. Update Cargo.toml + add LICENSE + rewrite README
6. Run cargo clippy -- -D warnings and fix everything it finds
7. cargo publish --dry-run — this will catch anything else crates.io will reject

A publishable README needs:
  - What the crate does (one paragraph)
  - A quick usage example (actual code with use statements)
  - Link to docs.rs once published

  Consider criterion for some benchmarks

Helpful References
- https://cs.opensource.google/go/go/+/refs/tags/go1.22.0:src/net/netip/netip.go
- https://oneuptime.com/blog/post/2026-02-01-rust-profiling-optimization/view


Setup Testing Coverage
- `rustup component add llvm-tools-preview`
- `cargo install cargo-llvm-cov`
- `cargo llvm-cov --html`
- `open target/llvm-cov/html/index.html`
- OR: `cargo llvm-cov`
