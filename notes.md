# Publishing
- Before publishing, check the code test coverage.
- Run: `cargo publish --dry-run`
- Run `cargo test` to run the test suite.
- Run `cargo llvm-cov` to generate a test coverage report.
- `cargo clippy -- -D warnings` to run clippy with all warnings enabled. Fix anything it finds.
- Try and reflect on documentation and the `README.md`. Does anything need to be updated?
  - Specifically a version reference, or added / modified / removed functionality.
  - Try to be as descriptive as possible. Pretend that prospective users of the library are reading this from the standpoint of a student who wants to learn how to use it.
  - Provide examples and use cases where appropriate.

# Test Coverage
- I chose to install `cargo-llvm-cov`
  - You may need to run: `rustup component add llvm-tools-preview`
  - You may also need to export `LLVM_COV` and `LLVM_PROFDATA` to point to the `llvm-cov` and `llvm-profdata` binaries in your `$PATH`
- You can generate an HTML document
  - `cargo llvm-cov --html`
  - `open target/llvm-cov/html/index.html`
- Or you can generate a terminal report
  - `cargo llvm-cov`
  - To see missing lines: `cargo llvm-cov --show-missing-lines`
- `cargo bench`

# Helpful References
- https://cs.opensource.google/go/go/+/refs/tags/go1.22.0:src/net/netip/netip.go
- https://oneuptime.com/blog/post/2026-02-01-rust-profiling-optimization/view
