# Contributing to CubeHash

Thank you for helping improve the CubeHash algorithm! Because `main` is a protected branch for a cryptographic engine, all changes go through Pull Requests with mandatory automated verification and maintainer review.

## Development Workflow

1. Fork or create a focused branch from `main` (e.g., `fix/tmr-edge-case`, `feat/mlkem-hybrid`).
2. Keep `cubehash-core` strictly focused on the core algorithm (`#![forbid(unsafe_code)]` must remain at line 1 of `crates/cubehash-core/src/lib.rs`). Never introduce networking, chat servers, or transport app code into this repository.
3. Run every required local check before opening a PR:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run --release -p cubehash-cli
cargo build --release -p cubehash-ffi
```

4. If modifying mathematical constructions, key schedules, bijective mappings, or wire formats, update [docs/MATHEMATICS.md](docs/MATHEMATICS.md), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), and add deterministic adversarial regression tests to `crates/cubehash-core/tests/security_suite.rs`.
5. Open a Pull Request targeting `main`. Once **CI Gate** passes and `@hami9` approves, the PR merges cleanly into `main`.

## License

By contributing, you agree that your contributions are dual-licensed under **MIT OR Apache-2.0** ([LICENSE-MIT](LICENSE-MIT) / [LICENSE-APACHE](LICENSE-APACHE)).
