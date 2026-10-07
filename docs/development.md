# Development

Use Rust 1.88 or newer and Python 3.11 or newer for repository checks. Build dependencies are recorded in `Cargo.lock`.

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo doc --workspace --no-deps --locked
cargo build --release --locked --bin tokencrumb
python3 tools/check_docs.py
python3 tools/smoke.py --binary target/release/tokencrumb
cargo run --locked -p tokencrumb-interop -- crates/tokencrumb-mcp-proxy/tests/fixtures/java_mandate.json
docker build -f deploy/Dockerfile -t tokencrumb-mcp-proxy:local .
docker run --rm tokencrumb-mcp-proxy:local --help
```

The library tests cover parsing, signatures, attenuation, revocation, replay protection, budgets and canonicalization. Integration tests cover CLI behavior, actual HTTP transports, state recovery and issuer interoperability. Fixed independent reference fixtures provide compatibility checks; do not regenerate expected cryptographic output from the implementation under test to make a failure disappear.

## Secret scanning

Run Gitleaks against both current files and all publishable history:

```sh
gitleaks dir --redact
gitleaks git --log-opts="--all" --redact
```

The repository configuration narrowly excludes reviewed public-key, nonce-digest and synthetic attestation fields in two reference fixture files from the generic API-key rule. It does not exempt source code or other secret rules. Test private keys are intentionally synthetic; operational keys belong outside Git.

## Packaging

```sh
cargo package --locked --package tokencrumb-mcp-proxy
```

Inspect the resulting archive before any registry publication. A successful local build is not permission to publish a package or change repository visibility.
