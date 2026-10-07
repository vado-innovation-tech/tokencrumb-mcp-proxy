# Development

CI covers Linux and macOS. Windows is not currently supported: persistent storage uses Unix file permissions and locking. Use Rust 1.88 or newer and Python 3.11 or newer for repository checks. The TLS smoke check also requires OpenSSL. Build dependencies are recorded in `Cargo.lock`.

```sh
cargo fmt --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo doc --workspace --no-deps --locked
cargo build --release --locked --bin tokencrumb
python3 tools/check_vendor.py
python3 tools/check_docs.py
python3 tools/smoke.py --binary target/release/tokencrumb
python3 tools/smoke.py --binary target/release/tokencrumb --tls
cargo run --locked -p tokencrumb-interop -- crates/tokencrumb-mcp-proxy/tests/fixtures/java_mandate.json
docker build -f deploy/Dockerfile -t tokencrumb-mcp-proxy:local .
docker run --rm tokencrumb-mcp-proxy:local --help
```

The library tests cover parsing, signatures, attenuation, revocation, replay protection, budgets and canonicalization. Integration tests cover CLI behavior, actual HTTP transports, state recovery and issuer interoperability. Fixed independent reference fixtures provide compatibility checks; do not regenerate expected cryptographic output from the implementation under test to make a failure disappear.

Use `cargo fmt --check` to check workspace members. Avoid `--all` while the custom Biscuit snapshot is present: it also formats local path dependencies and would rewrite preserved upstream source.

## Secret scanning

Run Gitleaks against both current files and all publishable history:

```sh
gitleaks dir --redact
gitleaks git --log-opts="--all" --redact
```

The repository configuration narrowly excludes reviewed public-key, nonce-digest and synthetic attestation fields in two reference fixture files from the generic API-key rule. These exceptions do not exempt other secret rules. A dedicated rule also detects the project’s plaintext Ed25519 key format, with exceptions for the four documented synthetic key fixture files and the exact upstream test value described below. Test private keys are intentionally synthetic; operational keys belong outside Git.

The vendored Biscuit source retains upstream inline tests. Two additional exceptions match only the exact published test public key in `src/bwk.rs` and the exact synthetic private key in `src/crypto/mod.rs`, restricted to those vendor paths. Other values and files remain scanned.

## Dependency maintenance

Run `cargo audit` to check the lockfile against RustSec. CI fails on known vulnerabilities and reports maintenance advisories. No advisory is suppressed.

The repository temporarily includes **custom `biscuit-auth` 6.0.0-tokencrumb.1**, which fixes compilation without Datalog macros and removes the unmaintained `proc-macro-error2` dependency. Return to an official upstream release as soon as its fix passes our validation. Read the [patch scope, provenance and removal procedure](biscuit-auth.md) before updating the snapshot. `python3 tools/check_vendor.py` verifies the reviewed source and prevents reintroducing the macro packages into the lockfile.

## Packaging

Build and install from the full checkout with `cargo install --locked --path crates/tokencrumb-mcp-proxy`, or build the provided container. Source archives must include the `vendor/` directory.

Registry publication is temporarily disabled with `publish = false`. `cargo package` cannot produce a usable standalone registry package while the custom dependency exists only in this checkout; substituting the unpatched upstream crate would break the build. Restore registry packaging only after [returning to an official Biscuit release](biscuit-auth.md#return-to-the-official-release). A successful local build is not permission to publish a package or change repository visibility.
