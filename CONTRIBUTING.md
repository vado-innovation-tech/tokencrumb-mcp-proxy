# Contributing

Use English for code comments, documentation, issues, pull requests and commit messages.

Before changing authorization or storage behavior, read the [architecture](docs/architecture.md) and [security model](docs/security-model.md). Explain the behavior change and add a regression test that would fail without it. Preserve signed protocol identifiers unless introducing an explicit, documented migration.

Run:

```sh
cargo fmt --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo doc --workspace --no-deps --locked
python3 tools/check_vendor.py
python3 tools/audit_dependencies.py
python3 tools/check_docs.py
gitleaks git --log-opts="--all" --redact
```

Include the relevant test results in your pull request. Keep changes focused. Never commit operational credentials, generated keys, tokens, logs or private infrastructure details. Fixed synthetic cryptographic fixtures belong only in the documented test directories.

See [development](docs/development.md) for the container and live integration checks.
