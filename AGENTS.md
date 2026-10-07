# Repository guidance

Keep product code, documentation and commit messages in English. Read docs/architecture.md and docs/security-model.md before changing authorization behavior.

Preserve the signed wire domains described in docs/compatibility.md. Keep test keys synthetic and document fixture provenance. Do not put credentials, tokens, logs, private infrastructure or local work notes in Git.

For Rust changes run formatting, Clippy and the relevant tests. For release changes run the full checks in CONTRIBUTING.md. Keep documentation commands executable against the current CLI.
