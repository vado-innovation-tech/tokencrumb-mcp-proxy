# Changelog

## Unreleased

- Temporarily use custom `biscuit-auth` 6.0.0-tokencrumb.1 to disable unused Datalog macros and remove `proc-macro-error2`. Return to the official crate once its feature-gating fix passes compatibility and security checks; see [the migration plan](docs/biscuit-auth.md).
- Name the project **TokenCrumb - MCP Proxy**, the package `tokencrumb-mcp-proxy` and the executable `tokencrumb`.
- Provide English documentation and generic configuration and container assets.
- Keep versioned attestation and registry signature domains compatible.
- Maintain issuer interoperability and synthetic reference fixtures.
- Update the time parser and TLS server dependency to address dependency audit findings.

## 0.3.0

- Implement the proxy, CLI, registry and security primitives in Rust.
- Verify compatibility with reference capability, policy, audit and storage fixtures.
