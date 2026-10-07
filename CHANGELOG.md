# Changelog

## Unreleased

### Added

- Add `dpop-proof` to generate agent-signed proofs for issuer HTTP requests.
- Accept a Biscuit embedded in an OIDC access-token response during bootstrap, verifying the Biscuit against a separately provisioned authority key. The enclosing JWT is not authenticated by this command.
- Support repeated `attenuate --tool` restrictions and trusted tool-name facts during authorization.
- Add HTTP and native HTTPS smoke checks, dependency auditing, and secret scanning in CI, including detection of the project's plaintext private-key format.

### Changed

- Reload a file-backed client capability when its file changes.
- Remove the draft-07 `$schema` declaration from tool input and output schemas returned by `tools/list`.
- Name the project **TokenCrumb - MCP Proxy**, the package `tokencrumb-mcp-proxy` and the executable `tokencrumb`, preserving the versioned attestation and registry signature domains.
- Consolidate setup, configuration, deployment, security, compatibility and contribution documentation in [README.md](README.md). Remove the roadmap and stop tracking local agent instructions.
- Provide generic configuration and container assets and document Linux and macOS support.
- Temporarily use custom `biscuit-auth` 6.0.0-tokencrumb.1 to disable unused Datalog macros and remove `biscuit-quote` and `proc-macro-error2` from the resolved dependencies. Verify the vendored source and audit both the build lockfile and Biscuit's official upstream base; see [provenance and removal criteria](README.md#temporary-biscuit-dependency).
- Disable registry publication while the custom Biscuit dependency requires a full checkout.

### Dependency updates

- Update the resolved `time` dependency from 0.3.45 to 0.3.55 and `axum-server` from 0.7.3 to 0.8.0 to address dependency audit findings; remove `rustls-pemfile` from the resolved dependencies.
- Remove unused direct dependencies and update CI actions.

## 0.3.0

- Implement the proxy, CLI, registry and security primitives in Rust.
- Verify compatibility with reference capability, policy, audit and storage fixtures.
