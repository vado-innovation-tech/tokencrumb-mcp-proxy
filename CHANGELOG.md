# Changelog

## Unreleased

### Added

- Support MCP 2026-07-28 next to `2025-06-18` and `2025-11-25` (dual-era): `mcp.spec_version` accepts a list (a single string remains valid), the era of each agent request and of each upstream (`server/discover` probe) is detected, `initialize`-era agents are translated for 2026-07-28 upstreams, and 2026-07-28 agents meeting an `initialize`-era upstream receive `UnsupportedProtocolVersion` to fall back.
- Check `MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name` and `Mcp-Param-*` against the body of 2026-07-28 requests before any decision (HTTP 400, `HeaderMismatch`), and recompute them from the forwarded body, including after `upstream_tool` renames. These names are reserved for upstream credentials.
- Relay `server/discover` reduced to `tools`; mark filtered 2026-07-28 tool lists `cacheScope: "private"` with a short `ttlMs`; add `resultType` to every gateway result in 2026-07-28 mode; empty the per-request client capabilities; refuse multi round-trip requests and tasks with code −31001.
- Record unsupported `MCP-Protocol-Version`, header mismatch and tracked-client-cap (429) refusals in the signed audit log.
- Add third-party authorities: a `third_party:` policy section declares second signers and the predicates each may state, and `require_third_party` makes a tool need their endorsement, read from Biscuit third-party blocks through `trusting` checks. Undeclared signers, undelegated predicates, rules and reserved facts in those blocks refuse the mandate; denials name the missing endorsement and the audit records the endorsing authorities.
- Refuse a mandate whose agent key, anchored in the authority block or resolved by the registry, is also a declared third-party key, current or previous: the agent could otherwise sign the endorsements a tool requires of a second authority. The audit reason reads `third-party key is the agent key`, whether or not the token carries a third-party block.
- Add `third-party-request`, `third-party-sign` and `third-party-append`, `keygen --type third-party`, `inspect --json` with per-block external keys and revocation ids, and `revoke --block` to revoke a token from one block on, such as a single endorsement.
- Add human approval of exact tool calls (HOLD): an `approvers:` policy section registers people and their keys, and `approval:` makes a tool require a single-use receipt signed by one of them over the call's intent hash. A call without a receipt is held — not forwarded, not charged — and answered with the intent to approve; the audit records `HOLD`, `ALLOW` with `detail.approval`, and `OUTCOME` (`ok`, `upstream_error`, `unknown`). Receipts arrive in the `approval-receipt` header and are consumed durably in the nonce database before forwarding; reservations past their lease are settled `unknown` at startup and periodically. Approver keys cannot be root, third-party or audit keys, approval tools require the attestation proofs, and warn-only mode still holds.
- Add `approve`, `inspect-receipt`, `keygen --type approver` and `client-wrap --approval-dir`, which writes held requests and attaches the matching receipt to the identical replay. Add [policy-approval.yaml](policy-approval.yaml).
- Add `dpop-proof` to generate agent-signed proofs for issuer HTTP requests.
- Accept a Biscuit embedded in an OIDC access-token response during bootstrap, verifying the Biscuit against a separately provisioned authority key. The enclosing JWT is not authenticated by this command.
- Support repeated `attenuate --tool` restrictions and trusted tool-name facts during authorization.
- Add HTTP and native HTTPS smoke checks, dependency auditing, and secret scanning in CI, including detection of the project's plaintext private-key format.
- Document a direct email contact for private vulnerability reports.

### Changed

- Ignore `Mcp-Session-Id` in 2026-07-28 requests and propagate session and `Last-Event-ID` headers only to `initialize`-era upstreams.
- Answer an unsupported `MCP-Protocol-Version` with a JSON-RPC `UnsupportedProtocolVersion` error body listing the accepted revisions, instead of an empty 400.
- Reload a file-backed client capability when its file changes.
- Remove the draft-07 `$schema` declaration from tool input and output schemas returned by `tools/list`.
- Name the project **TokenCrumb - MCP Proxy**, the package `tokencrumb-mcp-proxy` and the executable `tokencrumb`, preserving the versioned attestation and registry signature domains.
- Consolidate setup, configuration, deployment, security, compatibility and contribution documentation in [README.md](README.md). Remove the roadmap and stop tracking local agent instructions.
- Provide generic configuration and container assets and document Linux and macOS support.
- Temporarily use custom `biscuit-auth` 6.0.0-tokencrumb.1 to disable unused Datalog macros and remove `biscuit-quote` and `proc-macro-error2` from the resolved dependencies. Verify the vendored source and audit both the build lockfile and Biscuit's official upstream base; see [provenance and removal criteria](README.md#temporary-biscuit-dependency).
- Disable registry publication while the custom Biscuit dependency requires a full checkout.

### Dependency updates

- Update `rustls` to 0.23.46, `rustls-webpki` to 0.103.16, `webpki-roots` to 1.0.10 and `tokio` to 1.54.1 to address RUSTSEC-2026-0346 to 0349, 0381, 0382 and 0386.
- Suppress RUSTSEC-2026-0387 (`crypto-bigint` 0.5.5 through Biscuit's mandatory `p256` 0.13) in `.cargo/audit.toml`, with its reason and removal condition in the README; TokenCrumb signs with Ed25519 only.
- Update the resolved `time` dependency from 0.3.45 to 0.3.55 and `axum-server` from 0.7.3 to 0.8.0 to address dependency audit findings; remove `rustls-pemfile` from the resolved dependencies.
- Remove unused direct dependencies and update CI actions.
- Pin every GitHub Action to a full commit SHA, retaining its original version or branch as a comment.

## 0.3.0

- Implement the proxy, CLI, registry and security primitives in Rust.
- Verify compatibility with reference capability, policy, audit and storage fixtures.
