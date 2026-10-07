# TokenCrumb - MCP Proxy

An MCP authorization proxy and CLI using attenuable Biscuit capabilities, agent-signed calls, persistent budgets and verifiable audit logs.

The package provides the `tokencrumb` executable and the `tokencrumb_mcp_proxy` Rust library.

This checkout temporarily uses **custom `biscuit-auth` 6.0.0-tokencrumb.1** to disable unused macros and remove the unmaintained `proc-macro-error2` dependency. We will return to an official Biscuit release once its feature-gating fix passes our compatibility and security checks. See [provenance and the return-to-upstream plan](https://github.com/vado-innovation-tech/tokencrumb-mcp-proxy/blob/main/docs/biscuit-auth.md). Build from the full repository checkout; registry publication is disabled while the local dependency is required.

See the [project README](https://github.com/vado-innovation-tech/tokencrumb-mcp-proxy#readme), [documentation](https://github.com/vado-innovation-tech/tokencrumb-mcp-proxy/tree/main/docs) and [security model](https://github.com/vado-innovation-tech/tokencrumb-mcp-proxy/blob/main/docs/security-model.md).

Licensed under Apache-2.0; see LICENSE in this package.
