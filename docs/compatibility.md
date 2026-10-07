# Compatibility

The product is **TokenCrumb - MCP Proxy**. The executable is `tokencrumb`, the Cargo package is `tokencrumb-mcp-proxy`, and the Rust import is `tokencrumb_mcp_proxy`.

Existing command-line integrations must update the executable path. Configuration keys, capability semantics and versioned signed formats remain compatible with the reference implementation.

## Signed identifiers

The attestation domain `biscuitmcp/tools-call` and registry domain `biscuitmcp/agent-registry` remain unchanged. These are cryptographic protocol identifiers, not presentation labels. Changing them silently would invalidate signatures and break existing issuers or clients. The synthetic interoperability audience `biscuitmcp://interop` is likewise retained inside signed test tokens.

Do not perform a global replacement of those values. A future protocol migration must use explicit versioning, documented trust rules and cross-implementation tests.

## Reference fixtures

`crates/tokencrumb-mcp-proxy/tests/golden/` contains fixed outputs captured from an independent Python reference implementation. Inputs use synthetic keys, generic identifiers and reserved example addresses. The Rust tests verify these outputs rather than regenerating their own expected answers.

`tests/fixtures/interop/interop.json` exercises capabilities, encrypted keys, revocation and audit data written by the reference CLI. `tests/fixtures/java_mandate.json` exercises independent issuer interoperability. Private keys embedded in these fixture files are public test data and must never be deployed.

Unicode, intentionally malformed tokens and legacy format samples are deliberate test inputs. They are not user-facing language or live credentials. The runtime and normal test suite require no Python package dependencies; the smoke and documentation tools use only Python's standard library.
