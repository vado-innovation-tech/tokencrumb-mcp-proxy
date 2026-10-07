# Architecture

The Rust package contains the verifier, cryptographic and persistence primitives, MCP proxy, registry, and CLI. They share a library; ownership of private keys is a deployment boundary, not a claim that every command runs in one process.

## Control and data paths

The issuer signs the authority block of a Biscuit capability. Holders can append checks offline to reduce its scope. The agent wrapper signs each tool call. The proxy verifies the capability and call, applies its policy, records a decision and forwards an authorized request. Upstream authorization remains in force.

The authority public key is the trust anchor. An issuer name is signed metadata, not a replacement for a trusted key. Governed identity fields are accepted only from the authority block. Appended blocks cannot substitute an agent key, audience or issuer identity.

## Verification

The implementation performs bounded token parsing and signature verification, validates governed metadata and expiry, checks the required profile, validates call attestations where required, canonicalizes resources and arguments, evaluates Datalog checks and policy, and atomically charges the applicable budget. Errors fail closed in enforcement mode.

Attestations bind the agent identity, tool name, canonical argument hash and capability hash, with a timestamp and nonce. Signature verification alone is insufficient: freshness, token binding, expected identity and nonce state are checked as part of the authorization decision.

The policy supplies trusted facts for the current call. A capability may constrain those facts with checks; it may not manufacture verified proof facts. The effective rights are the intersection of the authority's grant, appended restrictions, runtime policy and upstream authorization.

## MCP transport

The proxy supports the configured MCP revision `2025-06-18`. Each upstream has its own endpoint and sessions. Tool lists are filtered through local policy mappings; callers still need authorization for each tool call. JSON-RPC batches and unsupported methods are refused. Server-initiated interaction and a long-lived server event channel are outside the supported surface.

HTTP upstreams use transport clients; stdio upstreams run as child processes. Child process commands are operator configuration, not client-supplied actions. The client wrapper translates stdio JSON-RPC into calls to the proxy.

## State and audit

Budget counters are keyed by the root capability and by tool. Attenuation does not create a fresh spending identity. Nonces persist in SQLite. Signed revocation documents are validated before use. File publication and locking protect local state transitions; no distributed transaction manager is included.

Audit entries carry sequence, previous hash, policy digest, decision context and a signature. Client-facing denials are generic and expose a correlation identifier; detailed reasons belong in the audit. Verify the chain with separately trusted public keys and retain external checkpoints to detect history rewrites by the audit signer.
