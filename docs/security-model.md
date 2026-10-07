# Security model

## Protected boundary

In enforcement mode, the proxy prevents forwarding a tool call unless its trusted authority capability, profile requirements, call attestation where required, policy checks and budget permit it. This assumes clients cannot bypass the proxy and the host, configured trust anchors, clock and persistent state remain trustworthy.

The default policy requires `hardened_biscuit_anchored`. A stolen capability alone does not provide the agent private key needed to sign a new call. A captured signed call is also subject to nonce and timestamp checks. The `native` profile intentionally retains bearer semantics; never attribute proof-of-possession guarantees to that profile.

## Controls and regression coverage

| Threat | Control | Test suite |
| --- | --- | --- |
| Stolen token with a substituted agent key | Authority-only key binding and profile enforcement | `adversarial`, `security_contract` |
| Replayed or modified call | Signature, nonce, timestamp, argument and token binding | `verifier`, `security_lifecycle` |
| Token for another deployment or route | Audience and upstream checks | `audience_upstream`, `multi_upstream` |
| Broader delegation | Append-only restrictions and tightest signed bounds | `delegation_depth`, `tool_attenuation` |
| Budget reset after attenuation or restart | Root-based counters and durable state | `budget_two_level`, `budget_persist`, `one_shot` |
| Policy or parser confusion | Strict JSON/YAML, typed metadata and bounded Datalog | `security_configuration`, `security_contract`, `datalog_limits` |
| Hidden protocol route | Explicit MCP method handling | `proxy_router`, `security_http_audit` |
| Audit tampering without the key | Signed hash chain and trusted key verification | `audit_chain` |

These tests establish specific local behaviors, not a certification of any deployment.

## Limits

- An operator controlling the host can change policy, keys, code, clock or persistent state. Cryptography does not make that operator untrusted by default.
- An issuer holding a trusted authority private key can issue new capabilities. Accepting several roots means any accepted root can authorize; it is not a quorum.
- An agent with valid keys can abuse any operation actually granted to it. The proxy does not make model output truthful or prevent prompt injection from selecting an allowed tool.
- Resource mappings depend on upstream semantics. Canonicalizing a path does not resolve symlinks or prove what a remote tool will read.
- Budgets count authorized calls, not bytes, rows, monetary cost or exactly-once upstream effects. A failure after authorization can consume budget without a successful upstream result.
- Local state persistence is not a cross-host distributed consistency guarantee. Rollback or independent replicas can violate intended global limits.
- Audit integrity does not prove completeness. The audit signer can rewrite and re-sign a local chain unless an independent witness retains checkpoints.
- Revocation is effective after trusted updates reach the verifier. It is not an instantaneous global operation.
- MCP resources, prompts and server-initiated interaction are unsupported. `tools/list` is catalog filtering, not an authorization grant.
- Observation mode is not an enforcement boundary. TLS, host protection, key lifecycle and upstream access controls remain deployment responsibilities.

Report vulnerabilities using [SECURITY.md](../SECURITY.md).
