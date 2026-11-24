# ADR 0007 — Code Mode: one endpoint, model-written scripts, per-call enforcement

- Status: Accepted
- Date: 2026-11-24

## Context

Today each upstream has its own gateway endpoint (`/mcp/<name>`) and clients register one entry per service (`tokencrumb-kdrive`, `tokencrumb-github`, …). Every tool definition of every service sits in the model's context, and each intermediate tool result goes back through the model.

Cloudflare's Code Mode (blog posts of 2025-09-26 and 2026-04-14, package `@cloudflare/codemode`) replaces all tools with two: `search` and `execute`. The model writes JavaScript against a typed API of the upstream tools; the code runs in a sandbox and only its output returns to the model. Cloudflare reports about 94 % fewer tokens for tool definitions and about 81 % fewer for a complex task (vendor figures, not independently verified). Its executor requires Cloudflare Workers, and its simple modes have no per-call human approval.

TokenCrumb is an authorization gateway. Its guarantees are per call: an agent signature over the public tool name and the arguments hash (`biscuitmcp/tools-call`), policy, budget, approval receipts and a signed audit. A script that issues calls on the agent's behalf must not weaken any of them. Target users are many, with highly sensitive data, on every MCP client, including web clients that cannot run `client-wrap`.

## Decision

### Scope

1. TokenCrumb offers a Code Mode endpoint that exposes all of a user's upstreams through `search` and `execute`.
2. The current per-service endpoints remain available as an option.
3. Only MCP tools are in scope. Resources, prompts, elicitation and sampling stay available through the per-service endpoints only.

### API

4. JavaScript only, with an API compatible with Cloudflare Code Mode:
   - `search` filters `codemode.tools()` and returns TypeScript declarations;
   - `execute` calls functions such as `codemode.kdrive_list_files({...})`, the service name prefixed to the tool name.
5. `search` lists only the tools the caller's capability authorizes. The catalog is itself sensitive.

### Where scripts run

6. Hybrid execution:
   - **Client side**, when `client-wrap` is present: the script runs in a QuickJS sandbox inside `client-wrap`, which signs each call as today.
   - **Server side**, otherwise: a separate `tokencrumb-codemode` service runs the script in one microVM per execution (Firecracker or gVisor).
7. Calls issued by a script go through the gateway's existing `/mcp/<service>` endpoints, like any other client. Policy, budget, approval and audit stay enforced per call, in the gateway. The service that runs code holds none of the gateway's keys.
8. Web clients without an agent key must sign in with OAuth (Keycloak → `tokencrumb-exchange` → Biscuit) and receive a short-lived capability bound to the user. Read calls proceed; write calls require approval. Policy can tighten this per tool.

### Limits and data flows

9. Per-script limits, configurable in policy. Defaults: 50 calls, 60 s, output capped at about 6,000 tokens.
10. Cross-service flow rules, declared per pair of services (allowed or denied), are enforced at run time. Once a script has called a service, later calls in the same script to a service denied for that flow are refused. The taint lasts for one script, not the session. A refusal surfaces as an exception the script can catch.

### Human approval

11. Users approve individual write calls with their concrete arguments, not scripts. The existing intent and HOLD mechanism applies unchanged:
    - the script stops at the held call;
    - the model receives what was already done;
    - after approval, the model runs again.
12. Approval happens on a TokenCrumb web page with a passkey, opened from a push notification. Approval receipts must accept P-256 (WebAuthn) signatures in addition to Ed25519.
13. A built-in "self" approver group lets users approve their own calls. That is the default. Policy can require a third-party group for critical tools.

### Audit

14. The audit records the full script and every call it issues. Each call entry carries the script hash.

## Consequences

### Preserved

- The `biscuitmcp/tools-call` signing domain is unchanged: approvals stay per call (point 11).
- The gateway's enforcement path is unchanged: scripts are just another client of `/mcp/<service>` (point 7).

### New work

- `tokencrumb-codemode` service.
- QuickJS sandbox in `client-wrap`.
- Capability-filtered `search`.
- Flow taint.
- Script audit entries.
- P-256 receipts.
- Approval page and notification.
- "self" approver group.

### Accepted trade-offs

- Web clients authenticate with a bearer capability. There is no proof of possession: the token is held by the client's provider, and a manipulated model can use it. Write approval (point 8) is the mitigation.
- A held write call interrupts the script, and the model must re-run the remaining work.

### Prerequisite to verify

The server-side microVM needs KVM on the cluster nodes (Firecracker) or a gVisor RuntimeClass.

## Alternatives rejected

- **Aggregator without a sandbox** (search plus batched calls). It saves definition tokens but not intermediate results.
- **Signing whole scripts.** It needs a new signing domain, and a person cannot meaningfully read and approve code.
- **V8 isolates on the server.** Engine escapes would cross tenants, which is unacceptable for highly sensitive data.
- **Static analysis of scripts for flow rules.** It is unreliable, because JavaScript can build call names dynamically.
- **Pausing and resuming a held script.** It would require persisting sandbox state. To revisit if needed.
