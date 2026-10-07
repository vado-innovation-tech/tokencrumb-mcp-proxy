# Getting started

Install the CLI and generate the three key pairs using the [README](../README.md). Start an existing MCP upstream that provides `read_file` and accepts a `path` argument. The sample policy is an example contract, not an adapter for every filesystem server: match the upstream's tool names, arguments and path semantics.

The authority signs capabilities, the agent signs calls, and the proxy signs its audit log. Only the authority **public** key belongs on the proxy; the authority private key and agent private key stay with their respective owners.

## Connect a client

A desktop client supporting stdio MCP servers can launch:

```json
{
  "mcpServers": {
    "workspace": {
      "command": "/absolute/path/to/tokencrumb",
      "args": [
        "client-wrap",
        "--proxy", "http://127.0.0.1:9443/mcp",
        "--token", "/absolute/path/to/state/capability.b64",
        "--agent-key", "/absolute/path/to/state/agent.key"
      ]
    }
  }
}
```

The wrapper uses newline-delimited JSON-RPC on stdin/stdout. Diagnostics go to stderr. It signs each `tools/call` and reloads a file-backed capability when that file changes. Give each configured upstream its own client entry.

A call to `read_file` with `{"path":"/workspace/notes.txt"}` can pass the sample policy. `/private/notes.txt` must be denied before reaching the upstream. The upstream still applies its own authorization and filesystem controls.

## Narrow a capability

```sh
tokencrumb attenuate --token state/capability.b64 \
  --authority-pub state/authority.pub \
  --resource /workspace/reports/ --budget 5 --ttl 5m \
  --tool read_file --out state/restricted.b64

tokencrumb inspect state/restricted.b64
```

Use `restricted.b64` in the wrapper to apply the tighter scope. Each appended block adds constraints. It cannot extend the original lifetime, restore a removed tool or reset the root capability's spent budget. Attenuate the latest token when extending an existing delegation chain.

`inspect` decodes a token for inspection; it is not a trust decision. The proxy verifies the signature against configured authority keys.

## Verify the audit

```sh
tokencrumb audit-verify --log state/audit.log --pub state/audit.pub
```

To retain an independent checkpoint:

```sh
tokencrumb audit-head --log state/audit.log --key state/audit.key \
  --out state/audit-head.json
```

Store checkpoints on a separate system the proxy cannot rewrite. An intact local chain alone does not prove completeness or protect against its own signing key holder.

## Reproduce the local integration check

```sh
cargo build --locked --bin tokencrumb
python3 tools/smoke.py --binary target/debug/tokencrumb
```

This check creates temporary synthetic keys and an isolated test upstream, exercises the real CLI and wrapper, verifies scope denials, and checks the audit chain. It does not require external accounts or credentials.
