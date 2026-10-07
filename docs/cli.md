# CLI reference

Run `tokencrumb --help` or `tokencrumb <command> --help` for all flags. Usage errors exit with status 2; rejected operations exit with status 1. Commands producing tokens send status messages to stderr so stdout can be redirected safely.

| Command | Purpose |
| --- | --- |
| `keygen` | Generate authority, agent or audit Ed25519 keys. |
| `forge` | Sign an authority capability with tools, audience, expiry and optional scope. |
| `attenuate` | Append restrictions without the authority private key. |
| `inspect` | Decode blocks and metadata without establishing trust. |
| `serve` | Run the authorization proxy. |
| `client-wrap` | Adapt a stdio MCP client to the proxy and sign tool calls. |
| `bootstrap` | Validate an issuer URL or verify a returned token against a provisioned trust anchor. |
| `dpop-proof` | Produce an agent-signed proof for an issuer HTTP request. |
| `policy-install` | Validate and atomically replace a policy file. |
| `revoke` | Add a token or identifier to a signed revocation list. |
| `revocation-migrate` | Verify and convert a legacy signed revocation list into a new file. |
| `registry-serve` | Serve signed agent key records for the registry-backed profile. |
| `registry-add` | Register an agent key over HTTP or directly in a store. |
| `audit-verify` | Check audit hashes, signatures and chain continuity. |
| `audit-head` | Produce a signed checkpoint for an independent witness. |

## Issuer integration

Provision the authority public key through a trusted channel first. The issuer response is not a source of trust anchors.

```sh
tokencrumb bootstrap --url https://issuer.example.com/capabilities
tokencrumb bootstrap --response state/issuer-response.json \
  --authority-pub state/authority.pub --out state/capability.b64
tokencrumb dpop-proof --agent-key state/agent.key \
  --url https://issuer.example.com/capabilities --method POST
```

`bootstrap --url` validates transport safety; it does not authenticate to the issuer or request a capability. `dpop-proof` creates a proof for the requested method and URL. The issuer must verify proof possession and apply its own issuance policy.

## Revoke a capability

```sh
tokencrumb revoke --key state/authority.key \
  --from-token state/capability.b64 --out state/revoked.list
```

Set the policy's `revocation` path to this file. Revocation must be distributed to each verifier. Multiple accepted authority keys do not imply multiple required signers.

## Registry-backed profile

```sh
tokencrumb keygen --out state/registry --type authority
tokencrumb registry-add --agent-id reader --pubkey "$(cat state/agent.pub)" \
  --store state/agents.json
tokencrumb registry-serve --signing-key state/registry.key \
  --store state/agents.json --write-token file:/absolute/path/to/registry-write-token \
  --listen 127.0.0.1:8081
```

Provision the write-token file separately. Configure the proxy with `--registry`, `--registry-pub` and an appropriate policy profile. Use TLS for remote registry access. The default key-anchored profile needs no registry.

## Keys and persistence

`keygen --passphrase` encrypts a private key with scrypt and AES-GCM. Avoid disclosing passphrases in shell history or process listings. Generated plaintext keys require restricted filesystem permissions and an appropriate key-management process.

The proxy requires `--audit-key`; `--ephemeral-audit-key` is an explicit alternative with no persistent signing identity. Budget state defaults beside the audit log; specify `--budget-state` to make its location explicit. The nonce database is derived from that state path.
