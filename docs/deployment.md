# Deployment

## Trust and network boundaries

Keep the authority private key on the issuer and the agent private key on the client. Provision only authority public keys, the proxy's audit signing key and necessary upstream credentials to the proxy.

Clients must reach protected tools through the proxy. Enforce that with upstream network isolation or independent upstream authentication. Otherwise a caller can bypass the proxy completely.

The CLI refuses non-loopback cleartext listeners unless `--insecure-http` is explicit. Prefer native TLS with `--tls-cert` and `--tls-key`. Certificates must be renewed externally and the process restarted; ACME and certificate hot reload are not implemented. If a reverse proxy terminates TLS, keep the cleartext hop in a trusted isolated network.

## Container

```sh
docker build -f deploy/Dockerfile -t tokencrumb-mcp-proxy:local .
docker run --rm tokencrumb-mcp-proxy:local --help
```

The image runs as UID 10001 and contains the CLI and CA certificates. Its build context uses an allowlist. No keys, capability files, logs or local notes are included.

The [Compose configuration](../docker-compose.yml) requires:

- `state/config/authority.pub`: the trusted issuer key.
- `state/config/audit.key`: the proxy audit signing key, readable by UID 10001.
- `state/config/policy.yaml`: a policy matching your upstream.
- `state/config/tls.crt` and `state/config/tls.key`: your server certificate and private key.
- `UPSTREAM_URL`: an MCP endpoint reachable from the container.

```sh
UPSTREAM_URL=https://upstream.example.com/mcp docker compose config
UPSTREAM_URL=https://upstream.example.com/mcp docker compose up --build -d
```

The URL above is a placeholder. Replace it before starting. Set `TOKENCRUMB_CONFIG_DIR` for another configuration directory and `TOKENCRUMB_AUDIENCE` for the deployment audience. The listener is published only on host loopback; configure ingress deliberately for remote clients. The configuration mount is read-only and persistent state uses a named volume. Provision permissions before startup; do not make private keys world-readable.

## Persistent state and recovery

Retain the budget file, its lock, the nonce database, audit log and audit lock on durable local storage. The default nonce path is `<budget-state>.nonces.db`. Restoring an old budget or nonce snapshot can re-enable operations or replay: treat state rollback as a security event, not a routine deployment shortcut.

Use one replica by default. Local workers require shared persistent paths and compatible locking; multiple hosts and distributed state coordination are not provided. Never deploy independent replicas with separate counters and claim a global budget.

Retain signed audit checkpoints independently. Back up keys and state with access controls appropriate to their contents. Keep capability contents and upstream secrets out of ordinary diagnostics.

## Updates

Use a tested commit or immutable container digest. Validate configuration before replacing it with `policy-install`. Test authority and audit key rotation using the explicit previous-key options before removing an old trust anchor. Restart for changes to upstream topology or certificates.

CI builds and tests images without publishing them. Repository or package visibility changes are separate administrative actions.
