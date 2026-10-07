# Configuration

The proxy loads a YAML policy and rejects unknown fields, duplicate mapping keys and inconsistent tool definitions. Start from [policy.yaml](../policy.yaml); do not copy a policy without matching it to your upstream's actual behavior.

## Profiles and enforcement

| Setting | Behavior |
| --- | --- |
| `mode: enforce` | Refuse calls that fail authorization. |
| `mode: warn-only` | Record authorization failures while permitting otherwise dispatchable calls; unsuitable as a security boundary. |
| `min_profile: native` | Permit bearer capabilities where tool requirements allow them. |
| `min_profile: registry_backed` | Require agent call signatures with keys resolved through a trusted signed registry. |
| `min_profile: hardened_biscuit_anchored` | Require agent call signatures with the key anchored in the capability's authority block. |

The supplied policy uses `enforce` and `hardened_biscuit_anchored`. A token's own required profile cannot be downgraded by the caller. CLI `--mode` and `--min-profile` override the file and are reflected in the effective policy digest.

## Tools and facts

Each tool defines `name`, `operation`, optional `resource.from`, `allow` constraints, and `require` proofs. `resource.from: arguments.path` projects a call argument into the resource checked by Datalog. Resource prefixes are canonicalized with path-boundary checks. Mapping a field does not establish its business meaning or resolve the upstream's symlinks.

The proxy injects trusted call context such as `tool`, `operation`, `resource`, `upstream`, `arg`, `budget` and verified proof facts. Capabilities cannot declare those trusted context facts themselves. To bind a scalar argument to signed authority facts:

```yaml
tools:
  - name: get_record
    operation: read
    args:
      - from: arguments.record_id
        as: record_id
```

Issue the corresponding right with `forge --fact 'assigned_record("R-1")' --scope-arg record_id=assigned_record`. Every resource in a multi-resource call must satisfy authorization.

## Budgets and expiry

`allow.budget` bounds each tool. `budget_total` optionally adds a policy-wide ceiling per root capability. Signed `budget_cap` facts narrow the capability budget; the tightest applicable limit wins. Attenuation descendants share the root budget identity.

`max_ttl` bounds the remaining signed lifetime. `clock_skew_seconds` and `serve --freshness` control timestamp acceptance. Expiry, audience and governed identity facts are checked independently of arbitrary token Datalog.

The `limits` section bounds token size, Datalog facts, iterations and execution time. Tune these against real policies and retain adversarial tests; disabling limits is not supported.

## Multiple upstreams

```yaml
mode: enforce
min_profile: hardened_biscuit_anchored
upstreams:
  catalog: https://catalog.example.com/mcp
  inventory: https://inventory.example.com/mcp
tools:
  - name: search_records
    upstream: catalog
    operation: read
  - name: get_stock
    upstream: inventory
    operation: read
```

These are served at `/mcp/catalog` and `/mcp/inventory`. Do not pass `--upstream` when the policy declares `upstreams`. With multiple upstreams each tool needs an explicit target. `upstream_tool` can map a public tool name to a different upstream name; authorization and call signatures use the public name.

An audience identifies the deployment; an upstream restriction identifies a route within it. They are distinct checks. Sessions remain scoped to their endpoint; budgets and audit state are shared.

## Upstream credentials

Use environment references, not secret values on the command line:

```sh
tokencrumb serve --help
# Add to your serve invocation:
# --upstream-header catalog:X-API-Key=CATALOG_API_KEY
```

For identity-bound forwarding, `--upstream-user-credentials` accepts a JSON array:

```json
[{"upstream":"catalog","issuer":"https://issuer.example.com","subject":"reader","header":"Authorization","env":"CATALOG_READER_AUTH"}]
```

The environment variable holds the complete header value. The proxy selects it only for the verified issuer and subject. It does not turn delegation into upstream entitlement or automatically exchange upstream credentials.

## Reload and revocation

Enable `--reload-policy` and publish validated updates atomically:

```sh
tokencrumb policy-install next-policy.yaml policy.yaml
```

Invalid updates do not replace the active policy. Upstream topology stays fixed until restart. Configure `revocation: /path/to/revoked.list` for a signed revocation list; `--revocation-pub` selects a separate signer when required. Use the [CLI](cli.md) to create and update the list.
