# Architecture decisions

The following decisions describe the maintained design.

1. **Authority-only identities.** Agent keys, audience and issuer identity come from the signed authority block. Attenuation may restrict access but cannot create a new trusted identity.
2. **Delegation complements upstream authorization.** The proxy bounds a capability; it does not reproduce an upstream application's entitlement model.
3. **One endpoint per upstream.** Separate sessions and routes preserve upstream identity. Budgets and audit state remain shared within the proxy configuration.
4. **Audience and route are separate.** The audience names the deployment. An upstream check restricts a capability to a route within that deployment.
5. **Two-level budgets.** Root capability and tool counters prevent a low-volume tool from inheriting a different tool's budget and prevent attenuation from resetting spending.
6. **Typed signed metadata.** Expiry, identity and bounds use explicit governed fields. Runtime context is supplied by the verifier and cannot be asserted by a token.
7. **Fail closed with durable state.** Invalid configuration, exhausted execution limits and unverifiable state must not silently weaken enforcement. Budget and nonce state survive restarts.
8. **Stable signed protocol identifiers.** Product naming is independent of the signature domains documented in compatibility.md. Changing the latter requires an explicit migration.

See [architecture](../architecture.md), [security model](../security-model.md) and [compatibility](../compatibility.md) for implementation details and limits.
