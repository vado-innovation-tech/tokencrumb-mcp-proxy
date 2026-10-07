# Temporary custom Biscuit dependency

TokenCrumb currently uses **`biscuit-auth` 6.0.0-tokencrumb.1**, a custom build of the official 6.0.0 crate included in [vendor/biscuit-auth](../vendor/biscuit-auth/README.md). This is a temporary workaround, not an official Biscuit release or a separately maintained implementation.

## Why it exists

The official crate enables `datalog-macro` by default. That feature pulls in `biscuit-quote`, which depends on the unmaintained `proc-macro-error2` ([RUSTSEC-2026-0173](https://rustsec.org/advisories/RUSTSEC-2026-0173.html)). TokenCrumb builds its Datalog rules at runtime and does not need these compile-time macros.

Disabling the feature in upstream 6.0.0 fails to compile: five modules import `ToAnyParam` even though the trait is feature-gated. Our patch applies the same gate to those five imports and gates one related `PublicKey` import to avoid an unused-import warning. Cryptographic operations, signatures, token formats, Datalog evaluation and authorization logic are unchanged.

TokenCrumb uses `default-features = false` with `regex-full` and `pem` enabled, preserving the other previous default features. Neither `biscuit-quote` nor `proc-macro-error2` is present in the project lockfile.

## Provenance and validation

The source comes from the published `biscuit-auth` 6.0.0 crate, corresponding to upstream commit `0f0b4e0e6fe07220c1ba6b51bff21d450d94a975`. The [provenance manifest](../vendor/biscuit-auth/UPSTREAM.json) records the archive checksum and original/custom SHA-256 hashes for every retained file. The [patch](../vendor/biscuit-auth/tokencrumb.patch) records every change to retained upstream files, including the build-only manifest adjustments. The original Apache-2.0 license and source attribution are preserved.

CI runs `python3 tools/check_vendor.py` to verify the vendored files, the selected custom dependency and the absence of the two macro packages from the lockfile. Existing security, reference-fixture, issuer interoperability and HTTP/HTTPS checks exercise TokenCrumb against this custom build.

`cargo audit` skips local dependencies. Therefore `python3 tools/audit_dependencies.py` audits both the real lockfile and a temporary copy that identifies Biscuit by its original official version and registry checksum. This ensures advisories against upstream 6.0.0 remain visible while we use the local patch; the build still uses the custom source. No advisory is suppressed.

The snapshot contains upstream build inputs, not its standalone examples, test harness or benchmarks. Its custom version and `publish = false` make its status explicit. Build and install from the full repository checkout, or use the Dockerfile; registry publication of TokenCrumb is disabled while this local dependency is required. A source archive must contain `vendor/` alongside the workspace manifests and lockfile.

## Return to the official release

**Replace this custom dependency as soon as an official release fixes the feature-gating issue and passes validation.** A new version number alone is not sufficient: it must build with `datalog-macro` disabled and retain protocol compatibility.

When that release is available:

1. Replace the local `biscuit-auth` entry in the root manifest with an exact official registry version, keeping `default-features = false` and the required `regex-full` and `pem` features. Update `Cargo.lock` and confirm the macro packages remain absent.
2. Run the complete [development checks](development.md), including independent compatibility fixtures, issuer interoperability, HTTP/HTTPS smoke checks, supported Rust versions and dependency auditing. Review upstream behavior changes before accepting them.
3. Remove `vendor/biscuit-auth`, its workspace exclusion, the vendor verification script/CI step, and vendor-specific Docker copy/ignore entries. Replace the custom dependency audit script with a direct `cargo audit` check. Remove the temporary publication restriction once registry packaging succeeds again.
4. Update the README, package README, changelog and this page to record the official version and removal of the workaround.

Maintainers should check [upstream releases](https://github.com/eclipse-biscuit/biscuit-rust/releases) during dependency updates. The switch requires a reviewed dependency update; builds do not automatically follow upstream releases.
