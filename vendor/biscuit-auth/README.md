# Custom Biscuit build for TokenCrumb

This is **TokenCrumb's temporary custom version of `biscuit-auth`**, identified as `6.0.0-tokencrumb.1`. It is based on the official `biscuit-auth` 6.0.0 crate; it is not an official upstream release.

TokenCrumb disables the optional Datalog macros to avoid the unmaintained `proc-macro-error2` build dependency (RUSTSEC-2026-0173). Upstream 6.0.0 fails to compile in that configuration because five imports reference a macro-only trait unconditionally. Our source patch gates those imports and one related public-key import. It does not change cryptography, token formats, parsing or authorization logic.

This directory is a build-only snapshot: upstream `src/`, `build.rs` and `LICENSE` are retained. The manifest has a custom version, disables publication, and omits development dependencies and targets whose examples, tests, benchmarks and samples are not included. Upstream copyright and license notices are preserved. Inline upstream tests remain in the source, but this snapshot is validated through TokenCrumb's tests rather than the upstream test harness. The original upstream README is replaced by this notice.

- [Upstream source](https://github.com/eclipse-biscuit/biscuit-rust/tree/0f0b4e0e6fe07220c1ba6b51bff21d450d94a975/biscuit-auth)
- [Published source archive](https://static.crates.io/crates/biscuit-auth/biscuit-auth-6.0.0.crate)
- [Provenance and SHA-256 checksums](UPSTREAM.json)
- [Complete changes to retained upstream files](tokencrumb.patch)
- [Apache-2.0 license](LICENSE)
- [Maintenance and return to upstream](../../docs/biscuit-auth.md)

**Return to the official crate as soon as an upstream release fixes compilation with `datalog-macro` disabled and passes TokenCrumb's compatibility and security checks.** This custom version is a temporary workaround, not a separate Biscuit implementation.
