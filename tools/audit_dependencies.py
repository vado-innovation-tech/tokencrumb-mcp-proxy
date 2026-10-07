#!/usr/bin/env python3
"""Audit resolved dependencies and the upstream base of the local Biscuit patch."""
import json
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
subprocess.run(["python3", str(ROOT / "tools/check_vendor.py")], check=True)
subprocess.run(["cargo", "audit"], cwd=ROOT, check=True)

# cargo-audit skips local/path dependencies. Audit the same resolved graph with
# the custom package identified by its original registry version and checksum.
# This is an audit-only copy: the build lockfile and dependency selection stay put.
metadata = json.loads((ROOT / "vendor/biscuit-auth/UPSTREAM.json").read_text())
lockfile = (ROOT / "Cargo.lock").read_text()
custom = f'name = "biscuit-auth"\nversion = "{metadata["custom_version"]}"'
upstream = (
    f'name = "biscuit-auth"\nversion = "{metadata["upstream_version"]}"\n'
    'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
    f'checksum = "{metadata["archive_sha256"]}"'
)
lockfile, count = re.subn(re.escape(custom), lambda _: upstream, lockfile)
if count != 1:
    raise SystemExit("Expected exactly one custom Biscuit package to audit")
with tempfile.TemporaryDirectory(prefix="tokencrumb-upstream-audit-") as directory:
    path = Path(directory) / "Cargo.lock"
    path.write_text(lockfile)
    print(f'Auditing vendored Biscuit against upstream {metadata["upstream_version"]}', flush=True)
    subprocess.run(["cargo", "audit", "--no-fetch", "--file", str(path)], cwd=ROOT, check=True)
