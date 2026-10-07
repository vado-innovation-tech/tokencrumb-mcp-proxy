#!/usr/bin/env python3
"""Verify the temporary Biscuit snapshot and its selected dependency settings."""
import hashlib
import json
from pathlib import Path
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]
VENDOR = ROOT / "vendor/biscuit-auth"
manifest = json.loads((VENDOR / "UPSTREAM.json").read_text())
errors = []
files = manifest["files"]
expected = set(files) | {"README.md", "UPSTREAM.json", "tokencrumb.patch"}
actual = {p.relative_to(VENDOR).as_posix() for p in VENDOR.rglob("*") if p.is_file()}
if actual != expected:
    errors.append(f"Unexpected vendor file set: {sorted(actual ^ expected)}")
for name, checksums in files.items():
    path = VENDOR / name
    if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != checksums["vendored_sha256"]:
        errors.append(f"Vendored source differs from the reviewed snapshot: {name}")
if hashlib.sha256((VENDOR / "tokencrumb.patch").read_bytes()).hexdigest() != manifest["patch_sha256"]:
    errors.append("The recorded upstream patch has changed")

workspace = tomllib.loads((ROOT / "Cargo.toml").read_text())
dependency = workspace["workspace"]["dependencies"]["biscuit-auth"]
if dependency != {
    "version": "=" + manifest["custom_version"],
    "path": "vendor/biscuit-auth",
    "default-features": False,
    "features": ["regex-full", "pem"],
}:
    errors.append("Unexpected Biscuit source, version or feature selection")
packages = tomllib.loads((ROOT / "Cargo.lock").read_text())["package"]
for package in packages:
    if package["name"] in {"biscuit-quote", "proc-macro-error2"}:
        errors.append(f"Unneeded macro dependency in Cargo.lock: {package['name']}")
biscuit = [p for p in packages if p["name"] == "biscuit-auth"]
if len(biscuit) != 1 or biscuit[0]["version"] != manifest["custom_version"] or "source" in biscuit[0]:
    errors.append("Cargo.lock must select exactly the local custom Biscuit version")
if errors:
    print("\n".join(errors), file=sys.stderr)
    sys.exit(1)
print(f"Verified {len(files)} vendored files; custom Biscuit selected; macro dependencies absent")
