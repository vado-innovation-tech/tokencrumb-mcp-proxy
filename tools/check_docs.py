#!/usr/bin/env python3
"""Check local Markdown links without external services or dependencies."""
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
paths = subprocess.check_output(
    ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=ROOT
).decode().split("\0")
errors = []
count = 0
for name in sorted(set(paths)):
    path = ROOT / name
    if path.suffix != ".md" or not path.is_file():
        continue
    count += 1
    source = re.sub(r"```[^\n]*\n.*?```", "", path.read_text(), flags=re.S)
    for target in re.findall(r"\[[^\]]*\]\(([^\s)]+)(?:\s+[^)]*)?\)", source):
        parts = urlsplit(target.strip("<>"))
        if parts.scheme or parts.netloc:
            continue
        destination = path.parent / unquote(parts.path) if parts.path else path
        if not destination.exists():
            errors.append(f"{name}: missing {target}")
        elif parts.fragment and destination.suffix == ".md":
            headings = re.findall(r"^#{1,6}\s+(.+?)\s*#*\s*$", destination.read_text(), re.M)
            anchors = {re.sub(r"[^\w\s-]", "", h.lower()).replace(" ", "-") for h in headings}
            if unquote(parts.fragment) not in anchors:
                errors.append(f"{name}: missing heading {target}")
if errors:
    print("\n".join(errors), file=sys.stderr)
    sys.exit(1)
print(f"Checked local links in {count} Markdown files")
