#!/usr/bin/env python3
"""Fetch source dependencies for a standalone checkout.

The grpc-mojo family is developed as sibling repositories (mojo-net,
protomojo, mojo-http2, grpc-mojo). Until the packages are published to a
conda channel, dependents consume them as *source* dependencies: this
script clones each dependency listed in deps.json into the directory the
manifest names (the umbrella uses packages/<name>, matching the historical
monorepo layout, so every include path keeps working; mojo-http2 uses
.deps/<name>).

Already-present directories are left untouched — a monorepo-style checkout
or a developer's own clone always wins over a fresh fetch. Use --update to
move previously fetched clones to their pinned ref.

URL selection: $GIT_URL_TEMPLATE (default
"https://github.com/nsalerni/{name}.git", which works anonymously for
public repos). CI on private repos overrides with per-dependency SSH host
aliases, e.g. GIT_URL_TEMPLATE="git@github.com-{name}:nsalerni/{name}.git"
with matching ~/.ssh/config entries carrying read-only deploy keys.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TEMPLATE = "https://github.com/nsalerni/{name}.git"


def remote_ref_type(dest: Path, ref: str) -> str:
    tag_ref = f"refs/tags/{ref}"
    branch_ref = f"refs/heads/{ref}"
    result = subprocess.run(
        [
            "git",
            "-C",
            str(dest),
            "ls-remote",
            "--exit-code",
            "--refs",
            "origin",
            tag_ref,
            branch_ref,
        ],
        stdout=subprocess.PIPE,
        text=True,
    )
    if result.returncode not in (0, 2):
        result.check_returncode()
    remote_refs = {
        line.split(maxsplit=1)[1] for line in result.stdout.splitlines() if line.strip()
    }
    if tag_ref in remote_refs:
        return "tag"
    if branch_ref in remote_refs:
        return "branch"
    raise ValueError(f"origin has no exact tag or branch named '{ref}'")


def update_clone(dest: Path, ref: str) -> None:
    ref_type = remote_ref_type(dest, ref)
    if ref_type == "tag":
        tag_ref = f"refs/tags/{ref}"
        subprocess.run(
            [
                "git",
                "-C",
                str(dest),
                "fetch",
                "--depth",
                "1",
                "origin",
                f"{tag_ref}:{tag_ref}",
            ],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(dest), "checkout", "--detach", ref],
            check=True,
        )
        return

    remote_branch = f"refs/remotes/origin/{ref}"
    subprocess.run(
        [
            "git",
            "-C",
            str(dest),
            "fetch",
            "--depth",
            "1",
            "origin",
            f"+refs/heads/{ref}:{remote_branch}",
        ],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(dest), "checkout", "-B", ref, f"origin/{ref}"],
        check=True,
    )


def main() -> int:
    manifest = ROOT / "deps.json"
    if not manifest.exists():
        print("no deps.json: nothing to fetch")
        return 0
    spec = json.loads(manifest.read_text())
    template = os.environ.get("GIT_URL_TEMPLATE", DEFAULT_TEMPLATE)
    update = "--update" in sys.argv[1:]
    dest_root = ROOT / spec.get("dir", "packages")
    dest_root.mkdir(exist_ok=True)

    for name, dep in spec["deps"].items():
        dest = dest_root / name
        ref = dep.get("ref", "main")
        if dest.exists():
            if not update:
                print(f"  {name}: already present at {dest} (skipped)")
                continue
            try:
                update_clone(dest, ref)
            except ValueError as error:
                print(f"  {name}: {error}", file=sys.stderr)
                return 1
            print(f"  {name}: updated to {ref}")
            continue
        url = dep.get("url") or template.format(name=name)
        print(f"  {name}: cloning {url} @ {ref}")
        subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", ref, url, str(dest)],
            check=True,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
