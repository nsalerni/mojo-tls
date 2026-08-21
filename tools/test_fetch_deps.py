#!/usr/bin/env python3
"""Local regression tests for dependency fetching."""

import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

TOOLS_DIR = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("fetch_deps", TOOLS_DIR / "fetch_deps.py")
assert SPEC is not None and SPEC.loader is not None
fetch_deps = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fetch_deps)


def git(*args: str, cwd: Path | None = None) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


class FetchDepsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp = Path(self.temp_dir.name)
        self.remote = self.temp / "remote.git"
        self.source = self.temp / "source"
        self.workspace = self.temp / "workspace"
        self.workspace.mkdir()

        git("init", "--bare", str(self.remote))
        git("init", str(self.source))
        git("config", "user.name", "Test Author", cwd=self.source)
        git("config", "user.email", "test@example.com", cwd=self.source)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def commit(self, value: str, message: str, tag: str | None = None) -> None:
        (self.source / "value.txt").write_text(f"{value}\n")
        git("add", "value.txt", cwd=self.source)
        git("commit", "-m", message, cwd=self.source)
        if tag is not None:
            git("tag", "-a", tag, "-m", tag, cwd=self.source)
        git("push", str(self.remote), "HEAD:main", "--tags", cwd=self.source)

    def write_manifest(self, ref: str) -> None:
        manifest = {
            "dir": ".deps",
            "deps": {
                "example": {
                    "url": self.remote.as_uri(),
                    "ref": ref,
                }
            },
        }
        (self.workspace / "deps.json").write_text(json.dumps(manifest))

    def fetch(self, update: bool = False) -> int:
        argv = ["fetch_deps.py", "--update"] if update else ["fetch_deps.py"]
        with patch.object(fetch_deps, "ROOT", self.workspace), patch.object(
            sys, "argv", argv
        ):
            return fetch_deps.main()

    def assert_shallow(self, clone: Path) -> None:
        self.assertEqual(git("rev-parse", "--is-shallow-repository", cwd=clone), "true")

    def test_update_fetches_new_tag_into_shallow_clone(self) -> None:
        self.commit("one", "first", "v0.1.0")
        self.write_manifest("v0.1.0")
        self.assertEqual(self.fetch(), 0)

        clone = self.workspace / ".deps" / "example"
        self.assert_shallow(clone)
        self.commit("two", "second", "v0.2.0")
        self.write_manifest("v0.2.0")
        self.assertEqual(self.fetch(update=True), 0)

        self.assertEqual(git("describe", "--tags", "--exact-match", cwd=clone), "v0.2.0")
        self.assertEqual(
            git("rev-parse", "HEAD", cwd=clone),
            git("rev-parse", "v0.2.0^{commit}", cwd=self.source),
        )
        self.assert_shallow(clone)

    def test_update_advances_branch_in_shallow_clone(self) -> None:
        self.commit("one", "first")
        self.write_manifest("main")
        self.assertEqual(self.fetch(), 0)

        clone = self.workspace / ".deps" / "example"
        self.commit("two", "second")
        self.assertEqual(self.fetch(update=True), 0)

        self.assertEqual(git("branch", "--show-current", cwd=clone), "main")
        self.assertEqual(
            git("rev-parse", "HEAD", cwd=clone),
            git("rev-parse", "HEAD", cwd=self.source),
        )
        self.assert_shallow(clone)

    def test_update_rejects_unknown_ref(self) -> None:
        self.commit("one", "first", "v0.1.0")
        self.write_manifest("v0.1.0")
        self.assertEqual(self.fetch(), 0)

        clone = self.workspace / ".deps" / "example"
        original_head = git("rev-parse", "HEAD", cwd=clone)
        self.write_manifest("missing")
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            self.assertEqual(self.fetch(update=True), 1)

        self.assertIn(
            "origin has no exact tag or branch named 'missing'", stderr.getvalue()
        )
        self.assertEqual(git("rev-parse", "HEAD", cwd=clone), original_head)


if __name__ == "__main__":
    unittest.main()
