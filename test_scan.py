"""Exercise the command with inert files and a disposable local Git repository."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCANNER = Path(__file__).with_name("scan.py")
"""Scanner entry point; always run it with the isolated system Python."""


class ScanTest(unittest.TestCase):
    """Check findings, coverage status, and the no-execution boundary at the CLI."""

    def setUp(self) -> None:
        """Allocate a fresh scope outside the real host scan."""
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / "account"
        self.root.mkdir()

    def scan(self, *flags: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        """Check fixture files without inspecting real socket or process state."""
        return subprocess.run(["/usr/bin/python3", "-I", str(SCANNER), "--no-live", *flags, self.root],
                              env=env, capture_output=True, text=True, timeout=20)

    def git(self, *args: str) -> None:
        """Write only the disposable fixture repository, ignoring user or system Git config."""
        subprocess.run(["/usr/bin/git", "-c", "user.name=Test", "-c", "user.email=test@example.test",
                        "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", *args],
                       cwd=self.root, env={"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"},
                       check=True, capture_output=True, timeout=10)

    def test_clean_files_and_lookalike_package_names_do_not_trigger(self) -> None:
        """Reject lookalike scoped and suffixed packages, test output status end to end."""
        (self.root / "package.json").write_text('{"dependencies":{"@other/cdeops":"1","cdeops-extra":"2"}}')
        result = self.scan()
        self.assertEqual(result.returncode, 0, result)

    def test_content_cache_and_persistence_hits_report_paths_without_contents(self) -> None:
        """Detect code, a scoped cache name, and a dangling known drop without running or echoing them."""
        source = self.root / "postcss.config.mjs"
        source.write_text("// fixture-private-value " + "Cot%3t=" + "shtP\n")
        index = self.root / ".npm/_cacache/index-v5/ab/cd/entry"
        index.parent.mkdir(parents=True)
        index.write_text('{"key":"https://registry.npmjs.org/@adminide-stack%2fclient-redux"}')
        drop = self.root / ".node_modules/.npm-ws.pid"
        drop.parent.mkdir()
        drop.symlink_to("missing")
        result = self.scan()
        self.assertEqual(result.returncode, 1, result)
        for path in (source, index, drop):
            self.assertIn(str(path), result.stdout)
        self.assertNotIn("fixture-private-value", result.stdout + result.stderr)

    def test_missing_root_sets_incomplete_bit_without_hiding_findings(self) -> None:
        """An unavailable root cannot be mistaken for absence of matching files."""
        missing = str(self.root / "missing")
        result = self.scan(missing)
        self.assertEqual(result.returncode, 2, result)
        (self.root / "package.json").write_text('{"dependencies":{"cdeops":"13.5.31"}}')
        result = self.scan(missing)
        self.assertEqual(result.returncode, 3, result)
        self.assertIn("REVIEW dependency", result.stdout)

    def test_history_finds_reflog_only_blob_without_running_fsmonitor(self) -> None:
        """Find a marker after its branch moves while ignoring inherited metadata and repo commands."""
        self.git("init", "--initial-branch=main", "--template=")
        source = self.root / "postcss.config.mjs"
        source.write_text("// clean\n")
        self.git("add", source.name)
        self.git("commit", "-m", "clean")
        source.write_text("// fixture " + "rmcej%" + "otb%\n")
        self.git("add", source.name)
        self.git("commit", "-m", "inert indicator")
        self.git("update-ref", "-m", "fixture branch move", "refs/heads/main", "HEAD^")
        source.write_text("// clean\n")

        # If Git executes the configured monitor, it leaves a file in the fixture.
        stamp = self.root / "executed"
        monitor = self.root / "monitor.sh"
        monitor.write_text(f"#!/bin/sh\ntouch '{stamp}'\n")
        monitor.chmod(0o700)
        self.git("config", "core.fsmonitor", str(monitor))
        result = self.scan("--history", env={**os.environ, "GIT_DIR": str(self.root / "wrong")})
        self.assertEqual(result.returncode, 1, result)
        self.assertIn("GIT CONTENT INDICATOR", result.stdout)
        self.assertIn(source.name, result.stdout)
        self.assertFalse(stamp.exists())


if __name__ == "__main__":
    unittest.main()
