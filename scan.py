#!/usr/bin/python3 -I
"""Look for local PolinRider indicators without executing or changing scanned content."""

import argparse
import fnmatch
import ipaddress
import os
from pathlib import Path
import re
import subprocess
import tomllib
from dataclasses import dataclass
from datetime import date


# Never source a target's ignore settings, shell config, or executable search path.
MAX_BYTES = 25_000_000
"""Maximum size of a file or Git blob searched for content."""
CONTENT = (
    "*.js", "*.cjs", "*.mjs", "*.ts", "*.jsx", "*.tsx", "*.php", "*.woff", "*.woff2",
    "*.sh", "*.service", "*.desktop", "*.timer", "*config*.json", "tasks.json", "*rc", "*profile",
)
"""Working-tree and installed-code file names relevant to current signatures."""
DEPENDENCIES = (
    "package.json", "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock",
    "bun.lock", "bun.lockb", "composer.json", "composer.lock", "go.mod", "go.sum", "*-index.json",
)
"""Dependency manifests, lockfiles, and pnpm index file names."""
HISTORY_CONTENT = (
    "*config*.js", "*config*.cjs", "*config*.mjs", "*config*.ts", "*config*.json", "*.woff", "*.woff2",
    "tasks.json", "cli.js", "temp_auto_push.bat",
)
"""Narrow history scope for Git configuration, IDE tasks, fonts, and propagation artifacts."""
PRUNE_HISTORY = {"node_modules", ".cache", ".bun", ".npm", ".local", ".rustup", ".gradle"}
"""Generated or package trees not searched for nested Git repositories."""


@dataclass(frozen=True)
class Rules:
    """Local signatures, dependency candidates, and host indicators for one reviewed snapshot."""

    reviewed: date
    content: str
    packages: str
    paths: tuple[Path, ...]
    ips: frozenset[str]

    @classmethod
    def load(cls, path: Path) -> "Rules":
        """Read local data and reject invalid or empty rule categories before scanning."""
        with path.open("rb") as source:
            raw = tomllib.load(source)

        def strings(key: str) -> list[str]:
            """Require a nonempty list of single-line expressions or literals."""
            values = raw.get(key)
            if not isinstance(values, list) or not values or any(
                not isinstance(value, str) or not value.strip() or "\n" in value for value in values
            ):
                raise ValueError(f"invalid indicator category: {key}")
            return values

        # Match names at package boundaries, including npm's encoded scope separator in cache URLs.
        names = [re.escape(name).replace("/", "(?:/|%2f)") for name in strings("package_names")]
        prefix = r"(^|[^a-z0-9_@./-]|node_modules/|registry\.npmjs\.org/)"
        packages = prefix + "(?:" + "|".join(names) + r")($|[^a-z0-9_./-])"
        literals = map(re.escape, strings("content_literals"))
        content = "|".join([*literals, *strings("content_patterns")])
        re.compile(content.encode(), re.IGNORECASE)

        # Persistence rules name only paths under a scanned root, never arbitrary host paths.
        paths = tuple(Path(value) for value in strings("persistence_paths"))
        if any(path.is_absolute() or ".." in path.parts or not path.parts for path in paths):
            raise ValueError("persistence indicators must be relative to a scan root")
        ips = frozenset(str(ipaddress.ip_address(value)) for value in strings("network_ips"))
        reviewed = raw.get("reviewed")
        if type(reviewed) is not date:
            raise ValueError("reviewed must be a TOML date")
        return cls(reviewed, content, packages, paths, ips)


@dataclass
class Report:
    """Track findings independently from failures or inaccessible scope."""

    findings: int = 0
    gaps: int = 0

    def hit(self, category: str, location: str | Path) -> None:
        """Report where to investigate without printing matching bytes or command arguments."""
        self.findings += 1
        print(f"{category}: {str(location)!r}", flush=True)

    def gap(self, message: str) -> None:
        """Make incomplete coverage visible without masking findings."""
        self.gaps += 1
        print(f"INCOMPLETE: {message}", flush=True)

    def finish(self) -> int:
        """Summarize coverage and return bit 0 for findings and bit 1 for gaps."""
        print(f"PolinRider: {self.findings} finding(s), {self.gaps} coverage issue(s)")
        return int(self.findings > 0) | (int(self.gaps > 0) << 1)


def scan_files(roots: list[Path], globs: tuple[str, ...], pattern: str, category: str, report: Report) -> None:
    """Search only named file types using system ripgrep, reporting paths and traversal errors."""
    # Keep package stores in scope, but skip Git objects, agent transcripts, and model blobs.
    selectors = [arg for glob in globs for arg in ("-g", glob)]
    exclusions = (
        "!**/.git/**", "!**/.pi/agent/sessions/**", "!**/.pi/agent/observatory/**",
        "!**/.codex/sessions/**", "!**/.claude/projects/**", "!**/.cache/huggingface/**",
    )
    selectors += [arg for glob in exclusions for arg in ("-g", glob)]
    command = ["/usr/bin/rg", "--no-config", "--hidden", "--no-ignore", "--one-file-system", "-a", "-i",
               "--files-with-matches", "--null", "--max-filesize", str(MAX_BYTES), *selectors, "-f", "-", "--", *roots]
    try:
        result = subprocess.run(command, input=(pattern + "\n").encode(), capture_output=True, timeout=120)
        output = result.stdout
    except subprocess.TimeoutExpired as error:
        report.gap(f"{category}: file search timed out")
        output = error.stdout or b""
        result = None
    except OSError as error:
        report.gap(f"{category}: cannot start ripgrep: {error.strerror}")
        return

    # Keep complete paths even on errors; discard a possible partial path from a killed process.
    for filename in output.split(b"\0")[:-1]:
        if filename:
            report.hit(category, os.fsdecode(filename))
    if result is not None and (result.returncode not in (0, 1) or result.stderr):
        diagnostics = result.stderr.splitlines()
        first = os.fsdecode(diagnostics[0]) if diagnostics else "no diagnostic"
        report.gap(f"{category}: ripgrep exit {result.returncode}, {len(diagnostics)} diagnostics, first: {first!r}")


def scan_persistence(roots: list[Path], rules: Rules, report: Report) -> None:
    """Check expected drop locations under each root, including dangling artifact symlinks."""
    for root in roots:
        for relative in rules.paths:
            path = root / relative
            try:
                # A redirect of the drop directory is itself worth inspecting, without following it.
                if any((root / part).is_symlink() for part in relative.parents if part != Path(".")):
                    report.gap(f"indirect persistence path: {str(path)!r}")
                    continue
                path.lstat()
            except FileNotFoundError:
                continue
            except OSError as error:
                report.gap(f"cannot inspect {str(path)!r}: {error.strerror}")
            else:
                report.hit("PERSISTENCE INDICATOR", path)


def scan_live(rules: Rules, report: Report) -> None:
    """Check numeric peer addresses and interactive Node processes without contacting peers."""
    sockets = subprocess.run(["/usr/bin/ss", "-H", "-tuna"], capture_output=True, text=True, timeout=10)
    if sockets.returncode or sockets.stderr:
        report.gap(f"socket snapshot: ss exit {sockets.returncode}")
    peers = {line.split()[5].rsplit(":", 1)[0].strip("[]") for line in sockets.stdout.splitlines() if len(line.split()) >= 6}
    for peer in sorted(peers & rules.ips):
        report.hit("KNOWN PEER IP", peer)

    # A detached interactive Node process is a review signal, not proof by itself.
    denied = 0
    for process in Path("/proc").glob("[0-9]*"):
        try:
            if (process / "comm").read_bytes().strip() not in (b"node", b"nodejs"):
                continue
            arguments = (process / "cmdline").read_bytes().split(b"\0")
        except (FileNotFoundError, ProcessLookupError):
            continue  # A process may exit between reading its name and arguments.
        except PermissionError:
            denied += 1
            continue
        if b"-i" in arguments[1:] or b"--interactive" in arguments[1:]:
            report.hit("REVIEW interactive Node PID", process.name)
    if denied:
        report.gap(f"{denied} process records were unreadable")


def read_history(gitdir: Path, rules: Rules, report: Report) -> None:
    """Inspect candidate blobs reachable from local refs and reflogs without filters or fetches."""
    # Inherited Git overrides must not redirect reads, relax protocol restrictions, or load hooks.
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null", GIT_ALLOW_PROTOCOL="",
               GIT_NO_LAZY_FETCH="1", GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0")
    git = ["/usr/bin/git", "--no-pager", "--no-replace-objects", f"--git-dir={gitdir}",
           "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null"]
    pathspecs = [f":(glob)**/{glob}" for glob in (*HISTORY_CONTENT, *DEPENDENCIES)]
    # Do not simplify away merged history that a path-limited traversal would otherwise hide.
    walk = subprocess.run([*git, "rev-list", "--objects", f"--filter=blob:limit={MAX_BYTES + 1}", "--full-history",
                           "--all", "--reflog", "--", *pathspecs],
                          env=env, capture_output=True, timeout=120)
    if walk.returncode or walk.stderr:
        report.gap(f"cannot enumerate Git objects in {str(gitdir.parent)!r} (exit {walk.returncode})")
        return

    content = re.compile(rules.content.encode(), re.IGNORECASE)
    packages = re.compile(rules.packages.encode(), re.IGNORECASE)
    # cat-file --batch returns raw blobs. Pass only full object IDs, never path or filter commands.
    with subprocess.Popen([*git, "cat-file", "--batch"], env=env, stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as reader:
        assert reader.stdin is not None and reader.stdout is not None
        for row in walk.stdout.splitlines():
            oid, _, path = row.partition(b" ")
            name = os.fsdecode(path.rsplit(b"/", 1)[-1])
            dependency = any(fnmatch.fnmatchcase(name, glob) for glob in DEPENDENCIES)
            source = any(fnmatch.fnmatchcase(name, glob) for glob in HISTORY_CONTENT)
            if not (source or dependency) or not re.fullmatch(rb"(?:[a-f0-9]{40}|[a-f0-9]{64})", oid):
                continue
            reader.stdin.write(oid + b"\n")
            reader.stdin.flush()
            header = reader.stdout.readline().split()
            if len(header) != 3:
                report.gap(f"missing Git object {oid.decode()} in {str(gitdir.parent)!r}")
                if not header:
                    break
                continue
            size = int(header[2])
            if size > MAX_BYTES:
                # Stop consuming data if the supposedly size-filtered walk returns a larger object.
                reader.terminate()
                report.gap(f"unexpected oversized Git object {oid.decode()} in {str(gitdir.parent)!r}")
                break
            blob = reader.stdout.read(size + 1)
            if len(blob) != size + 1:
                raise OSError("truncated Git object")
            if header[1] != b"blob":
                continue
            location = f"{gitdir.parent}:{os.fsdecode(path)}@{oid.decode()[:12]}"
            if source and (name == "temp_auto_push.bat" or content.search(blob)):
                report.hit("GIT CONTENT INDICATOR", location)
            if dependency and packages.search(blob):
                report.hit("REVIEW Git dependency", location)
        reader.stdin.close()
        if reader.wait(timeout=10):
            report.gap(f"Git blob read failed in {str(gitdir.parent)!r}")


def scan_history(roots: list[Path], rules: Rules, report: Report) -> None:
    """Discover ordinary local checkouts, skipping Git pointers and generated package trees."""
    for root in roots:
        def inaccessible(error: OSError) -> None:
            """Surface worktree discovery errors without printing arbitrary file contents."""
            report.gap(f"cannot enumerate Git worktrees under {str(error.filename)!r}: {error.strerror}")

        device = root.stat().st_dev
        for path, dirs, files in os.walk(root, onerror=inaccessible):
            parent = Path(path)
            if parent.stat().st_dev != device:
                dirs.clear()
                continue
            gitdir = parent / ".git"
            if ".git" in files or (".git" in dirs and (gitdir.is_symlink() or (gitdir / "commondir").exists())):
                report.gap(f"skipped indirect Git metadata at {str(gitdir)!r}")
            elif ".git" in dirs:
                try:
                    read_history(gitdir, rules, report)
                except (OSError, subprocess.TimeoutExpired) as error:
                    report.gap(f"Git history read failed in {str(parent)!r}: {type(error).__name__}")
            dirs[:] = [name for name in dirs if name != ".git" and name not in PRUNE_HISTORY]


def main() -> int:
    """Run each independent check and keep going if one scope cannot be inspected."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("roots", nargs="*", type=Path, metavar="ROOT", help="directories to inspect (default: home)")
    parser.add_argument("--history", action="store_true", help="scan Git refs and reflogs in trusted local checkouts")
    parser.add_argument("--no-live", action="store_true", help="skip process and socket snapshots")
    args = parser.parse_args()
    report = Report()

    # Never report an all-clear on missing rules or a mistyped root.
    try:
        rules = Rules.load(Path(__file__).with_name("indicators.toml"))
    except (OSError, ValueError, re.error) as error:
        report.gap(f"cannot load indicator snapshot: {error}")
        return report.finish()
    roots = []
    for path in args.roots or [Path.home()]:
        try:
            root = path.expanduser().resolve(strict=True)
            if not root.is_dir():
                raise NotADirectoryError(root)
        except (OSError, RuntimeError):
            report.gap(f"unavailable scan root: {str(path)!r}")
        else:
            if root not in roots:
                roots.append(root)

    print(f"Indicator snapshot: {rules.reviewed}. File roots: {', '.join(repr(str(root)) for root in roots)}", flush=True)
    if roots:
        scan_files(roots, CONTENT, rules.content, "CONTENT INDICATOR", report)
        scan_files(roots, (*DEPENDENCIES, "**/.npm/_cacache/index-v5/**"), rules.packages, "REVIEW dependency", report)
    scan_persistence(roots, rules, report)
    if not args.no_live:
        try:
            scan_live(rules, report)
        except (OSError, subprocess.TimeoutExpired) as error:
            report.gap(f"live snapshot failed: {type(error).__name__}")
    if args.history:
        try:
            scan_history(roots, rules, report)
        except OSError as error:
            report.gap(f"Git discovery failed: {error.strerror}")
    return report.finish()


if __name__ == "__main__":
    raise SystemExit(main())
