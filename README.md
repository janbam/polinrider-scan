# PolinRider scan

From the repository directory, run on Linux as the account that develops or deploys code. Requires system Python 3.11+, ripgrep, and `ss`, plus Git for history. No network access, installs, or account changes during a scan.

```sh
./scan.py
```

By default it scans your home directory and checks current processes and socket peers. Positional directories replace the default. Use `--no-live` if you only want the filesystem checks.

```sh
./scan.py --history "$HOME"
```

`--history` reads selected config, IDE task, font, manifest, and lockfile blobs from local refs and reflogs. Use it only on trusted local checkouts. It doesn't fetch, check out, or follow Git metadata pointers. It doesn't scan bare repositories or discover checkouts inside generated package directories.

| Exit | Meaning |
| --- | --- |
| `0` | No matching indicators in the checked scope |
| `1` | Findings |
| `2` | Incomplete scan |
| `3` | Findings and incomplete scan |

The working-tree scan checks relevant source and config files, installed JS, dependency files, and a few known drop paths. It doesn't follow symlinks during traversal, cross mounted filesystems, unpack compressed archives, or search files over 25 MB. Add a mounted directory explicitly if needed. A package hit calls for comparing the installed version with the advisory and checking whether it ran. A loader or persistence hit calls for incident triage. The script prints locations, not matching bytes.

A clean run is not a forensic all-clear. The scanner doesn't inspect root-only data from an unprivileged account, collect historical network traffic, or cover every campaign variant. Each run prints the local indicator snapshot date. See [AGENTS.md](AGENTS.md) for update sources and procedure.
