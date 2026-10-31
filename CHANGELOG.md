# Changelog

## Unreleased

- Linux: the command, not foil, is the OOM killer's first choice
  (`oom_score_adj` 1000, inherited by everything it starts). Under a tight
  `--memory` the kernel could kill foil itself, so the run ended with no
  message and no cleanup.
OpenSandbox compatibility.

- `foil serve`: OpenSandbox's lifecycle API, with foil branches as
  sandboxes; each sandbox runs `foil __execd` (OpenSandbox's execd API:
  commands, sessions, files, metrics) inside one long-lived `foil run`, and
  the server relays to it. Extra endpoints `diff`, `commit` and `logs`;
  `networkPolicy` becomes `--strict` + `--allow-host`; sandboxes survive a
  server restart; pause freezes the run's cgroup (stops its processes
  without one, and on macOS). The unchanged OpenSandbox Python SDK passes
  `integrations/opensandbox/sdk_e2e.py` on Linux and macOS.
- `--listen-socket PATH` for `foil run`: the run may listen on that Unix
  socket even under `--strict` (what `foil serve` uses).
- `integrations/opensandbox/`: an image and demo for foil inside an
  OpenSandbox sandbox, and a patch adding `runtime.type = "foil"` to
  OpenSandbox's server (with OSEP-0025, a draft proposal).
- `install.sh`: `FOIL_VERSION` picks a release; `FOIL_NO_SETUP=1` and
  containers skip the AppArmor setup.
- Licensed under Apache-2.0 alone (was MIT OR Apache-2.0; 0.3.0 and earlier
  keep their license). Contributions need the [CLA](CLA.md), signed once by
  comment on the first pull request.
- Pull request and issue templates, and a code of conduct.

## 0.4.0 — 2026-10-26

macOS support.

- Branches from APFS clones: a frozen `base` and the `tree` the command
  works in; diff, conflicts and commit are exact three-way comparisons; commit
  clones files back (no data copied), with the same crash-safe journal.
- The sandbox from Seatbelt: `--protect`, `--no-network`, `--strict` (home
  folders and other volumes hidden, a private home, clean environment, only
  foil's proxy reachable, signals and process information only within the
  run).
- Every process of a run is found through its profile, detached ones too,
  and stopped at the end; a SIGKILLed foil's leftovers are stopped before the
  branch is used again.
- The network proxy listens on a loopback port and requires a per-run token.
- `--memory` as a watchdog and `--timeout`; `--cpus`/`--pids` stay Linux-only.
- `foil vm`: Linux foil in a Lima VM sharing only the folders you name.
- `foil doctor` checks each of these for real; `tests/mac.rs` (19 tests).
- CI on macOS (Apple silicon and Intel); releases add a universal macOS
  binary; `install.sh` and Homebrew install it.

## 0.3.0 — 2026-10-24

First public release.

- `--timeout TIME` for `foil run`, `foil agent` and `foil fanout`: the
  command gets SIGTERM, then SIGKILL after the grace period, and the run
  exits 124. A hung fanout attempt no longer holds up the others.
- `foil fanout --json`: the attempts, their checks and the best one, on stdout.
- `examples/django-username`: three Claude Code sessions fix a real Django
  bug (ticket #30257) in parallel strict branches; the best passing fix is
  committed. Verified end to end (~20 s, Haiku).
- `examples/best-of-n`: four agents on one failing test, the smallest passing
  fix committed, a rogue attempt contained (no API key needed; `claude.sh` for
  real Claude Code sessions).
- Limits and `foil session` name their systemd scope, so foil works when it
  is itself started by `systemd-run --scope`.
- `foil commit` counts changed paths, not folders overlayfs copied up to
  hold them ("applied 1 change", not "applied 66 changes").
- On kernels before 6.13 a file changed in the same clock tick just before
  a branch was made no longer shows as a false conflict: the branch starts
  on a fresh tick (a few ms at branch creation).
- `fanout` records each attempt's own run time; `--json` gives `status` as a
  number and `timed_out` separately.
- Release binaries with SHA-256 checksums; `install.sh` can download one.
- Licensed MIT OR Apache-2.0: free for any use, with credit (copyright notice, NOTICE file).

Security and reliability fixes from a design review:

- Strict runs without a terminal get their own session: the command can no
  longer signal foil's process group (and through it the calling script)
  or reach a controlling terminal.
- Descriptors foil inherited are closed before a strict command starts.
- The proxy refuses internal addresses (loopback, private, link-local such
  as 169.254.169.254) for hosts allowed only through `*` or `*.domain`, and
  connects to the address it checked (no DNS rebinding window).
- The proxy streams request bodies instead of holding them in memory,
  bounds chunk-size lines, rejects bad lengths, caps open connections, and
  backs off when out of descriptors: the sandbox can't crash it.
- `--allow-host` values are checked up front (`host:99999` is an error, not
  "ports 80 and 443"); `[v6]:port` and trailing dots match.
- `foil agent` never shows the home folder or a folder right in it
  (`~/.cargo`, `~/.local`) as part of an agent's installation.
- `foil agent` warns when no API key is injected.
- `FOIL_GRACE_MS` applies inside strict runs too.
- foil no longer signals the proxy's PID after the cleanup already reaped it.
- The proxy reports readiness on a pipe: no 5 ms polling at start.

## 0.2.0 — 2026-10-23

- `--strict`, the allowlist proxy with API-key injection, `foil agent`.
- `foil fanout` and `foil pick`; `foil session`.
- Crash-safe, race-free commit (journal, open folder handles, no symlink
  following); conflict detection; `.gitignore`d build output left out.
- Runs inside Docker and Podman; platform matrix (Ubuntu 22.04–26.04,
  Debian 13, Fedora 44, AlmaLinux 9).

## 0.1.0 — 2026-10-11

- Branches (`run -b`, `diff`, `commit`, `abort`), `--protect`,
  `--no-network`, `--memory`/`--cpus`/`--pids`, cleanup box, `foil doctor`,
  `foil setup`.
