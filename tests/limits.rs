//! Tests for `--memory`, `--cpus` and `--pids`. They need a systemd user
//! session; without one they are skipped, unless FOIL_REQUIRE_LIMITS is set,
//! which turns a skip into a failure.

use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Output};

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn run(options: &[&str], script: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_foil"))
        .arg("run")
        .args(options)
        .args(["--", "sh", "-c", script])
        .output()
        .unwrap()
}

/// Whether limits work here; skips (or fails, if required) otherwise.
fn available() -> bool {
    let out = run(&["--pids", "1000"], "true");
    if out.status.success() {
        return true;
    }
    assert!(
        std::env::var_os("FOIL_REQUIRE_LIMITS").is_none(),
        "limits unavailable: {}",
        text(&out.stderr)
    );
    eprintln!("skipped: limits unavailable here: {}", text(&out.stderr));
    false
}

#[test]
fn limits_are_set_on_the_runs_cgroup() {
    if !available() {
        return;
    }
    // Older systemd (Ubuntu 22.04's 249) does not delegate the cpu
    // controller to user managers by default: then --cpus must fail with a
    // clear explanation, and the other limits must still work.
    let cpu = run(&["--cpus", "1"], "true");
    let cpu_delegated = cpu.status.success();
    if !cpu_delegated {
        assert!(text(&cpu.stderr).contains("did not apply the cpu limit"), "{}", text(&cpu.stderr));
    }
    // The command sits in foil's box; the limits are on the scope around it.
    let (flags, files, want): (&[&str], &str, &str) = if cpu_delegated {
        (&["--memory", "64M", "--cpus", "0.5", "--pids", "50"], "memory.max memory.swap.max cpu.max pids.max", "67108864\n0\n50000 100000\n50\n")
    } else {
        (&["--memory", "64M", "--pids", "50"], "memory.max memory.swap.max pids.max", "67108864\n0\n50\n")
    };
    let out = run(flags, &format!("cd /sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup)/.. && cat {files}"));

    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), want);
}

#[test]
fn a_memory_hog_is_killed_with_a_clear_message() {
    if !available() {
        return;
    }
    let out = run(&["--memory", "32M"], "x=$(head -c 200000000 /dev/zero | tr '\\0' a); echo survived");

    assert_eq!(out.status.signal(), Some(libc::SIGKILL), "{}", text(&out.stderr));
    assert!(!text(&out.stdout).contains("survived"));
    assert!(text(&out.stderr).contains("more memory than --memory allows"), "{}", text(&out.stderr));
}

/// foil shares the memory limit with its command; if the OOM killer chose
/// foil, nothing would report the kill or clean up after it. (Linux: macOS
/// has no OOM killer; its --memory is foil's own watchdog.)
#[cfg(target_os = "linux")]
#[test]
fn the_command_not_foil_is_the_oom_killers_first_choice() {
    let out = run(&[], "cat /proc/self/oom_score_adj");
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "1000\n");
}

#[test]
fn a_pids_limit_stops_runaway_forks() {
    if !available() {
        return;
    }
    let out = run(&["--pids", "10"], "for i in $(seq 30); do sleep 1 & done; wait");

    assert!(text(&out.stderr).to_lowercase().contains("fork"), "{}", text(&out.stderr));
}

#[test]
fn bad_limit_values_are_rejected() {
    for (flag, value) in [("--memory", "lots"), ("--cpus", "0"), ("--pids", "-3")] {
        let out = run(&[flag, value], "true");
        assert_eq!(out.status.code(), Some(2), "{flag} {value} was accepted");
    }
}

/// `foil session`: runs inside it make their cleanup box in the session's
/// scope directly (no scope of their own), and the box really holds them.
#[test]
fn runs_inside_a_session_get_their_box_without_a_scope_each() {
    if !available() {
        return;
    }
    let ws = std::env::temp_dir().join(format!("foil-session-{}", std::process::id()));
    std::fs::create_dir_all(&ws).unwrap();
    let foil = env!("CARGO_BIN_EXE_foil");
    let script = format!(
        "{foil} run -b s1 -- cat /proc/self/cgroup; echo; FOIL_NO_SCOPE=1 {foil} run -b s2 -- cat /proc/self/cgroup"
    );
    let out = Command::new(foil)
        .args(["session", "--", "sh", "-c", &script])
        .current_dir(&ws)
        .env("FOIL_HOME", std::env::temp_dir().join(format!("foil-session-home-{}", std::process::id())))
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&ws);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    // Both runs sit in a foil box; the second could not have asked systemd
    // (FOIL_NO_SCOPE), so its box came from the session.
    // (A box is a cgroup named foil-<pid>; the session's scope is named foil-session-...)
    let is_box = |line: &str| line.rsplit('/').next().and_then(|b| b.strip_prefix("foil-")).is_some_and(|n| n.bytes().all(|c| c.is_ascii_digit()));
    assert_eq!(stdout.lines().filter(|l| is_box(l)).count(), 2, "{stdout}");
    assert!(!stdout.contains("FOIL_SCOPED"));
}
