//! macOS: branches from APFS clones and the Seatbelt sandbox, tested the way
//! tests/branch.rs and tests/strict.rs test Linux. Each `cannot_*` test tries
//! something a run must not be able to do, and checks that it failed.
#![cfg(target_os = "macos")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// A home folder (with a secret), a workspace in it, another repository in
/// it, and a branch store, all under one scratch root.
struct Env {
    root: PathBuf,
}

impl Env {
    fn new(test: &str) -> Env {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        // Not under the temp folder: runs may always write there.
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("mac-{}-{n}-{test}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for dir in ["home/ws/src", "home/.ssh", "home/other", "store"] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        std::fs::write(root.join("home/ws/a.txt"), "base\n").unwrap();
        std::fs::write(root.join("home/.ssh/id_ed25519"), "PRIVATE KEY\n").unwrap();
        std::fs::write(root.join("home/other/secret.txt"), "other repo secret\n").unwrap();
        Env { root: root.canonicalize().unwrap() }
    }

    fn path(&self, rel: &str) -> String {
        self.root.join(rel).display().to_string()
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_foil"));
        cmd.args(args)
            .current_dir(self.root.join("home/ws"))
            .env("HOME", self.root.join("home"))
            .env("FOIL_HOME", self.root.join("store"))
            .env("FOIL_GRACE_MS", "200");
        cmd
    }

    fn foil(&self, args: &[&str]) -> Output {
        self.cmd(args).output().unwrap()
    }

    /// `foil run <options> -- sh -c <script>`.
    fn run(&self, options: &[&str], script: &str) -> Output {
        let mut args = vec!["run"];
        args.extend_from_slice(options);
        args.extend_from_slice(&["--", "sh", "-c", script]);
        self.foil(&args)
    }

    fn read(&self, rel: &str) -> Option<String> {
        std::fs::read_to_string(self.root.join("home/ws").join(rel)).ok()
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = Command::new("chmod").args(["-R", "u+rwx"]).arg(&self.root).status();
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn alive(pid: i32) -> bool {
    // SAFETY: signal 0 only checks for existence.
    unsafe { libc::kill(pid, 0) == 0 }
}

// ---------------------------------------------------------------- branches

#[test]
fn a_branch_runs_in_its_clone_and_commits_back() {
    let env = Env::new("branch");
    let out = env.run(&["-b", "t"], "pwd; echo changed > a.txt; echo new > src/new.txt");
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stdout).trim_end().ends_with("/branches/t/tree"), "{}", text(&out.stdout));
    assert_eq!(env.read("a.txt").as_deref(), Some("base\n"), "the workspace changed before commit");

    let diff = env.foil(&["diff", "t"]);
    assert_eq!(text(&diff.stdout), "M a.txt\nA src/new.txt\n");
    let commit = env.foil(&["commit", "t"]);
    assert!(commit.status.success(), "{}", text(&commit.stderr));
    assert_eq!(text(&commit.stdout), "applied 2 changes\n");
    assert_eq!(env.read("a.txt").as_deref(), Some("changed\n"));
    assert_eq!(env.read("src/new.txt").as_deref(), Some("new\n"));
}

#[test]
fn a_run_starts_in_the_same_folder_inside_the_clone() {
    let env = Env::new("cwd");
    let out = env.cmd(&["run", "-b", "t", "-w", "..", "--", "pwd"]).current_dir(env.root.join("home/ws/src")).output().unwrap();
    assert!(text(&out.stdout).trim_end().ends_with("/branches/t/tree/src"), "{}", text(&out.stdout));
}

#[test]
fn cannot_write_the_real_workspace_from_a_branch() {
    let env = Env::new("realws");
    let ws = env.path("home/ws");
    let out = env.run(&["-b", "t"], &format!("echo evil > '{ws}/a.txt' 2>/dev/null; echo evil > '{ws}/b.txt' 2>/dev/null; true"));
    assert!(out.status.success());
    assert_eq!(env.read("a.txt").as_deref(), Some("base\n"));
    assert_eq!(env.read("b.txt"), None);
}

#[test]
fn a_commit_refuses_files_changed_in_the_workspace_since() {
    let env = Env::new("conflict");
    assert!(env.run(&["-b", "t"], "echo branch > a.txt").status.success());
    std::fs::write(env.root.join("home/ws/a.txt"), "workspace\n").unwrap();
    let out = env.foil(&["commit", "t"]);
    assert!(!out.status.success());
    assert!(text(&out.stderr).contains("a.txt"), "{}", text(&out.stderr));
    assert_eq!(env.read("a.txt").as_deref(), Some("workspace\n"));
    assert!(env.foil(&["commit", "--force", "t"]).status.success());
    assert_eq!(env.read("a.txt").as_deref(), Some("branch\n"));
}

#[test]
fn an_interrupted_commit_finishes_when_run_again() {
    let env = Env::new("resume");
    assert!(env.run(&["-b", "t"], "echo 1 > one; echo 2 > two; echo 3 > three").status.success());
    let out = env.cmd(&["commit", "t"]).env("FOIL_TEST_CRASH_AFTER", "2").output().unwrap();
    assert!(!out.status.success(), "the commit was not interrupted");
    assert!(!env.foil(&["abort", "t"]).status.success(), "abort accepted a half-applied commit");
    let again = env.foil(&["commit", "t"]);
    assert!(again.status.success(), "{}", text(&again.stderr));
    for (f, v) in [("one", "1\n"), ("two", "2\n"), ("three", "3\n")] {
        assert_eq!(env.read(f).as_deref(), Some(v));
    }
}

#[test]
fn branches_and_metadata_survive_modes_symlinks_and_deletions() {
    let env = Env::new("kinds");
    std::fs::write(env.root.join("home/ws/src/gone.txt"), "x").unwrap();
    let out = env.run(&["-b", "t"], "chmod 600 a.txt; ln -s a.txt link; unlink src/gone.txt; mkdir -p d/e; echo f > d/e/f");
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(env.foil(&["commit", "t"]).status.success());
    use std::os::unix::fs::PermissionsExt;
    let ws = env.root.join("home/ws");
    assert_eq!(std::fs::metadata(ws.join("a.txt")).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(std::fs::read_link(ws.join("link")).unwrap(), PathBuf::from("a.txt"));
    assert!(!ws.join("src/gone.txt").exists());
    assert_eq!(env.read("d/e/f").as_deref(), Some("f\n"));
}

// ---------------------------------------------------------------- cleanup

#[test]
fn detached_processes_end_with_the_run() {
    let env = Env::new("detached");
    let pidfile = env.root.join("pid");
    let out = env.run(&[], &format!("(nohup sleep 60 >/dev/null 2>&1 & echo $! > '{}')", pidfile.display()));
    assert!(out.status.success());
    let pid: i32 = std::fs::read_to_string(&pidfile).unwrap().trim().parse().unwrap();
    assert!(!alive(pid), "a detached process survived the run");
}

#[test]
fn leftovers_of_a_killed_foil_are_stopped_at_once() {
    let env = Env::new("stale");
    let pidfile = env.root.join("writer.pid");
    let script = format!("(while :; do echo tick >> log; sleep 0.02; done) & echo $! > '{}'; wait", pidfile.display());
    let mut foil = env.cmd(&["run", "-b", "t", "--", "sh", "-c", &script]).stdout(Stdio::null()).spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let writer: i32 = loop {
        if let Some(pid) = std::fs::read_to_string(&pidfile).ok().and_then(|p| p.trim().parse().ok()) {
            break pid;
        }
        assert!(Instant::now() < deadline, "writer never started");
        std::thread::sleep(Duration::from_millis(10));
    };
    foil.kill().unwrap(); // SIGKILL: foil gets no chance to clean up
    foil.wait().unwrap();
    // foil's watcher stops the run as soon as foil is gone.
    let deadline = Instant::now() + Duration::from_secs(3);
    while alive(writer) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    let still = alive(writer);
    if still {
        // SAFETY: our own test process's leftover.
        unsafe { libc::kill(writer, libc::SIGKILL) };
    }
    assert!(!still, "the writer outlived a SIGKILLed foil");
    let out = env.foil(&["commit", "t"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(env.read("log").is_some_and(|l| l.contains("tick")));
}

#[test]
fn timeout_stops_the_run() {
    let env = Env::new("timeout");
    let started = Instant::now();
    let out = env.run(&["--timeout", "300ms"], "trap '' TERM; sleep 30");
    assert_eq!(out.status.code(), Some(124), "{}", text(&out.stderr));
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn memory_watchdog_stops_a_run_that_grows_too_big() {
    let env = Env::new("memory");
    let out = env.run(&["--memory", "64M"], "python3 -c 'x = bytearray(400 * 1024 * 1024); import time; time.sleep(5)'");
    assert!(!out.status.success());
    assert!(text(&out.stderr).contains("more memory than --memory allows"), "{}", text(&out.stderr));
    let cpus = env.run(&["--cpus", "1"], "true");
    assert_eq!(cpus.status.code(), Some(125));
}

// ---------------------------------------------------------------- isolation

#[test]
fn cannot_write_outside_with_protect() {
    let env = Env::new("protect");
    let outside = env.path("home/other/new.txt");
    let out = env.run(&["--protect"], &format!("echo x > '{outside}' 2>/dev/null; echo ok > /tmp/foil-mac-protect-$$ && unlink /tmp/foil-mac-protect-$$ && echo tmp-ok"));
    assert_eq!(text(&out.stdout), "tmp-ok\n", "{}", text(&out.stderr));
    assert!(!env.root.join("home/other/new.txt").exists());
}

#[test]
fn cannot_reach_the_network_with_no_network_but_loopback_works() {
    let env = Env::new("offline");
    // serve_once reads the request before replying: closing a socket with
    // unread data sends a reset, which can discard the reply before curl reads it.
    let port = serve_once(|_| "ok".to_owned());
    let out = env.run(
        &["--no-network"],
        &format!("curl -s -m 3 http://127.0.0.1:{port}/; echo; curl -s -m 3 -o /dev/null https://example.com || echo blocked"),
    );
    assert_eq!(text(&out.stdout), "ok\nblocked\n", "{}", text(&out.stderr));
}

#[test]
fn cannot_read_secrets_with_strict() {
    let env = Env::new("strict-read");
    let script = format!(
        "cat '{}' 2>/dev/null || echo no-ssh; cat '{}' 2>/dev/null || echo no-other; cat a.txt; ls -A ~ | wc -l | tr -d ' '",
        env.path("home/.ssh/id_ed25519"),
        env.path("home/other/secret.txt")
    );
    let out = env.run(&["-b", "t", "--strict"], &script);
    assert_eq!(text(&out.stdout), "no-ssh\nno-other\nbase\n0\n", "{}", text(&out.stderr));
}

#[test]
fn cannot_see_environment_secrets_with_strict() {
    let env = Env::new("strict-env");
    let out = env.cmd(&["run", "--strict", "--allow-env", "SHOWN", "--", "sh", "-c", "echo ${SECRET:-none} ${SHOWN:-none}"])
        .env("SECRET", "s3cret")
        .env("SHOWN", "yes")
        .output()
        .unwrap();
    assert_eq!(text(&out.stdout), "none yes\n");
}

#[test]
fn cannot_signal_other_processes_with_strict() {
    let env = Env::new("strict-signal");
    let mut outside = Command::new("sleep").arg("30").spawn().unwrap();
    let out = env.run(&["--strict"], &format!("kill -TERM {} 2>/dev/null && echo SIGNALLED || echo refused", outside.id()));
    let survived = outside.try_wait().unwrap().is_none();
    let _ = outside.kill();
    let _ = outside.wait();
    assert_eq!(text(&out.stdout), "refused\n");
    assert!(survived);
}

/// A one-shot HTTP server on loopback; `respond` builds the body from the head.
fn serve_once(respond: fn(&str) -> String) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for conn in listener.incoming().flatten() {
            let mut reader = BufReader::new(conn.try_clone().unwrap());
            let mut head = String::new();
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
                head.push_str(&line);
            }
            let len = head
                .lines()
                .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap_or(0)))
                .unwrap_or(0);
            let mut body = vec![0u8; len];
            let _ = reader.read_exact(&mut body);
            let reply = respond(&head);
            let mut conn = conn;
            let _ = write!(conn, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}", reply.len());
        }
    });
    port
}

#[test]
fn cannot_reach_hosts_outside_the_allowlist_or_local_ports() {
    let env = Env::new("allow");
    let allowed = serve_once(|_| "allowed-body".to_owned());
    let other = serve_once(|_| "must-not-be-seen".to_owned());
    let script = format!(
        "curl -s --noproxy '' -x \"$HTTP_PROXY\" http://127.0.0.1:{allowed}/; echo; \
         curl -s --noproxy '' -x \"$HTTP_PROXY\" http://127.0.0.1:{other}/; echo; \
         curl -s --noproxy '*' -m 2 http://127.0.0.1:{other}/ || echo direct-refused"
    );
    let out = env.run(&["--strict", "--allow-host", &format!("127.0.0.1:{allowed}")], &script);
    let stdout = text(&out.stdout);
    assert!(stdout.starts_with("allowed-body\n"), "{stdout}\n{}", text(&out.stderr));
    assert!(!stdout.contains("must-not-be-seen"), "{stdout}");
    assert!(stdout.contains("direct-refused"), "{stdout}");
}

#[test]
fn cannot_see_the_injected_key_or_use_the_proxy_without_the_token() {
    let env = Env::new("inject");
    let api = serve_once(|head| format!("key-ok={}", head.lines().any(|l| l.eq_ignore_ascii_case("x-api-key: sk-real-key"))));
    let script = "echo \"key=$ANTHROPIC_API_KEY\"; curl -s \"$ANTHROPIC_BASE_URL/v1/messages\" -d '{}'; echo; \
                  wrong=$(echo \"$ANTHROPIC_BASE_URL\" | sed 's#/__inject/[0-9a-f]*/#/__inject/0000/#'); \
                  curl -s -o /dev/null -w '%{http_code}' \"$wrong/v1/messages\" -d '{}'";
    let out = env
        .cmd(&["run", "--strict", "--inject-key", "anthropic", "--", "sh", "-c", script])
        .env("ANTHROPIC_API_KEY", "sk-real-key")
        .env("FOIL_INJECT_ANTHROPIC_URL", format!("http://127.0.0.1:{api}"))
        .output()
        .unwrap();
    let stdout = text(&out.stdout);
    assert!(!stdout.contains("sk-real-key"), "the key is visible inside: {stdout}");
    assert!(stdout.contains("key-ok=true"), "{stdout}\n{}", text(&out.stderr));
    assert!(stdout.ends_with("407"), "a request without the token got through: {stdout}");
}

#[test]
fn fanout_works_on_macos() {
    let env = Env::new("fanout");
    let out = env.foil(&[
        "fanout", "-n", "3", "--name", "f", "--check", "[ $(cat a.txt) -ge 2 ]", "--pick", "--", "sh", "-c", "echo $FOIL_ATTEMPT > a.txt",
    ]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(env.read("a.txt").as_deref(), Some("2\n"));
}

#[test]
fn doctor_passes() {
    let out = Command::new(env!("CARGO_BIN_EXE_foil")).arg("doctor").output().unwrap();
    assert!(out.status.success(), "{}", text(&out.stdout));
}
