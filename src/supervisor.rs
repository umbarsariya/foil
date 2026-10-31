//! Transparent process supervision for `foil run`.
//!
//! foil sits between the caller and one child command and must be invisible:
//! the child keeps foil's stdio, environment, terminal and process group, and
//! foil exits exactly the way the child did. Signals sent to foil (e.g. by
//! `docker stop` or a CI runner) are relayed to the child through a pidfd.
//! When the user has a delegated cgroup, the command runs in its own cgroup
//! "box" (see `cgroup.rs`), and one write to `cgroup.kill` stops everything
//! it started. foil is also a child subreaper, so either way every leftover
//! descendant is killed and reaped before foil returns. Leftovers first get a
//! SIGTERM and a short grace period (`FOIL_GRACE_MS`, default 1000) to save
//! their work and exit on their own; SIGKILL is only for what is still left.
//!
//! Invariant: the calling process must stay single-threaded while
//! `supervise` runs. Signals are blocked only on the calling thread, and
//! orphans are reparented to (and listed under) the main thread.

use std::collections::HashSet;
use std::ffi::OsString;
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::time::{Duration, Instant};

use libc::{c_int, c_long, pid_t};

use crate::isolate::{self, Plan};
use crate::cgroup::{self, Cgroup};

/// Signals foil relays to the child. SIGCHLD is watched too, for reaping.
pub(crate) const FORWARDED: [c_int; 7] = [
    libc::SIGHUP,
    libc::SIGINT,
    libc::SIGQUIT,
    libc::SIGTERM,
    libc::SIGUSR1,
    libc::SIGUSR2,
    libc::SIGWINCH,
];

/// How long leftovers get between SIGTERM and SIGKILL, unless FOIL_GRACE_MS says otherwise.
const DEFAULT_GRACE: Duration = Duration::from_millis(1000);

/// The longest single wait in the grace period. Normally a SIGCHLD wakes foil
/// first; this only matters if a box member's exit is reported elsewhere.
const GRACE_TICK: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Termination {
    Exited(i32),
    Signaled(i32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Outcome {
    pub termination: Termination,
    /// Descendants other than the command itself that foil reaped.
    pub orphans_reaped: usize,
    /// Whether the command ran inside its own cgroup box.
    pub contained: bool,
    /// Whether the command was stopped because its time ran out.
    pub timed_out: bool,
}

/// Run `argv` as a child, relay signals to it, and wait for it and all of
/// its descendants to be gone. With `isolation`, the command runs isolated
/// as it describes: in a branch, read-only, offline (see `isolate.rs`).
pub fn supervise(argv: &[OsString], isolation: Option<&Plan>) -> io::Result<Outcome> {
    supervise_for(argv, isolation, None)
}

/// [`supervise`], but give the command at most `timeout`: then it gets
/// SIGTERM, the grace period, and SIGKILL, like everything it left behind.
pub fn supervise_for(argv: &[OsString], isolation: Option<&Plan>, timeout: Option<Duration>) -> io::Result<Outcome> {
    let (program, args) = argv
        .split_first()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no command given"))?;

    // Orphaned descendants get reparented to us instead of to init.
    cvt(unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1 as libc::c_ulong) })?;

    // Block the signals we handle so they queue on a signalfd instead of
    // running default actions. This must happen before the child exists.
    let mut watched = FORWARDED.to_vec();
    watched.push(libc::SIGCHLD);
    let mask = sigset(&watched);
    check(unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &mask, std::ptr::null_mut()) })?;
    let sfd = cvt(unsafe { libc::signalfd(-1, &mask, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK) })?;
    // SAFETY: signalfd just returned this descriptor and nothing else owns it.
    let sfd = unsafe { OwnedFd::from_raw_fd(sfd) };
    let grace = grace_from_env();

    // Created before the child so that it is born straight into the box.
    let mut cgroup = Cgroup::create();
    let entry = cgroup.as_ref().map(Cgroup::entry);

    let parent = unsafe { libc::getpid() };
    let empty = sigset(&[]);
    let plan = isolation.cloned();
    let (program, args) = match isolation {
        Some(p) => p.wrap(argv),
        None => (program.clone(), args.to_vec()),
    };
    let mut cmd = Command::new(&program);
    cmd.args(&args);
    if let Some(env) = isolation.and_then(Plan::env) {
        cmd.env_clear().envs(env.iter().map(|(k, v)| (k, v)));
    }
    // SAFETY: the closure runs in the forked child before exec and only
    // makes async-signal-safe calls (no allocation, no locks).
    unsafe {
        cmd.pre_exec(move || {
            // Join the box first, so everything the command starts is inside.
            // On failure the child runs uncontained; the parent sees it via
            // `contains` and subreaper cleanup still applies.
            if let Some(procs) = &entry {
                let _ = cgroup::enter(procs);
            }
            // Dead-man's switch: if foil dies (even by SIGKILL), so does the child.
            cvt(libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong))?;
            // foil may have died between fork and prctl; then no signal will come.
            if libc::getppid() != parent {
                libc::_exit(1);
            }
            // When memory runs out (a --memory limit, which also covers foil,
            // or the whole machine), the OOM killer must pick the command,
            // never foil: a killed foil can't clean up or say what happened.
            // Raising one's own score needs no privilege; children inherit it.
            let _ = isolate::write_file(c"/proc/self/oom_score_adj", b"1000");
            // Then the isolation: from here on, the workspace is the overlay.
            // (In a strict run this returns in a new child, PID 1 of its own
            // PID namespace, which arms its own dead-man's switch.)
            if let Some(plan) = &plan {
                isolate::enter(plan)?;
            }
            // The signal mask and ignored dispositions survive exec; undo ours.
            check(libc::pthread_sigmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut()))?;
            libc::signal(libc::SIGPIPE, libc::SIG_DFL);
            Ok(())
        });
    }
    let pid = match cmd.spawn() {
        Ok(child) => child.id() as pid_t,
        // Isolating and running the command report errors the same way; a
        // throwaway test child tells the two apart.
        Err(err) if isolation.is_some_and(|p| !isolate::can_enter(p)) => return Err(isolate::explain(err)),
        Err(err) => return Err(err),
    };
    let contained = cgroup.as_ref().is_some_and(|cg| cg.contains(pid as u32));

    // Cleanup runs even if waiting failed, so an error never leaks the child.
    let deadline = timeout.and_then(|t| Instant::now().checked_add(t));
    let result = wait_for_exit(pid, &sfd, deadline, grace);
    // After an error, skip the grace period and go straight to SIGKILL.
    let spared = match result {
        Ok(_) => grace_period(cgroup.as_ref(), &sfd, grace),
        Err(_) => 0,
    };
    if let Some(cg) = &mut cgroup {
        // One write stops everything in the box, even processes we may not signal.
        let _ = cg.kill();
    }
    let drained = drain_descendants();
    // Everything is reaped, so the box is empty; dropping it removes it.
    drop(cgroup);
    result.map(|(termination, reaped, timed_out)| Outcome {
        termination,
        orphans_reaped: reaped + spared + drained,
        contained,
        timed_out,
    })
}

/// Relay signals to `pid` until it exits; returns its termination, the
/// number of other (orphaned) children reaped along the way, and whether
/// `deadline` passed first. At the deadline `pid` gets SIGTERM, and
/// SIGKILL if it is still there `grace` later.
fn wait_for_exit(
    pid: pid_t,
    sfd: &OwnedFd,
    mut deadline: Option<Instant>,
    grace: Duration,
) -> io::Result<(Termination, usize, bool)> {
    // The child is unreaped, so its PID cannot be recycled yet: no race here.
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as c_long, 0 as c_long) };
    if pidfd == -1 {
        let err = io::Error::last_os_error();
        return Err(io::Error::new(
            err.kind(),
            format!("pidfd_open (needs Linux >= 5.3): {err}"),
        ));
    }
    // SAFETY: pidfd_open returned a new descriptor that we now own.
    let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd as c_int) };

    let mut status = None;
    let mut orphans = 0;
    let mut timed_out = false;
    loop {
        reap_exited(pid, &mut status, &mut orphans)?;
        if let Some(termination) = status {
            return Ok((termination, orphans, timed_out));
        }
        if let Some(at) = deadline.filter(|at| Instant::now() >= *at) {
            if timed_out {
                forward(&pidfd, libc::SIGKILL)?;
                deadline = None;
            } else {
                timed_out = true;
                forward(&pidfd, libc::SIGTERM)?;
                deadline = Some(at.checked_add(grace).unwrap_or(at));
            }
            continue;
        }
        // Wake up at the deadline, rounded up so it has passed by then.
        let ms = deadline.map_or(-1, |at| {
            at.saturating_duration_since(Instant::now()).as_nanos().div_ceil(1_000_000).min(c_int::MAX as u128) as c_int
        });

        let mut fds = [pollin(sfd), pollin(&pidfd)];
        if unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, ms) } == -1 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if fds[0].revents & libc::POLLIN != 0 {
            for info in read_signals(sfd)? {
                let sig = info.ssi_signo as c_int;
                // SIGCHLD only wakes us up to reap. Terminal-generated signals
                // (SI_KERNEL) already reached the child via the shared process
                // group; forwarding them would deliver Ctrl-C twice.
                if sig != libc::SIGCHLD && info.ssi_code != libc::SI_KERNEL {
                    forward(&pidfd, sig)?;
                }
            }
        }
    }
}

/// FOIL_GRACE_MS as a duration; 0 means SIGKILL leftovers at once.
pub(crate) fn grace_from_env() -> Duration {
    let Some(raw) = std::env::var_os("FOIL_GRACE_MS") else {
        return DEFAULT_GRACE;
    };
    match raw.to_str().and_then(|ms| ms.trim().parse().ok()) {
        Some(ms) => Duration::from_millis(ms),
        None => {
            eprintln!("foil: ignoring FOIL_GRACE_MS={raw:?}: not a whole number of milliseconds");
            DEFAULT_GRACE
        }
    }
}

/// Ask every leftover process to exit with SIGTERM, then wait up to `grace`
/// for them to do so, reaping as they go. Returns the number reaped.
///
/// The wait ends early when nothing is left, when no leftover accepted the
/// SIGTERM (e.g. all are root-owned, so warning them is pointless), or when
/// foil itself is told to stop (the caller is in a hurry). Orphans adopted
/// during the wait get their own SIGTERM. Whatever is still running at the
/// end is SIGKILLed by the caller.
fn grace_period(cgroup: Option<&Cgroup>, sfd: &OwnedFd, grace: Duration) -> usize {
    let me = unsafe { libc::getpid() };
    let mut reaped = reap_leftovers();
    let left = |reaped: &mut usize| {
        *reaped += reap_leftovers();
        cgroup.is_some_and(Cgroup::is_populated) || !children_of(me).is_empty()
    };
    if grace.is_zero() || !left(&mut reaped) {
        return reaped;
    }
    let mut warned = HashSet::new();
    if terminate(cgroup, me, &mut warned) == 0 {
        return reaped;
    }
    // None: a grace too long to represent, i.e. wait as long as it takes.
    let deadline = Instant::now().checked_add(grace);
    while left(&mut reaped) {
        let wait = match deadline {
            Some(deadline) => deadline.saturating_duration_since(Instant::now()).min(GRACE_TICK),
            None => GRACE_TICK,
        };
        if wait.is_zero() {
            break;
        }
        let mut fds = [pollin(sfd)];
        let ms = wait.as_nanos().div_ceil(1_000_000) as c_int;
        if unsafe { libc::poll(fds.as_mut_ptr(), 1, ms) } == -1
            && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
        {
            break;
        }
        if fds[0].revents & libc::POLLIN != 0 {
            let Ok(signals) = read_signals(sfd) else { break };
            let hurry = [libc::SIGHUP, libc::SIGINT, libc::SIGQUIT, libc::SIGTERM];
            if signals.iter().any(|s| hurry.contains(&(s.ssi_signo as c_int))) {
                break;
            }
        }
        terminate(cgroup, me, &mut warned);
    }
    reaped
}

/// SIGTERM each leftover not in `warned` yet; returns how many accepted it.
/// A process gets one SIGTERM only: some programs treat a second as "quit
/// now, skip the clean-up". (A PID recycled into a new leftover is skipped;
/// SIGKILL still gets it.)
fn terminate(cgroup: Option<&Cgroup>, me: pid_t, warned: &mut HashSet<pid_t>) -> usize {
    let mut sent = 0;
    if let Some(cg) = cgroup {
        for pid in cg.pids() {
            if warned.insert(pid as pid_t) && terminate_listed(cg, pid) {
                sent += 1;
            }
        }
    }
    // Our own unreaped children: their PIDs cannot be recycled, so plain kill is safe.
    for child in children_of(me) {
        if warned.insert(child) && unsafe { libc::kill(child, libc::SIGTERM) } == 0 {
            sent += 1;
        }
    }
    sent
}

/// SIGTERM `pid`, which the box listed but which foil may not own: it may
/// have died and its PID been reused since the listing. The pidfd pins one
/// exact process; if the PID now belongs to a process outside the box, the
/// check fails, and if the pinned process is gone, the signal gets ESRCH.
fn terminate_listed(cg: &Cgroup, pid: u32) -> bool {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as c_long, 0 as c_long) };
    if fd == -1 {
        return false;
    }
    // SAFETY: pidfd_open returned a new descriptor that we now own.
    let pidfd = unsafe { OwnedFd::from_raw_fd(fd as c_int) };
    cg.contains(pid) && send_signal(&pidfd, libc::SIGTERM) == 0
}

/// Reap every exited child without blocking; returns how many. PID 0 never
/// matches a real child, so every one counts as a leftover.
fn reap_leftovers() -> usize {
    let mut reaped = 0;
    let _ = reap_exited(0, &mut None, &mut reaped);
    reaped
}

fn pollin(fd: &OwnedFd) -> libc::pollfd {
    libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    }
}

fn read_signals(sfd: &OwnedFd) -> io::Result<Vec<libc::signalfd_siginfo>> {
    const BATCH: usize = 16;
    let size = std::mem::size_of::<libc::signalfd_siginfo>();
    // SAFETY: signalfd_siginfo is plain integers; all-zero is a valid value.
    let mut buf: [libc::signalfd_siginfo; BATCH] = unsafe { std::mem::zeroed() };
    let n = unsafe { libc::read(sfd.as_raw_fd(), buf.as_mut_ptr().cast(), size * BATCH) };
    if n == -1 {
        let err = io::Error::last_os_error();
        return match err.kind() {
            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted => Ok(Vec::new()),
            _ => Err(err),
        };
    }
    Ok(buf[..n as usize / size].to_vec())
}

fn forward(pidfd: &OwnedFd, sig: c_int) -> io::Result<()> {
    if send_signal(pidfd, sig) == -1 {
        let err = io::Error::last_os_error();
        // ESRCH: the child already exited; the next reap will notice.
        if err.raw_os_error() != Some(libc::ESRCH) {
            return Err(err);
        }
    }
    Ok(())
}

/// Signal the process behind `pidfd`; returns 0, or -1 with errno set.
/// Signalling through a pidfd can never hit a recycled PID.
fn send_signal(pidfd: &OwnedFd, sig: c_int) -> c_long {
    unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd() as c_long,
            sig as c_long,
            0 as c_long,
            0 as c_long,
        )
    }
}

/// Reap every exited child without blocking, recording the main child's status.
fn reap_exited(main: pid_t, status: &mut Option<Termination>, orphans: &mut usize) -> io::Result<()> {
    loop {
        let mut raw = 0;
        match unsafe { libc::waitpid(-1, &mut raw, libc::WNOHANG) } {
            0 => return Ok(()),
            -1 => {
                let err = io::Error::last_os_error();
                match err.raw_os_error() {
                    Some(libc::ECHILD) => return Ok(()),
                    Some(libc::EINTR) => continue,
                    _ => return Err(err),
                }
            }
            pid if pid == main => *status = Some(decode(raw)),
            _ => *orphans += 1,
        }
    }
}

fn decode(raw: c_int) -> Termination {
    if libc::WIFSIGNALED(raw) {
        Termination::Signaled(libc::WTERMSIG(raw))
    } else {
        Termination::Exited(libc::WEXITSTATUS(raw))
    }
}

/// Kill and reap every remaining descendant. As a subreaper we inherit each
/// grandchild when its parent dies, so repeat until waitpid reports ECHILD.
/// Only our own unreaped children are signalled, so no PID can be recycled.
fn drain_descendants() -> usize {
    let me = unsafe { libc::getpid() };
    let mut reaped = 0;
    loop {
        for child in children_of(me) {
            unsafe { libc::kill(child, libc::SIGKILL) };
        }
        let mut raw = 0;
        match unsafe { libc::waitpid(-1, &mut raw, 0) } {
            -1 if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted => continue,
            -1 => return reaped, // ECHILD: nothing left
            _ => reaped += 1,
        }
    }
}

/// PIDs whose parent is `parent`: fast path via the task's `children` file
/// (CONFIG_PROC_CHILDREN), falling back to scanning /proc/*/stat.
fn children_of(parent: pid_t) -> Vec<pid_t> {
    if let Ok(list) = std::fs::read_to_string(format!("/proc/{parent}/task/{parent}/children")) {
        return list.split_whitespace().filter_map(|p| p.parse().ok()).collect();
    }
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries
        .filter_map(|entry| {
            let pid: pid_t = entry.ok()?.file_name().to_str()?.parse().ok()?;
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
            // Field 2 (comm) may contain spaces and ')', so parse after the last ')'.
            let after_comm = stat.get(stat.rfind(')')? + 2..)?;
            let ppid: pid_t = after_comm.split(' ').nth(1)?.parse().ok()?;
            (ppid == parent).then_some(pid)
        })
        .collect()
}

/// Exit the current process the same way the child terminated, so foil's own
/// parent (a shell, CI runner or container runtime) sees an identical status.
pub fn exit_like(termination: Termination) -> ! {
    match termination {
        Termination::Exited(code) => std::process::exit(code),
        Termination::Signaled(sig) => {
            // SAFETY: plain libc calls on a process that is about to die.
            unsafe {
                // The child may already have dumped core; foil must not add a second.
                let no_core = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
                libc::setrlimit(libc::RLIMIT_CORE, &no_core);
                libc::signal(sig, libc::SIG_DFL);
                libc::pthread_sigmask(libc::SIG_UNBLOCK, &sigset(&[sig]), std::ptr::null_mut());
                libc::raise(sig);
            }
            // Only reached if the signal's default action does not terminate.
            std::process::exit(128 + sig)
        }
    }
}

fn sigset(signals: &[c_int]) -> libc::sigset_t {
    let mut set = MaybeUninit::<libc::sigset_t>::uninit();
    // SAFETY: sigemptyset initialises the whole set before it is read.
    unsafe {
        libc::sigemptyset(set.as_mut_ptr());
        for &sig in signals {
            libc::sigaddset(set.as_mut_ptr(), sig);
        }
        set.assume_init()
    }
}

/// Map the `-1 + errno` convention to `io::Result`.
pub(crate) fn cvt(rc: c_int) -> io::Result<c_int> {
    if rc == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc)
    }
}

/// pthread_* functions return the error number instead of setting errno.
fn check(rc: c_int) -> io::Result<()> {
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(rc))
    }
}
