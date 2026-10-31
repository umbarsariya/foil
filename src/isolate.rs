//! Isolation for `foil run`: a branch overlay over the workspace, a
//! read-only view of everything else (`--protect`) and no network
//! (`--no-network`), each optional.
//!
//! All of it happens in the forked child, between fork and exec. The child
//! enters a new user namespace that maps our own uid and gid to themselves,
//! so no root is needed and the command keeps its identity, then:
//!
//! - a new mount namespace, private to the run, where the branch overlay is
//!   mounted right over the workspace path (see `branch.rs`);
//! - with `--protect`: every mount made read-only, except clones of the
//!   workspace, the temp folders and `--allow-write` paths, taken just before
//!   and put back on top afterwards;
//! - with `--no-network`: a new network namespace with only loopback;
//! - with `--strict`: all of the above made deny-by-default, plus a PID and
//!   an IPC namespace, `no_new_privs` and a clean environment (`strict.rs`).
//!
//! Nothing outlives the run: the namespaces and mounts vanish with its last
//! process, which the cgroup box makes sure has happened before foil returns.
//!
//! Needs unprivileged user namespaces, which some systems restrict;
//! `explain` turns failures into hints and `foil doctor` checks in advance.

use std::ffi::{CStr, CString, OsString};
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use libc::{c_int, c_long};

use crate::strict::{self, View};
use crate::supervisor::cvt;

/// Paths that stay writable under `--protect` when they exist: scratch space
/// that compilers, test runners and shells expect to write.
const SCRATCH: [&str; 3] = ["/tmp", "/var/tmp", "/dev/shm"];

/// The most writable paths `--protect` takes; the child keeps one descriptor
/// per path in a fixed-size array, since it may not allocate.
pub const MAX_WRITABLE: usize = 32;

/// What the user asked for on the command line.
#[derive(Debug, Clone, Default)]
pub struct Options {
    pub no_network: bool,
    pub protect: bool,
    pub allow_write: Vec<PathBuf>,
    pub strict: bool,
    pub allow_read: Vec<PathBuf>,
    /// Environment variables passed into a strict run besides the basic set.
    pub allow_env: Vec<String>,
    /// `NAME=VALUE` pairs set inside a strict run.
    pub setenv: Vec<(String, String)>,
    /// Host folder of the network proxy's socket, when a strict run has one.
    pub proxy_dir: Option<PathBuf>,
    /// Unix sockets the run may create and listen on (`foil serve`'s execd);
    /// their folders are in `allow_write`, so the socket is the host's too.
    pub listen: Vec<PathBuf>,
}

/// Variables a strict run keeps from foil's environment; everything else
/// (tokens, keys, agent sockets) is left out unless `--allow-env` names it.
const BASIC_ENV: [&str; 16] = [
    "PATH", "HOME", "USER", "LOGNAME", "SHELL", "TERM", "COLORTERM", "TERM_PROGRAM", "LANG", "LANGUAGE", "TZ",
    "NO_COLOR", "FORCE_COLOR", "COLUMNS", "LINES", "EDITOR",
];

/// Port of the in-sandbox relay to the network proxy.
pub const PROXY_PORT: u16 = 3128;

/// An overlayfs mount: `lower` seen through `upper`, mounted over `lower`.
#[derive(Clone)]
pub struct Overlay {
    target: CString,
    /// `lowerdir=…,upperdir=…,workdir=…,userxattr`.
    options: CString,
}

impl Overlay {
    pub fn new(lower: &Path, upper: &Path, work: &Path) -> io::Result<Overlay> {
        for path in [lower, upper, work] {
            // These characters separate or escape overlayfs mount options.
            if path.as_os_str().as_bytes().iter().any(|b| b",:\\".contains(b)) {
                return Err(invalid(format!(
                    "overlayfs cannot use a path containing ',', ':' or '\\': {}",
                    path.display()
                )));
            }
        }
        let mut options = b"lowerdir=".to_vec();
        options.extend_from_slice(lower.as_os_str().as_bytes());
        options.extend_from_slice(b",upperdir=");
        options.extend_from_slice(upper.as_os_str().as_bytes());
        options.extend_from_slice(b",workdir=");
        options.extend_from_slice(work.as_os_str().as_bytes());
        // Mark whiteouts and opaque directories with user.* xattrs, which an
        // unprivileged mount may write (trusted.* needs real root).
        options.extend_from_slice(b",userxattr");
        Ok(Overlay {
            target: c_path(lower)?,
            options: CString::new(options).map_err(|_| invalid("NUL byte in a path".to_owned()))?,
        })
    }
}

/// Everything the forked child needs, built in advance because the child
/// may not allocate memory between fork and exec.
#[derive(Clone)]
pub struct Plan {
    /// `"<uid> <uid> 1"`: map our own uid to itself in the new user namespace.
    uid_map: CString,
    gid_map: CString,
    overlay: Option<Overlay>,
    /// Empty unless `--protect`: the paths that stay writable.
    writable: Vec<CString>,
    protect: bool,
    no_network: bool,
    /// The directory the command starts in, looked up again after the mounts.
    cwd: CString,
    /// `--strict`: the view to build, and the command's environment.
    view: Option<View>,
    env: Option<Vec<(OsString, OsString)>>,
}

impl Plan {
    /// The plan for these options, or `None` when they ask for no isolation.
    pub fn new(options: &Options, overlay: Option<Overlay>) -> io::Result<Option<Plan>> {
        if !options.allow_write.is_empty() && !options.protect && !options.strict {
            return Err(invalid("--allow-write only makes sense with --protect or --strict".to_owned()));
        }
        if !options.allow_read.is_empty() && !options.strict {
            return Err(invalid("--allow-read only makes sense with --strict".to_owned()));
        }
        if overlay.is_none() && !options.protect && !options.no_network && !options.strict {
            return Ok(None);
        }
        if options.strict {
            return Plan::strict(options, overlay).map(Some);
        }
        let mut writable = Vec::new();
        if options.protect {
            if let Some(overlay) = &overlay {
                writable.push(overlay.target.clone());
            }
            for path in SCRATCH.iter().map(Path::new).filter(|p| p.is_dir()) {
                writable.push(c_path(path)?);
            }
            for path in &options.allow_write {
                let path = path.canonicalize().map_err(|err| {
                    io::Error::new(err.kind(), format!("--allow-write {}: {err}", path.display()))
                })?;
                writable.push(c_path(&path)?);
            }
            if writable.len() > MAX_WRITABLE {
                return Err(invalid(format!("at most {MAX_WRITABLE} writable paths, counting the defaults")));
            }
        }
        // SAFETY: getuid and getgid cannot fail.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        Ok(Some(Plan {
            uid_map: CString::new(format!("{uid} {uid} 1")).expect("digits only"),
            gid_map: CString::new(format!("{gid} {gid} 1")).expect("digits only"),
            overlay,
            writable,
            protect: options.protect,
            no_network: options.no_network,
            cwd: c_path(&std::env::current_dir()?)?,
            view: None,
            env: None,
        }))
    }

    fn strict(options: &Options, overlay: Option<Overlay>) -> io::Result<Plan> {
        let cwd = std::env::current_dir()?;
        let workspace = match &overlay {
            Some(o) => Some((PathBuf::from(std::ffi::OsStr::from_bytes(o.target.as_bytes())), true)),
            None => Some((cwd.clone(), false)),
        };
        let home = std::env::var_os("HOME").map(PathBuf::from).filter(|h| h.is_absolute());
        let view = View::new(&strict::Spec {
            workspace: workspace.as_ref().map(|(p, w)| (p.as_path(), *w)),
            allow_read: &options.allow_read,
            allow_write: &options.allow_write,
            proxy_dir: options.proxy_dir.as_deref(),
            home,
        })?;
        let mut env: Vec<(OsString, OsString)> = std::env::vars_os()
            .filter(|(k, _)| {
                let k = k.to_string_lossy();
                BASIC_ENV.contains(&k.as_ref()) || k.starts_with("LC_") || options.allow_env.iter().any(|a| *a == k)
            })
            .collect();
        env.push(("TMPDIR".into(), "/tmp".into()));
        for (k, v) in &options.setenv {
            env.retain(|(name, _)| name != k.as_str());
            env.push((k.into(), v.into()));
        }
        // SAFETY: getuid and getgid cannot fail.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        Ok(Plan {
            uid_map: CString::new(format!("{uid} {uid} 1")).expect("digits only"),
            gid_map: CString::new(format!("{gid} {gid} 1")).expect("digits only"),
            overlay,
            writable: Vec::new(),
            protect: false,
            no_network: true,
            cwd: c_path(&cwd)?,
            view: Some(view),
            env: Some(env),
        })
    }

    fn needs_mounts(&self) -> bool {
        self.overlay.is_some() || self.protect || self.view.is_some()
    }

    /// Whether this is a strict run, whose command runs under `foil __pid1`.
    pub fn is_strict(&self) -> bool {
        self.view.is_some()
    }

    /// The environment the command gets, if not foil's own.
    pub fn env(&self) -> Option<&[(OsString, OsString)]> {
        self.env.as_deref()
    }

    /// The program and arguments to exec for `argv`: in a strict run, PID 1's
    /// helper first. `/proc/self/exe` is foil's own binary, whatever the view shows.
    pub fn wrap(&self, argv: &[OsString]) -> (OsString, Vec<OsString>) {
        if !self.is_strict() {
            return (argv[0].clone(), argv[1..].to_vec());
        }
        let mut args = vec![OsString::from("__pid1"), OsString::from("--")];
        args.extend_from_slice(argv);
        ("/proc/self/exe".into(), args)
    }
}

/// Move the calling process (forked, not yet exec'd) into the isolation
/// `p` describes. Runs between fork and exec, so it makes raw syscalls on
/// prebuilt buffers only: no allocation.
pub fn enter(p: &Plan) -> io::Result<()> {
    let mut flags = libc::CLONE_NEWUSER;
    if p.view.is_some() {
        flags |= libc::CLONE_NEWPID | libc::CLONE_NEWIPC;
    }
    if p.needs_mounts() {
        flags |= libc::CLONE_NEWNS;
    }
    if p.no_network {
        flags |= libc::CLONE_NEWNET;
    }
    // SAFETY: plain syscalls on NUL-terminated buffers that outlive the calls.
    unsafe {
        cvt(libc::unshare(flags))?;
        // An unprivileged process must give up setgroups before writing gid_map.
        write_file(c"/proc/self/setgroups", b"deny")?;
        write_file(c"/proc/self/uid_map", p.uid_map.as_bytes())?;
        write_file(c"/proc/self/gid_map", p.gid_map.as_bytes())?;
        if p.view.is_some() {
            // From here on, nothing the command runs can gain privileges
            // (setuid programs, file capabilities).
            cvt(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1 as libc::c_ulong, 0, 0, 0))?;
        }
        if p.no_network {
            // A new network namespace starts with only `lo`, and it is down.
            loopback_up()?;
        }
        if p.needs_mounts() {
            // Make every mount private, so nothing we do propagates anywhere else.
            cvt(libc::mount(
                c"none".as_ptr(),
                c"/".as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null(),
            ))?;
            if let Some(o) = &p.overlay {
                cvt(libc::mount(
                    c"overlay".as_ptr(),
                    o.target.as_ptr(),
                    c"overlay".as_ptr(),
                    0,
                    o.options.as_ptr().cast(),
                ))?;
            }
            if p.protect {
                read_only_except(&p.writable)?;
            }
            if let Some(view) = &p.view {
                strict::build(view)?;
                // Returns only in PID 1, already inside the view.
                return strict::fork_pid1(view);
            }
        }
        // A working directory under a new mount still points at what was
        // there before; look the path up again.
        cvt(libc::chdir(p.cwd.as_ptr()))?;
    }
    Ok(())
}

/// Make every mount read-only except `writable`. Each writable path is
/// cloned first (with the mounts below it, e.g. the branch overlay), the
/// whole tree is then made read-only, and the clones are mounted back on top.
/// Overlayfs keeps its own private copy of the upper layer's mount, so a
/// branch keeps working even though its storage folder becomes read-only.
unsafe fn read_only_except(writable: &[CString]) -> io::Result<()> {
    let mut clones = [-1 as c_int; MAX_WRITABLE];
    for (slot, path) in clones.iter_mut().zip(writable) {
        *slot = syscall_fd(libc::syscall(
            libc::SYS_open_tree,
            libc::AT_FDCWD as c_long,
            path.as_ptr(),
            (libc::OPEN_TREE_CLONE | libc::OPEN_TREE_CLOEXEC | libc::AT_RECURSIVE as libc::c_uint) as c_long,
        ))?;
    }
    let attr = libc::mount_attr {
        attr_set: libc::MOUNT_ATTR_RDONLY,
        attr_clr: 0,
        propagation: 0,
        userns_fd: 0,
    };
    syscall_fd(libc::syscall(
        libc::SYS_mount_setattr,
        libc::AT_FDCWD as c_long,
        c"/".as_ptr(),
        libc::AT_RECURSIVE as c_long,
        &attr as *const libc::mount_attr,
        std::mem::size_of::<libc::mount_attr>(),
    ))?;
    for (&fd, path) in clones.iter().zip(writable) {
        syscall_fd(libc::syscall(
            libc::SYS_move_mount,
            fd as c_long,
            c"".as_ptr(),
            libc::AT_FDCWD as c_long,
            path.as_ptr(),
            libc::MOVE_MOUNT_F_EMPTY_PATH as c_long,
        ))?;
        libc::close(fd);
    }
    Ok(())
}

/// Bring up `lo` in the current network namespace.
unsafe fn loopback_up() -> io::Result<()> {
    let sock = cvt(libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0))?;
    // SAFETY: ifreq is plain data; all-zero is a valid value.
    let mut req: libc::ifreq = std::mem::zeroed();
    for (dst, &src) in req.ifr_name.iter_mut().zip(b"lo\0") {
        *dst = src as libc::c_char;
    }
    let mut rc = libc::ioctl(sock, libc::SIOCGIFFLAGS as _, &mut req);
    if rc == 0 {
        req.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short;
        rc = libc::ioctl(sock, libc::SIOCSIFFLAGS as _, &req);
    }
    let err = io::Error::last_os_error();
    libc::close(sock);
    if rc == -1 {
        return Err(err);
    }
    Ok(())
}

/// Whether `enter` works here at all, tried in a throwaway child. Used after
/// a run failed to start, to tell an isolation problem from a command
/// problem, and by `foil doctor`.
pub fn can_enter(p: &Plan) -> bool {
    probe(p).is_ok()
}

/// Try `enter` in a throwaway child; the error is what the child hit.
pub fn probe(p: &Plan) -> io::Result<()> {
    let p = p.clone();
    let mut cmd = Command::new("true");
    cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    // SAFETY: `enter` only makes raw syscalls on prebuilt buffers.
    unsafe { cmd.pre_exec(move || enter(&p)) };
    match cmd.status() {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => Err(io::Error::other(format!("probe exited with {status}"))),
        Err(err) => Err(err),
    }
}

/// Wrap an error from entering the isolation with a hint about the likely cause.
pub fn explain(err: io::Error) -> io::Error {
    io::Error::other(format!("cannot isolate the command: {err}\n  hint: {}", hint(&err)))
}

/// The likely cause of an isolation failure on this system.
pub fn hint(err: &io::Error) -> &'static str {
    let read = |path: &str| fs::read_to_string(path).map(|s| s.trim().to_owned()).unwrap_or_default();
    if crate::container::runtime().is_some() {
        "foil is running inside a container, whose defaults block it; \
         `foil doctor` lists each blocker and the setting that removes it"
    } else if read("/proc/sys/kernel/apparmor_restrict_unprivileged_userns") == "1" {
        "AppArmor restricts unprivileged user namespaces here \
         (kernel.apparmor_restrict_unprivileged_userns=1); run `sudo foil setup` once"
    } else if read("/proc/sys/user/max_user_namespaces") == "0" {
        "user namespaces are disabled here (user.max_user_namespaces=0)"
    } else if err.raw_os_error() == Some(libc::EINVAL) {
        "overlayfs rejected the layers; FOIL_HOME must be on a filesystem with \
         user xattrs, such as ext4, xfs, btrfs, or tmpfs on Linux >= 6.6"
    } else if err.raw_os_error() == Some(libc::ENOSYS) {
        "--protect needs Linux >= 5.12 (mount_setattr)"
    } else {
        "foil needs Linux >= 5.11 and unprivileged user namespaces, which \
         container runtimes often block (e.g. Docker's default seccomp profile); \
         `foil doctor` checks this machine"
    }
}

/// Write all of `data` to the file at `path` with raw syscalls (no allocation).
pub(crate) unsafe fn write_file(path: &CStr, data: &[u8]) -> io::Result<()> {
    let fd = cvt(libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC))?;
    let written = libc::write(fd, data.as_ptr().cast(), data.len());
    let err = io::Error::last_os_error();
    libc::close(fd);
    if written == -1 {
        return Err(err);
    }
    // A short write sets no errno; report it as such (no allocation needed).
    if written as usize != data.len() {
        return Err(io::ErrorKind::WriteZero.into());
    }
    Ok(())
}

/// Map a raw `syscall` result (-1 + errno, else a value) to `io::Result`.
fn syscall_fd(rc: c_long) -> io::Result<c_int> {
    if rc == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc as c_int)
    }
}

pub(crate) fn c_path(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| invalid(format!("NUL byte in path {}", path.display())))
}

fn invalid(msg: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}
