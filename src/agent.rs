//! The public socket exposes only read/sign operations. A separate same-user
//! socket controls the vault lifecycle; a private OpenSSH agent does the signing.
//!
//! The watchdog holds the same `flock` as the server and sees EOF if the server
//! exits, including after SIGKILL. It removes plaintext metadata and terminates
//! the backend. If neither process could clean up (e.g. host power loss), the
//! next start or non-running status/lock/stop scrubs stale files under the lock.
//! The daemon.lock inode is deliberately retained, with no pid or key contents.

use crate::{Identity, Paths, vault};
use anyhow::{Context, Result, bail, ensure};
use clap::Subcommand;
use ssh_key::{PrivateKey, PublicKey, private::KeypairData};
use std::{
    collections::{HashMap, hash_map::Entry},
    env,
    fs::{self, File, OpenOptions, Permissions},
    io::{self, Read, Write},
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd},
        unix::{
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
            net::{UnixListener, UnixStream},
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub const AGENT_SOCKET: &str = "agent.sock";
const CONTROL_SOCKET: &str = "control.sock";
const BACKEND_DIR: &str = ".backend";
const LOCK_FILE: &str = "daemon.lock";
const CONFIG_TMP: &str = ".managed.tmp";
const IDENTITY_DIR: &str = "identities";
const DEFAULT_IDLE: u64 = 900;
const STARTUP: Duration = Duration::from_secs(5);
const IO_TIMEOUT: Duration = Duration::from_secs(3);
const CLIENT_TIMEOUT: Duration = Duration::from_secs(120);
const UNLOCK_TIMEOUT: Duration = Duration::from_secs(30);
const TICK: Duration = Duration::from_millis(25);
const MAX_AGENT: usize = 256 * 1024;
const MAX_CONTROL: usize = 16 * 1024 * 1024;
const MAX_IDENTITIES: usize = 512;

const FAILURE: u8 = 5;
const SUCCESS: u8 = 6;
const LIST: u8 = 11;
const IDENTITIES: u8 = 12;
const SIGN: u8 = 13;
const SIGNATURE: u8 = 14;
const ADD: u8 = 17;
const CLEAR: u8 = 19;
const EXTENSION: u8 = 27;
const RSA_SHA256: u32 = 2;
const RSA_SHA512: u32 = 4;

const STATUS: u8 = 1;
const STOP: u8 = 2;
const UNLOCK: u8 = 3;
const LOCK: u8 = 4;

#[derive(Subcommand)]
pub enum AgentCommand {
    /// Start the agent, initially locked
    Start {
        /// Remain attached to the terminal
        #[arg(long, short = 'f')]
        foreground: bool,
        /// Lock this many seconds after unlock or the last successful signature
        #[arg(long, value_name = "SECONDS", default_value_t = DEFAULT_IDLE,
            value_parser = clap::value_parser!(u64).range(1..))]
        idle_timeout: u64,
    },
    /// Show the agent's run and lock state
    Status,
    /// Stop the agent and discard unlocked keys and configuration
    Stop,
    /// Decrypt the vault and load its keys and configuration
    Unlock,
    /// Discard unlocked keys and configuration without stopping the agent
    Lock,
    #[command(hide = true)]
    Watchdog,
}

pub fn agent_cmd(p: &Paths, command: AgentCommand) -> Result<()> {
    dispatch(p, command, &["agent"])
}

/// Entry point for the standalone binary, whose commands are not nested.
pub fn standalone_cmd(p: &Paths, command: AgentCommand) -> Result<()> {
    dispatch(p, command, &[])
}

fn dispatch(p: &Paths, command: AgentCommand, prefix: &[&str]) -> Result<()> {
    p.prepare_runtime()?;
    match command {
        AgentCommand::Start {
            foreground: true,
            idle_timeout,
        } => serve(p, prefix, Duration::from_secs(idle_timeout)),
        AgentCommand::Start {
            foreground: false,
            idle_timeout,
        } => start_background(p, prefix, idle_timeout),
        AgentCommand::Watchdog => watchdog(p),
        AgentCommand::Unlock => {
            disable_core_dumps()?;
            let control = p.runtime.join(CONTROL_SOCKET);
            ensure!(
                connect(&control)?.is_some(),
                "agent is not running; run start first"
            );
            // Never give passphrases to the daemon. Only the decrypted snapshot
            // travels over the authenticated local socket. Provider resolution
            // can prompt indefinitely, so do not hold a connection during it.
            let (config, keys) = vault::unlock_material(p)?;
            let payload = encode_unlock(&config, &keys)?;
            drop(keys);
            let mut socket = connect(&control)?.context("agent stopped while unlocking")?;
            deadlines(&socket, UNLOCK_TIMEOUT)?;
            send_frame(&mut socket, &payload)?;
            drop(payload);
            println!("{}", control_reply(&mut socket)?);
            Ok(())
        }
        command => {
            let op = match command {
                AgentCommand::Status => STATUS,
                AgentCommand::Stop => STOP,
                AgentCommand::Lock => LOCK,
                _ => unreachable!(),
            };
            if let Some(mut socket) = connect(&p.runtime.join(CONTROL_SOCKET))? {
                send_frame(&mut socket, &[op])?;
                let reply = control_reply(&mut socket)?;
                if op == STOP {
                    // Do not report a successful stop until the watchdog has
                    // reaped the backend and removed the old socket names.
                    wait_for_cleanup(p)?;
                }
                println!("{reply}");
            } else {
                recover_stale(p)?;
                println!("agent not running");
            }
            Ok(())
        }
    }
}

fn child_command(p: &Paths, prefix: &[&str]) -> Result<Command> {
    let mut command = Command::new(env::current_exe()?);
    internal_env(&mut command, p)?;
    command.args(prefix);
    Ok(command)
}

fn internal_env(command: &mut Command, p: &Paths) -> Result<()> {
    // The daemon does not open the vault. Do not pass along arbitrary secret
    // environment variables such as provider session tokens.
    command
        .env_clear()
        .env("SSHP_RUNTIME_DIR", &p.runtime)
        .env("SSHP_REPO", &p.repo)
        .env("HOME", crate::home()?);
    Ok(())
}

fn detach(command: &mut Command) {
    // SAFETY: setsid is async-signal-safe and this hook touches no Rust state.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

fn start_background(p: &Paths, prefix: &[&str], idle: u64) -> Result<()> {
    let control = p.runtime.join(CONTROL_SOCKET);
    if connect(&control)?.is_some() {
        println!("agent already running");
        return Ok(());
    }
    let mut log = tempfile::tempfile()?;
    let mut command = child_command(p, prefix)?;
    command
        .args(["start", "--foreground", "--idle-timeout", &idle.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(log.try_clone()?);
    detach(&mut command);
    let mut child = command.spawn().context("start agent daemon")?;
    let started = Instant::now();
    while started.elapsed() < STARTUP {
        if let Some(mut socket) = connect(&control)? {
            send_frame(&mut socket, &[STATUS])?;
            println!("{}", control_reply(&mut socket)?);
            println!("SSH_AUTH_SOCK={}", p.runtime.join(AGENT_SOCKET).display());
            return Ok(());
        }
        if let Some(exit) = child.try_wait()? {
            use std::io::Seek;
            log.rewind()?;
            let mut error = String::new();
            log.read_to_string(&mut error)?;
            bail!("agent failed to start ({exit}): {}", error.trim());
        }
        thread::sleep(TICK);
    }
    let _ = child.kill();
    let _ = child.wait();
    bail!("agent did not start in time")
}

fn open_lock(p: &Paths) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(p.runtime.join(LOCK_FILE))?;
    let m = file.metadata()?;
    ensure!(
        m.is_file() && m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o077 == 0,
        "unsafe daemon lock file"
    );
    Ok(file)
}

fn try_flock(fd: BorrowedFd<'_>) -> io::Result<bool> {
    // Passing a duplicate of this open file description to the watchdog
    // preserves the lock after a crash. Never explicitly unlock or unlink it.
    loop {
        if unsafe { libc::flock(fd.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(true);
        }
        let error = io::Error::last_os_error();
        match error.kind() {
            io::ErrorKind::WouldBlock => return Ok(false),
            io::ErrorKind::Interrupted => continue,
            _ => return Err(error),
        }
    }
}

fn remove_file(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
}

fn remove_dir(path: &Path) -> io::Result<()> {
    match fs::remove_dir_all(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
}

fn scrub(p: &Paths) -> io::Result<()> {
    let mut result = remove_file(&p.managed_config());
    for name in [CONFIG_TMP, AGENT_SOCKET, CONTROL_SOCKET] {
        result = remove_file(&p.runtime.join(name)).and(result);
    }
    for name in [IDENTITY_DIR, BACKEND_DIR] {
        result = remove_dir(&p.runtime.join(name)).and(result);
    }
    result
}

fn recover_stale(p: &Paths) -> Result<()> {
    let file = open_lock(p)?;
    if try_flock(file.as_fd())? {
        scrub(p).context("remove stale agent files")?;
    }
    Ok(())
}

fn wait_for_cleanup(p: &Paths) -> Result<()> {
    let lock = open_lock(p)?;
    let start = Instant::now();
    while !try_flock(lock.as_fd())? {
        ensure!(
            start.elapsed() < STARTUP,
            "timed out waiting for agent cleanup"
        );
        thread::sleep(TICK);
    }
    scrub(p).context("clean up stopped agent")
}

fn watchdog(p: &Paths) -> Result<()> {
    // stdout is a duplicated lock descriptor, not a pipe or terminal.
    let inherited = io::stdout();
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    ensure!(
        unsafe { libc::fstat(inherited.as_raw_fd(), stat.as_mut_ptr()) } == 0,
        "watchdog requires an inherited daemon lock"
    );
    let stat = unsafe { stat.assume_init() };
    let expected = fs::symlink_metadata(p.runtime.join(LOCK_FILE))?;
    ensure!(
        expected.is_file()
            && stat.st_ino == expected.ino() as libc::ino_t
            && stat.st_dev == expected.dev() as libc::dev_t
            && try_flock(inherited.as_fd())?,
        "watchdog requires an inherited daemon lock"
    );
    // OpenSSH command mode forks its backend, then execs us as the parent.
    // It also checks that we're still alive, independently of this watchdog.
    let pid: libc::pid_t = env::var("SSH_AGENT_PID")?.parse()?;
    ensure!(pid > 1, "invalid OpenSSH agent pid");
    // The daemon holds the only write end. The kernel closes it even on SIGKILL.
    let _ = io::copy(&mut io::stdin().lock(), &mut io::sink());
    let unpublish = remove_file(&p.managed_config());
    let result = stop_backend(pid);
    let cleanup = scrub(p);
    unpublish?;
    result?;
    cleanup?;
    Ok(())
}

fn wait_pid(pid: libc::pid_t, flags: libc::c_int) -> io::Result<bool> {
    loop {
        match unsafe { libc::waitpid(pid, std::ptr::null_mut(), flags) } {
            0 => return Ok(false),
            n if n == pid => return Ok(true),
            _ => {
                let err = io::Error::last_os_error();
                match err.raw_os_error() {
                    Some(libc::EINTR) => continue,
                    Some(libc::ECHILD) => return Ok(true),
                    _ => return Err(err),
                }
            }
        }
    }
}

fn stop_backend(pid: libc::pid_t) -> io::Result<()> {
    if !wait_pid(pid, libc::WNOHANG)? {
        // waitpid proved this is our unreaped child; its pid cannot be reused.
        unsafe { libc::kill(pid, libc::SIGTERM) };
        let start = Instant::now();
        while !wait_pid(pid, libc::WNOHANG)? {
            if start.elapsed() >= Duration::from_secs(1) {
                unsafe { libc::kill(pid, libc::SIGKILL) };
                wait_pid(pid, 0)?;
                break;
            }
            thread::sleep(TICK);
        }
    }
    Ok(())
}

struct Watch(Child);

impl Drop for Watch {
    fn drop(&mut self) {
        drop(self.0.stdin.take());
        let _ = self.0.wait();
    }
}

struct Runtime<'a>(&'a Paths);

impl Drop for Runtime<'_> {
    fn drop(&mut self) {
        let _ = scrub(self.0);
    }
}

static SIGNALLED: AtomicBool = AtomicBool::new(false);

extern "C" fn signal_handler(_: libc::c_int) {
    SIGNALLED.store(true, Ordering::Relaxed);
}

fn install_signals() -> io::Result<()> {
    // SAFETY: handler performs only a lock-free atomic store.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = signal_handler as *const () as libc::sighandler_t;
        libc::sigemptyset(&mut action.sa_mask);
        for signal in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
            if libc::sigaction(signal, &action, std::ptr::null_mut()) < 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

fn disable_core_dumps() -> io::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn bind(path: &Path) -> Result<UnixListener> {
    let listener = UnixListener::bind(path).with_context(|| format!("bind {}", path.display()))?;
    fs::set_permissions(path, Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

fn serve(p: &Paths, prefix: &[&str], idle: Duration) -> Result<()> {
    install_signals()?;
    disable_core_dumps()?;
    let lock = open_lock(p)?;
    ensure!(
        try_flock(lock.as_fd())?,
        "agent is already running or starting"
    );
    scrub(p)?;
    let _runtime = Runtime(p);
    let backend_dir = p.runtime.join(BACKEND_DIR);
    fs::create_dir(&backend_dir)?;
    fs::set_permissions(&backend_dir, Permissions::from_mode(0o700))?;
    // A surviving old backend must not be able to unlink a new backend's
    // socket if it notices the loss of its watchdog after another start.
    let backend_tmp = tempfile::Builder::new()
        .prefix("")
        .rand_bytes(8)
        .tempdir_in(backend_dir)?;
    let backend = backend_tmp.path().join("s");
    let mut command = Command::new("/usr/bin/ssh-agent");
    internal_env(&mut command, p)?;
    command
        .args(["-P", "", "-a"])
        .arg(&backend)
        .arg(env::current_exe()?)
        .args(prefix)
        .arg("watchdog")
        .stdin(Stdio::piped())
        .stdout(lock.try_clone()?);
    detach(&mut command);
    let mut watch = Watch(command.spawn().context("start agent watchdog")?);
    let ready = Instant::now();
    while connect(&backend)?.is_none() {
        ensure!(
            watch.0.try_wait()?.is_none(),
            "agent watchdog exited during startup"
        );
        ensure!(
            ready.elapsed() < STARTUP,
            "private OpenSSH agent did not start"
        );
        if SIGNALLED.load(Ordering::Relaxed) {
            return Ok(());
        }
        thread::sleep(TICK);
    }
    fs::set_permissions(&backend, Permissions::from_mode(0o600))?;
    let agent = bind(&p.runtime.join(AGENT_SOCKET))?;
    let control = bind(&p.runtime.join(CONTROL_SOCKET))?;
    let state = Arc::new(Server {
        paths: p.clone(),
        idle,
        backend,
        closing: AtomicBool::new(false),
        stopping: AtomicBool::new(false),
        state: RwLock::new(State::default()),
    });
    let agent_workers = Arc::new(AtomicUsize::new(0));
    let control_workers = Arc::new(AtomicUsize::new(0));
    let result = (|| -> Result<()> {
        let mut health = Instant::now();
        while !SIGNALLED.load(Ordering::Relaxed) && !state.stopping.load(Ordering::Acquire) {
            accept(&control, &state, &control_workers, 8, control_client)?;
            accept(&agent, &state, &agent_workers, 64, agent_client)?;
            if let Ok(mut inner) = state.state.try_write()
                && inner.unlocked.as_ref().is_some_and(|u| u.expired(idle))
            {
                state.lock(&mut inner)?;
            }
            if health.elapsed() >= Duration::from_secs(1) {
                ensure!(
                    watch.0.try_wait()?.is_none(),
                    "agent watchdog exited unexpectedly"
                );
                ensure!(
                    connect(&state.backend)?.is_some(),
                    "private OpenSSH agent exited unexpectedly"
                );
                health = Instant::now();
            }
            thread::sleep(TICK);
        }
        Ok(())
    })();
    // Stop accepting and serialize with a possibly in-progress publish even
    // when our event loop returns an error. Watchdog cleanup follows this.
    state.closing.store(true, Ordering::Release);
    state.stopping.store(true, Ordering::Release);
    let cleanup = state.lock(&mut state.state.write().unwrap());
    result.and(cleanup)
}

struct Worker(Arc<AtomicUsize>);

impl Drop for Worker {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

fn accept(
    listener: &UnixListener,
    state: &Arc<Server>,
    workers: &Arc<AtomicUsize>,
    max: usize,
    handle: fn(UnixStream, &Server) -> Result<()>,
) -> io::Result<()> {
    for _ in 0..16 {
        let stream = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if workers.load(Ordering::Relaxed) >= max || peer_uid(&stream).ok() != Some(euid()) {
            continue;
        }
        // On BSD/macOS, accept can inherit O_NONBLOCK from the listening
        // socket. Workers need timed blocking reads between protocol frames.
        stream.set_nonblocking(false)?;
        workers.fetch_add(1, Ordering::Relaxed);
        let worker = Worker(workers.clone());
        let state = state.clone();
        thread::Builder::new().spawn(move || {
            let _worker = worker;
            let _ = handle(stream, &state);
        })?;
    }
    Ok(())
}

fn euid() -> libc::uid_t {
    unsafe { libc::geteuid() }
}

#[cfg(target_os = "linux")]
fn peer_uid(stream: &UnixStream) -> io::Result<libc::uid_t> {
    let mut credentials = std::mem::MaybeUninit::<libc::ucred>::uninit();
    let mut size = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            credentials.as_mut_ptr().cast(),
            &mut size,
        )
    };
    if result == 0 && size as usize == std::mem::size_of::<libc::ucred>() {
        Ok(unsafe { credentials.assume_init() }.uid)
    } else if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid peer credentials",
        ))
    }
}

#[cfg(not(target_os = "linux"))]
fn peer_uid(stream: &UnixStream) -> io::Result<libc::uid_t> {
    let (mut uid, mut gid) = (0, 0);
    if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } == 0 {
        Ok(uid)
    } else {
        Err(io::Error::last_os_error())
    }
}

fn deadlines(stream: &UnixStream, timeout: Duration) -> io::Result<()> {
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))
}

fn connect(path: &Path) -> Result<Option<UnixStream>> {
    match UnixStream::connect(path) {
        Ok(stream) => {
            ensure!(
                peer_uid(&stream)? == euid(),
                "socket belongs to a different user"
            );
            deadlines(&stream, IO_TIMEOUT)?;
            Ok(Some(stream))
        }
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            ) =>
        {
            Ok(None)
        }
        Err(e) => Err(e).with_context(|| format!("connect to {}", path.display())),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum KeyType {
    Ed25519,
    Rsa,
}

#[derive(Default)]
struct State {
    epoch: u64,
    unlocked: Option<Unlocked>,
}

struct Unlocked {
    types: HashMap<Vec<u8>, KeyType>,
    identity_reply: Vec<u8>,
    activity: Mutex<Instant>,
}

impl Unlocked {
    fn expired(&self, idle: Duration) -> bool {
        self.activity.lock().unwrap().elapsed() >= idle
    }
}

struct Server {
    paths: Paths,
    idle: Duration,
    backend: PathBuf,
    closing: AtomicBool,
    stopping: AtomicBool,
    // Exclusive from the start of loading until after publish, and throughout
    // revocation. Signing takes a read guard, so lock can't finish while an old
    // generation is still signing or an unlock is still publishing.
    state: RwLock<State>,
}

impl Server {
    fn backend(&self) -> Result<UnixStream> {
        connect(&self.backend)?.context("private OpenSSH agent is unavailable")
    }

    fn clear_keys(&self) -> Result<()> {
        ensure!(
            exchange(&mut self.backend()?, &[CLEAR])?.as_slice() == [SUCCESS],
            "private OpenSSH agent refused to clear keys"
        );
        Ok(())
    }

    fn status(&self) -> Result<String> {
        let mut state = self.state.write().unwrap();
        if state
            .unlocked
            .as_ref()
            .is_some_and(|u| u.expired(self.idle))
        {
            self.lock(&mut state)?;
        }
        Ok(match &state.unlocked {
            Some(u) => format!("agent running (unlocked, {} identities)", u.types.len()),
            None => "agent running (locked)".into(),
        })
    }

    fn lock(&self, state: &mut State) -> Result<()> {
        let unpublish = remove_file(&self.paths.managed_config());
        let public_files = remove_dir(&self.paths.runtime.join(IDENTITY_DIR));
        if state.unlocked.take().is_some() {
            state.epoch = state.epoch.wrapping_add(1);
            if let Err(err) = self.clear_keys() {
                // Do not leave a possibly loaded backend running on error.
                self.stopping.store(true, Ordering::Release);
                return Err(err);
            }
        }
        let cleanup = unpublish.and(public_files);
        if cleanup.is_err() {
            self.stopping.store(true, Ordering::Release);
        }
        cleanup.context("remove managed SSH configuration and public identities")
    }

    fn unlock(&self, state: &mut State, input: &[u8]) -> Result<usize> {
        ensure!(
            !self.closing.load(Ordering::Acquire) && !self.stopping.load(Ordering::Acquire),
            "agent is stopping"
        );
        let request = parse_unlock(input)?;
        self.lock(state)?;
        let mut backend = self.backend()?;
        let loaded = load_snapshot(&self.paths, &mut backend, request);
        match loaded {
            Ok(unlocked) => {
                let count = unlocked.types.len();
                state.epoch = state.epoch.wrapping_add(1);
                state.unlocked = Some(unlocked);
                Ok(count)
            }
            Err(err) => {
                if self.clear_keys().is_err() {
                    self.stopping.store(true, Ordering::Release);
                }
                let _ = remove_file(&self.paths.runtime.join(CONFIG_TMP));
                let _ = remove_dir(&self.paths.runtime.join(IDENTITY_DIR));
                Err(err)
            }
        }
    }
}

fn control_client(mut socket: UnixStream, server: &Server) -> Result<()> {
    deadlines(&socket, IO_TIMEOUT)?;
    let payload = read_frame(&mut socket, MAX_CONTROL)?;
    let (op, data) = payload.split_first().context("empty control request")?;
    let (result, stop) = match (*op, data.is_empty()) {
        (STATUS, true) => (server.status(), false),
        (UNLOCK, false) => (
            server
                .unlock(&mut server.state.write().unwrap(), data)
                .map(|n| format!("agent unlocked ({n} identities)")),
            false,
        ),
        (LOCK, true) | (STOP, true) => {
            let stop = *op == STOP;
            if stop {
                server.closing.store(true, Ordering::Release);
            }
            let result = server.lock(&mut server.state.write().unwrap());
            (
                result.map(|()| {
                    if stop {
                        "agent stopped"
                    } else {
                        "agent locked"
                    }
                    .into()
                }),
                stop,
            )
        }
        _ => (Err(anyhow::anyhow!("unsupported control request")), false),
    };
    // Erase the decrypted snapshot before we acknowledge the operation.
    drop(payload);
    let (status, message) = match result {
        Ok(text) => (SUCCESS, text),
        Err(err) => (FAILURE, format!("{err:#}")),
    };
    let mut response = vec![status];
    response.extend(message.as_bytes());
    let reply = send_frame(&mut socket, &response);
    if stop {
        server.stopping.store(true, Ordering::Release);
    }
    reply.context("send control response")
}

fn control_reply(socket: &mut UnixStream) -> Result<String> {
    let reply = read_frame(socket, MAX_AGENT)?;
    let (&code, text) = reply.split_first().context("empty control response")?;
    let text = std::str::from_utf8(text)?;
    ensure!(code == SUCCESS, "{text}");
    Ok(text.to_owned())
}

fn agent_client(mut socket: UnixStream, server: &Server) -> Result<()> {
    // Interactive SSH authentication can pause between listing and signing.
    socket.set_read_timeout(Some(CLIENT_TIMEOUT))?;
    socket.set_write_timeout(Some(IO_TIMEOUT))?;
    let mut backend = None;
    let mut epoch = None;
    loop {
        let request = read_frame(&mut socket, MAX_AGENT)?;
        let response = {
            let state = server.state.read().unwrap();
            // A bound or forwarded connection belongs to its original unlock
            // generation. Keep speaking the protocol after revocation, but
            // never promote an old stream into a new generation.
            let same_generation = *epoch.get_or_insert(state.epoch) == state.epoch;
            let unlocked = state.unlocked.as_ref().filter(|u| {
                same_generation
                    && !server.closing.load(Ordering::Acquire)
                    && !server.stopping.load(Ordering::Acquire)
                    && !u.expired(server.idle)
            });
            if request.as_slice() == [LIST] {
                unlocked.map_or_else(
                    || vec![IDENTITIES, 0, 0, 0, 0],
                    |u| u.identity_reply.clone(),
                )
            } else if let Some(u) = unlocked
                && (allowed_sign(&request, &u.types) || is_session_bind(&request))
            {
                let backend = match &mut backend {
                    Some(socket) => socket,
                    slot @ None => slot.insert(server.backend()?),
                };
                let reply = exchange(backend, &request)?;
                if request[0] == SIGN && reply.first() == Some(&SIGNATURE) {
                    *u.activity.lock().unwrap() = Instant::now();
                }
                reply.to_vec()
            } else {
                // Never forward addition/removal, locking, PKCS#11, unknown
                // extensions, or any unsupported flags/constraints.
                vec![FAILURE]
            }
        };
        send_frame(&mut socket, &response)?;
    }
}

fn allowed_sign(request: &[u8], keys: &HashMap<Vec<u8>, KeyType>) -> bool {
    let Some(mut rest) = request.strip_prefix(&[SIGN]) else {
        return false;
    };
    let Ok(blob) = take_string(&mut rest) else {
        return false;
    };
    if take_string(&mut rest).is_err() {
        return false;
    }
    matches!(
        (
            keys.get(blob),
            <[u8; 4]>::try_from(rest).map(u32::from_be_bytes),
        ),
        (Some(KeyType::Ed25519), Ok(0)) | (Some(KeyType::Rsa), Ok(RSA_SHA256 | RSA_SHA512))
    )
}

fn is_session_bind(request: &[u8]) -> bool {
    let Some(mut rest) = request.strip_prefix(&[EXTENSION]) else {
        return false;
    };
    take_string(&mut rest).is_ok_and(|name| name == b"session-bind@openssh.com")
}

fn read_frame(stream: &mut UnixStream, limit: usize) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut length = [0u8; 4];
    stream.read_exact(&mut length)?;
    let len = u32::from_be_bytes(length) as usize;
    if len == 0 || len > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid agent frame length",
        ));
    }
    let mut payload = Zeroizing::new(vec![0; len]);
    stream.read_exact(&mut payload)?;
    Ok(payload)
}

fn send_frame(stream: &mut UnixStream, payload: &[u8]) -> io::Result<()> {
    let size = u32::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "agent frame overflow"))?;
    stream.write_all(&size.to_be_bytes())?;
    stream.write_all(payload)
}

fn exchange(stream: &mut UnixStream, request: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    send_frame(stream, request)?;
    Ok(read_frame(stream, MAX_AGENT)?)
}

fn put_string(out: &mut Vec<u8>, value: &[u8]) {
    out.extend((value.len() as u32).to_be_bytes());
    out.extend(value);
}

fn take_u32(data: &mut &[u8]) -> Result<usize> {
    let (len, rest) = data.split_at_checked(4).context("truncated integer")?;
    *data = rest;
    Ok(u32::from_be_bytes(len.try_into()?) as usize)
}

fn take_string<'a>(data: &mut &'a [u8]) -> Result<&'a [u8]> {
    let len = take_u32(data)?;
    let (value, rest) = data.split_at_checked(len).context("truncated string")?;
    *data = rest;
    Ok(value)
}

fn take_str<'a>(data: &mut &'a [u8]) -> Result<&'a str> {
    Ok(std::str::from_utf8(take_string(data)?)?)
}

fn encode_unlock(config: &str, keys: &[Identity]) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(keys.len() <= MAX_IDENTITIES, "too many identities");
    let mut size = 9usize.saturating_add(config.len());
    for id in keys {
        size = size
            .saturating_add(12)
            .saturating_add(id.pem.len())
            .saturating_add(id.public.len());
        for host in &id.hosts {
            size = size.saturating_add(4).saturating_add(host.len());
        }
    }
    ensure!(size <= MAX_CONTROL, "unlock snapshot is too large");
    // Size the allocation before copying any keys, to avoid reallocating
    // uncleared intermediate copies of the plaintext.
    let mut out = Zeroizing::new(Vec::with_capacity(size));
    out.push(UNLOCK);
    put_string(&mut out, config.as_bytes());
    out.extend((keys.len() as u32).to_be_bytes());
    for id in keys {
        put_string(&mut out, id.pem.as_bytes());
        put_string(&mut out, id.public.as_bytes());
        out.extend((id.hosts.len() as u32).to_be_bytes());
        for host in &id.hosts {
            put_string(&mut out, host.as_bytes());
        }
    }
    Ok(out)
}

struct VaultKey<'a> {
    pem: &'a str,
    public: &'a str,
    hosts: Vec<&'a str>,
}

struct Snapshot<'a> {
    config: &'a str,
    keys: Vec<VaultKey<'a>>,
}

fn parse_unlock(mut data: &[u8]) -> Result<Snapshot<'_>> {
    let config = take_str(&mut data)?;
    let count = take_u32(&mut data)?;
    ensure!(count <= MAX_IDENTITIES, "too many identities");
    let mut keys = Vec::with_capacity(count);
    for _ in 0..count {
        let pem = take_str(&mut data)?;
        let public = take_str(&mut data)?;
        let count = take_u32(&mut data)?;
        ensure!(count <= 4096, "too many host patterns for one identity");
        let hosts = (0..count)
            .map(|_| take_str(&mut data))
            .collect::<Result<_>>()?;
        keys.push(VaultKey { pem, public, hosts });
    }
    ensure!(data.is_empty(), "trailing data in unlock request");
    Ok(Snapshot { config, keys })
}

fn add_identity(stream: &mut UnixStream, key: &PrivateKey, comment: &str) -> Result<KeyType> {
    // Allocate for the full packet before copying any private components.
    let kind;
    let mut packet = match key.key_data() {
        KeypairData::Ed25519(pair) => {
            kind = KeyType::Ed25519;
            let size = 1 + (4 + b"ssh-ed25519".len()) + (4 + 32) + (4 + 64) + (4 + comment.len());
            let mut packet = Zeroizing::new(Vec::with_capacity(size));
            packet.push(ADD);
            put_string(&mut packet, b"ssh-ed25519");
            put_string(&mut packet, pair.public.as_ref());
            let bytes = Zeroizing::new(pair.to_bytes());
            put_string(&mut packet, bytes.as_ref());
            packet
        }
        KeypairData::Rsa(pair) => {
            kind = KeyType::Rsa;
            let parts = [
                &pair.public.n,
                &pair.public.e,
                &pair.private.d,
                &pair.private.iqmp,
                &pair.private.p,
                &pair.private.q,
            ];
            let size = 1
                + 11
                + 4
                + comment.len()
                + parts.iter().map(|p| 4 + p.as_bytes().len()).sum::<usize>();
            ensure!(size <= MAX_AGENT, "RSA identity is too large");
            let mut packet = Zeroizing::new(Vec::with_capacity(size));
            packet.push(ADD);
            put_string(&mut packet, b"ssh-rsa");
            for part in parts {
                put_string(&mut packet, part.as_bytes());
            }
            packet
        }
        _ => bail!("only Ed25519 and RSA identities are supported"),
    };
    put_string(&mut packet, comment.as_bytes());
    ensure!(
        exchange(stream, &packet)?.as_slice() == [SUCCESS],
        "OpenSSH rejected an identity"
    );
    Ok(kind)
}

fn ssh_path(path: &Path) -> Result<String> {
    let value = path
        .to_str()
        .context("SSH configuration path is not UTF-8")?;
    ensure!(
        !value.contains(['\n', '\r', '\0', '"', '\\']) && !value.contains("${"),
        "unsupported character in SSH runtime path"
    );
    Ok(format!("\"{}\"", value.replace('%', "%%")))
}

fn valid_host(host: &str) -> bool {
    host.len() <= 253
        && host
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn load_snapshot(p: &Paths, backend: &mut UnixStream, snapshot: Snapshot<'_>) -> Result<Unlocked> {
    let dir = p.runtime.join(IDENTITY_DIR);
    // Each generation uses different public key paths, so a concurrent ssh
    // invocation that read the old config cannot pick up a different key.
    let public_files = if snapshot.keys.iter().any(|entry| !entry.hosts.is_empty()) {
        fs::create_dir(&dir)?;
        fs::set_permissions(&dir, Permissions::from_mode(0o700))?;
        Some(tempfile::Builder::new().prefix("keys-").tempdir_in(dir)?)
    } else {
        None
    };
    let agent_path = ssh_path(&p.runtime.join(AGENT_SOCKET))?;
    let mut text = String::from("# Generated by sshp-agent; removed on lock.\n");
    let mut types = HashMap::new();
    let mut listed = Vec::new();
    for (index, entry) in snapshot.keys.into_iter().enumerate() {
        let private =
            PrivateKey::from_openssh(entry.pem).context("decode unlocked OpenSSH private key")?;
        let mut public =
            PublicKey::from_openssh(entry.public).context("decode vault public key")?;
        let blob = public.to_bytes()?;
        ensure!(
            private.public_key().to_bytes()? == blob,
            "private key does not match its public identity"
        );
        let comment = public.comment();
        ensure!(
            comment.len() <= 4096 && !comment.contains('\0'),
            "invalid SSH key comment"
        );
        if let Entry::Vacant(slot) = types.entry(blob) {
            let kind = add_identity(backend, &private, comment)?;
            put_string(&mut listed, slot.key());
            put_string(&mut listed, comment.as_bytes());
            slot.insert(kind);
        }
        if entry.hosts.is_empty() {
            continue;
        }
        ensure!(
            entry.hosts.iter().all(|host| valid_host(host)),
            "invalid SSH host alias in vault"
        );
        let path = public_files
            .as_ref()
            .unwrap()
            .path()
            .join(format!("{index}.pub"));
        public.set_comment("");
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        writeln!(output, "{}", public.to_openssh()?)?;
        use std::fmt::Write as _;
        writeln!(
            text,
            "Host {}\n    IdentityAgent {agent_path}\n    IdentitiesOnly yes\n    IdentityFile {}",
            entry.hosts.join(" "),
            ssh_path(&path)?
        )?;
    }
    ensure!(
        listed.len() + 5 <= MAX_AGENT,
        "vault identities exceed the SSH agent response limit"
    );
    let mut identity_reply = vec![IDENTITIES];
    identity_reply.extend((types.len() as u32).to_be_bytes());
    identity_reply.extend(listed);
    text.push_str("\nHost *\n");

    let tmp = p.runtime.join(CONFIG_TMP);
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    output.write_all(text.as_bytes())?;
    output.write_all(&crate::source::to_bytes(snapshot.config))?;
    output.write_all(b"\n\nHost *\n")?;
    drop(output);
    fs::rename(tmp, p.managed_config()).context("publish managed SSH configuration")?;
    if let Some(public_files) = public_files {
        let _ = public_files.keep();
    }
    Ok(Unlocked {
        types,
        identity_reply,
        activity: Mutex::new(Instant::now()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::{Algorithm, LineEnding, rand_core::OsRng};

    #[test]
    fn sign_requests_require_exact_key_and_flags() {
        let types = HashMap::from([
            (b"ed25519".to_vec(), KeyType::Ed25519),
            (b"rsa".to_vec(), KeyType::Rsa),
        ]);
        let sign = |blob: &[u8], flags: u32, trailing: &[u8]| {
            let mut data = vec![SIGN];
            put_string(&mut data, blob);
            put_string(&mut data, b"message");
            data.extend(flags.to_be_bytes());
            data.extend(trailing);
            allowed_sign(&data, &types)
        };
        assert!(sign(b"ed25519", 0, b""));
        assert!(sign(b"rsa", RSA_SHA256, b""));
        assert!(sign(b"rsa", RSA_SHA512, b""));
        assert!(!sign(b"rsa", 0, b""));
        assert!(!sign(b"rsa", RSA_SHA256 | RSA_SHA512, b""));
        assert!(!sign(b"ed25519", RSA_SHA256, b""));
        assert!(!sign(b"ed25519", 0, b"trailing"));
        assert!(!sign(b"missing", 0, b""));
    }

    #[test]
    fn published_config_contains_only_public_keys_and_resumes_user_config() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let p = Paths {
            repo: temp.path().join("vault"),
            runtime: temp.path().join("run space"),
        };
        p.prepare_runtime()?;
        let private = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)?;
        let id = Identity {
            public: private.public_key().to_openssh()?,
            fingerprint: String::new(),
            pem: private.to_openssh(LineEnding::LF)?,
            hosts: vec!["fixture.invalid".into(), "alternate.invalid".into()],
        };
        let raw_include = temp.path().join("raw.conf");
        fs::write(&raw_include, "Host fixture.invalid\n    Port 2244\n")?;
        let raw = format!(
            "Host *\nInclude \"{}\"\nMatch host not-this.invalid\n    Port 33",
            raw_include.display()
        );
        let raw = [b"# \xff\n", raw.as_bytes()].concat();
        let serialized = encode_unlock(&crate::source::from_bytes(&raw), &[id])?;
        let request = parse_unlock(&serialized[1..])?;
        let (mut socket, mut stock) = UnixStream::pair()?;
        let stock_thread = thread::spawn(move || -> Result<()> {
            deadlines(&stock, IO_TIMEOUT)?;
            let add = read_frame(&mut stock, MAX_AGENT)?;
            ensure!(add[0] == ADD, "expected an identity addition");
            send_frame(&mut stock, &[SUCCESS])?;
            Ok(())
        });
        let unlocked = load_snapshot(&p, &mut socket, request)?;
        stock_thread.join().unwrap()?;
        assert_eq!(unlocked.types.len(), 1);
        let rendered = fs::read(p.managed_config())?;
        let text = String::from_utf8_lossy(&rendered);
        assert!(text.contains("Host fixture.invalid alternate.invalid"));
        assert!(rendered.ends_with(&[raw.as_slice(), b"\n\nHost *\n"].concat()));
        assert!(!text.contains("PRIVATE KEY"));
        let user = temp.path().join("user.conf");
        let include = crate::integration::include_line(&p.managed_config())?;
        fs::write(&user, format!("{include}    ServerAliveInterval 13\n"))?;
        let output = Command::new("/usr/bin/ssh")
            .args(["-G", "-F"])
            .arg(user)
            .arg("fixture.invalid")
            .output()?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let config = String::from_utf8(output.stdout)?;
        assert!(config.contains("serveraliveinterval 13"));
        assert!(config.contains("port 2244"));
        let identity = config
            .lines()
            .find_map(|line| line.strip_prefix("identityfile "))
            .unwrap();
        let identity = fs::read_to_string(identity)?;
        assert_eq!(
            PublicKey::from_openssh(&identity)?.to_bytes()?,
            private.public_key().to_bytes()?
        );
        Ok(())
    }

    #[test]
    fn lock_waits_for_an_in_progress_publish() -> Result<()> {
        let temp = tempfile::tempdir_in("/tmp")?;
        let paths = Paths {
            repo: temp.path().join("vault"),
            runtime: temp.path().join("run"),
        };
        paths.prepare_runtime()?;
        let backend = paths.runtime.join("test.sock");
        let stock = UnixListener::bind(&backend)?;
        stock.set_nonblocking(true)?;
        let server = Arc::new(Server {
            paths,
            backend,
            idle: Duration::from_secs(30),
            closing: AtomicBool::new(false),
            stopping: AtomicBool::new(false),
            state: RwLock::new(State::default()),
        });
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)?;
        let unlock = encode_unlock(
            "Host fixture.invalid",
            &[Identity {
                pem: key.to_openssh(LineEnding::LF)?,
                public: key.public_key().to_openssh()?,
                fingerprint: String::new(),
                hosts: vec!["fixture.invalid".into()],
            }],
        )?;
        let spawn_control = |request: &[u8]| -> Result<_> {
            let (mut client, worker) = UnixStream::pair()?;
            deadlines(&client, IO_TIMEOUT)?;
            let server = server.clone();
            let worker = thread::spawn(move || control_client(worker, &server));
            send_frame(&mut client, request)?;
            Ok((client, worker))
        };
        let accept_stock = || -> Result<UnixStream> {
            let start = Instant::now();
            loop {
                match stock.accept() {
                    Ok((stream, _)) => {
                        stream.set_nonblocking(false)?;
                        deadlines(&stream, IO_TIMEOUT)?;
                        return Ok(stream);
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        ensure!(
                            start.elapsed() < IO_TIMEOUT,
                            "test backend received no request"
                        );
                        thread::sleep(TICK);
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        };

        let (mut unlock, unlocking) = spawn_control(&unlock)?;
        let mut add = accept_stock()?;
        assert_eq!(read_frame(&mut add, MAX_AGENT)?[0], ADD);
        let (mut lock, locking) = spawn_control(&[LOCK])?;
        // Loading is paused while holding the write guard; neither operation
        // can finish or expose partial configuration.
        assert!(server.state.try_write().is_err());
        assert!(!server.paths.managed_config().exists());
        send_frame(&mut add, &[SUCCESS])?;
        assert!(control_reply(&mut unlock)?.contains("unlocked"));
        let mut clear = accept_stock()?;
        assert_eq!(read_frame(&mut clear, MAX_AGENT)?.as_slice(), [CLEAR]);
        send_frame(&mut clear, &[SUCCESS])?;
        assert_eq!(control_reply(&mut lock)?, "agent locked");
        unlocking.join().unwrap()?;
        locking.join().unwrap()?;
        assert!(!server.paths.managed_config().exists());
        assert!(!server.paths.runtime.join(IDENTITY_DIR).exists());
        Ok(())
    }
}
