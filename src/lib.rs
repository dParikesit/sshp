use anyhow::{Context, Result, ensure};
use std::{
    env,
    fs::{self, DirBuilder, File, OpenOptions},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

pub mod agent;
pub mod config;
pub mod integration;
mod source;
pub mod sync;
pub mod vault;

pub struct Identity {
    pub pem: Zeroizing<String>,
    pub public: String,
    pub fingerprint: String,
    pub hosts: Vec<String>,
}

#[derive(Clone)]
pub struct Paths {
    pub repo: PathBuf,
    pub runtime: PathBuf,
}

pub fn home() -> Result<PathBuf> {
    let p = PathBuf::from(env::var_os("HOME").context("HOME is not set")?);
    ensure!(p.is_absolute(), "HOME must be absolute");
    Ok(p)
}

pub fn private_dir(dir: &Path) -> Result<()> {
    DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    let meta = fs::symlink_metadata(dir)?;
    ensure!(
        meta.is_dir() && meta.uid() == unsafe { libc::geteuid() } && meta.mode() & 0o077 == 0,
        "{} must be a real directory owned by you with mode 0700",
        dir.display()
    );
    Ok(())
}

impl Paths {
    pub fn discover() -> Result<Self> {
        let repo = match env::var_os("SSHP_REPO") {
            Some(p) => PathBuf::from(p),
            None => env::var_os("XDG_DATA_HOME")
                .map(PathBuf::from)
                .unwrap_or(home()?.join(".local/share"))
                .join("sshp/vault"),
        };
        let runtime = env::var_os("SSHP_RUNTIME_DIR")
            .map(PathBuf::from)
            .unwrap_or(default_runtime()?);
        ensure!(
            repo.is_absolute() && runtime.is_absolute(),
            "vault and runtime paths must be absolute"
        );
        ensure!(
            !runtime.starts_with(&repo) && !repo.starts_with(&runtime),
            "runtime and repository must be separate"
        );
        Ok(Self { repo, runtime })
    }

    pub fn prepare_runtime(&self) -> Result<()> {
        private_dir(&self.runtime)
    }

    pub fn managed_config(&self) -> PathBuf {
        self.runtime.join("managed.conf")
    }

    /// A lock beside the repository works even before a clone exists. Closing it
    /// releases flock; never unlink a live lock (that would split the lock domain).
    pub fn lock_repo(&self) -> Result<File> {
        let parent = self
            .repo
            .parent()
            .context("repository has no parent directory")?;
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
        let mut name = self
            .repo
            .file_name()
            .context("invalid vault path")?
            .to_owned();
        name.push(".sshp.lock");
        lock_file(&parent.join(name))
    }
}

/// Use a per-user parent. A predictable Include beneath shared /tmp would
/// allow another user to claim the path after a reboot, before the first unlock.
fn default_runtime() -> Result<PathBuf> {
    let mut bases = vec![env::var_os("XDG_RUNTIME_DIR")];
    if cfg!(target_os = "macos") {
        bases.push(env::var_os("TMPDIR"));
    }
    for base in bases.into_iter().flatten().map(PathBuf::from) {
        if base.is_absolute()
            && fs::metadata(&base).is_ok_and(|m| {
                m.is_dir() && m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o077 == 0
            })
        {
            return Ok(base.join("sshp"));
        }
    }
    Ok(home()?.join(".sshp/run"))
}

pub(crate) fn lock_file(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("open lock {}", path.display()))?;
    let m = file.metadata()?;
    ensure!(
        m.is_file() && m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o077 == 0,
        "unsafe lock file"
    );
    file.lock().context("acquire exclusive lock")?;
    Ok(file)
}
