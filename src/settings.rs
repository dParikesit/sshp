//! Per-machine preferences: a clone must never select local credentials or lock policy.
use anyhow::{Context, Result, ensure};
use clap::{Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use std::{
    env, fs,
    io::{ErrorKind, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt},
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, ValueEnum)]
pub enum AgentLock {
    #[default]
    #[serde(rename = "15m")]
    #[value(name = "15m")]
    Minutes15,
    #[serde(rename = "1h")]
    #[value(name = "1h")]
    Hour1,
    #[serde(rename = "4h")]
    #[value(name = "4h")]
    Hours4,
    #[serde(rename = "24h")]
    #[value(name = "24h")]
    Hours24,
    #[serde(rename = "machine-lock")]
    MachineLock,
    #[serde(rename = "restart")]
    Restart,
}

#[derive(Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct Settings {
    pub age_key_file: Option<PathBuf>,
    pub agent_lock: AgentLock,
}

fn config_home() -> Result<PathBuf> {
    let dir = env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or(crate::home()?.join(".config"));
    ensure!(dir.is_absolute(), "XDG_CONFIG_HOME must be absolute");
    Ok(dir)
}

fn file() -> Result<PathBuf> {
    Ok(config_home()?.join("sshp/settings.toml"))
}

pub fn load() -> Result<Settings> {
    let path = file()?;
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Settings::default()),
        Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
    };
    let settings: Settings =
        toml::from_str(&text).with_context(|| format!("invalid settings in {}", path.display()))?;
    ensure!(
        settings
            .age_key_file
            .as_ref()
            .is_none_or(|p| p.is_absolute()),
        "age-key-file must be absolute in {}",
        path.display()
    );
    Ok(settings)
}

pub fn identity_path() -> Result<PathBuf> {
    Ok(load()?
        .age_key_file
        .unwrap_or(config_home()?.join("fnox/age.txt")))
}

#[derive(Subcommand)]
pub enum SettingsCommand {
    /// Show local settings without opening the vault
    Show,
    /// Save a setting on this machine
    Set {
        #[command(subcommand)]
        setting: Setting,
    },
}

#[derive(Subcommand)]
pub enum Setting {
    /// Local plaintext or passphrase-protected age identity file
    AgeKeyFile { path: PathBuf },
    /// Auto-lock policy (effective on the next agent start)
    AgentLock { policy: AgentLock },
}

pub fn set_identity(p: &crate::Paths, path: &Path) -> Result<()> {
    set(
        p,
        Setting::AgeKeyFile {
            path: path.to_owned(),
        },
    )
}

fn set(p: &crate::Paths, setting: Setting) -> Result<()> {
    let path = file()?;
    let dir = path.parent().unwrap();
    ensure!(
        !path.starts_with(&p.repo) && !path.starts_with(&p.runtime),
        "store sshp settings outside the vault and runtime directories"
    );
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    let meta = fs::metadata(dir)?;
    ensure!(
        meta.is_dir() && meta.uid() == unsafe { libc::geteuid() } && meta.mode() & 0o022 == 0,
        "unsafe settings directory: {}",
        dir.display()
    );
    let _lock = crate::lock_file(&dir.join(".settings.lock"))?;
    let mut settings = load()?;
    match setting {
        Setting::AgeKeyFile { path } => {
            let absolute = std::path::absolute(path)?;
            ensure!(
                absolute.is_file(),
                "age identity is not a regular file: {}",
                absolute.display()
            );
            settings.age_key_file = Some(absolute);
        }
        Setting::AgentLock { policy } => settings.agent_lock = policy,
    }
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    tmp.write_all(toml::to_string(&settings)?.as_bytes())?;
    tmp.as_file().sync_all()?;
    tmp.persist(path)?;
    Ok(())
}

pub fn run(p: &crate::Paths, cmd: SettingsCommand) -> Result<()> {
    match cmd {
        SettingsCommand::Show => {
            let mut settings = load()?;
            settings
                .age_key_file
                .get_or_insert(config_home()?.join("fnox/age.txt"));
            print!("{}", toml::to_string(&settings)?);
            Ok(())
        }
        SettingsCommand::Set { setting } => set(p, setting),
    }
}
