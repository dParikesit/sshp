//! The portable vault is a single fnox age secret. We parse the small supported
//! subset ourselves. External key lookups use a separate, local fnox config.

use std::{
    collections::{BTreeMap, BTreeSet},
    env, fmt,
    fs::{self, File, OpenOptions},
    io::{self, IsTerminal, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use age::x25519;
use anyhow::{Context, Result, anyhow, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use clap::Subcommand;
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, MapAccess, Visitor},
};
use ssh_key::{Algorithm, HashAlg, Kdf, LineEnding, PrivateKey, PublicKey};
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

use crate::{Identity, Paths};

const FILE: &str = "vault.toml";
const VERSION: u32 = 2;
const MAX_RECORD: usize = 8 * 1024 * 1024;
pub(crate) const MAX_VAULT: usize = 12 * 1024 * 1024;
const MAX_CONFIG: usize = 1024 * 1024;
const MAX_KEY: usize = 32 * 1024;
const MAX_REFERENCE: usize = 1024;
const MAX_PASSPHRASE: usize = 4096;

// Strict outer schema: no hooks, imports, profiles, extra secrets, identity
// overrides, backend switches or executable age plugins.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    default_provider: Option<String>,
    providers: AgeProviders,
    secrets: AgeSecrets,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgeProviders {
    age: AgeProvider,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgeProvider {
    #[serde(rename = "type")]
    kind: String,
    recipients: [String; 1],
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgeSecrets {
    #[serde(rename = "SSHP_VAULT")]
    record: AgeSecret,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgeSecret {
    provider: String,
    value: String,
    #[serde(default)]
    env: Option<bool>,
}

struct Secret(Zeroizing<String>);

impl Secret {
    fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl Serialize for Secret {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        String::deserialize(deserializer).map(|value| Self(Zeroizing::new(value)))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Vault {
    version: u32,
    recipient: String,
    pub config: String,
    // Inert v1 metadata: retain until its last key is explicitly relinked.
    // Never pass imported settings, paths or commands to the local fnox resolver.
    #[serde(
        default,
        rename = "providers",
        deserialize_with = "unique_map",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    legacy_providers: BTreeMap<String, BTreeMap<String, Secret>>,
    #[serde(deserialize_with = "unique_map")]
    keys: BTreeMap<String, Key>,
}

fn unique_map<'de, D, T>(deserializer: D) -> std::result::Result<BTreeMap<String, T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Unique<T>(std::marker::PhantomData<T>);

    impl<'de, T: Deserialize<'de>> Visitor<'de> for Unique<T> {
        type Value = BTreeMap<String, T>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("an object with unique labels")
        }

        fn visit_map<A: MapAccess<'de>>(
            self,
            mut input: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            let mut output = BTreeMap::new();
            while let Some((key, value)) = input.next_entry()? {
                if output.insert(key, value).is_some() {
                    return Err(de::Error::custom("duplicate label"));
                }
            }
            Ok(output)
        }
    }

    deserializer.deserialize_map(Unique(std::marker::PhantomData))
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Key {
    public: String,
    fingerprint: String,
    hosts: Vec<String>,
    source: Source,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "type", rename_all = "snake_case")]
enum Source {
    Age { pem: Secret },
    Fnox { secret: String },
    // Read-only representation for migration; no legacy resolver.
    Provider { provider: String, reference: Secret },
}

struct Snapshot {
    recipient: x25519::Recipient,
    vault: Vault,
}

fn bounded_read(reader: impl Read, max: usize, label: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut data = Zeroizing::new(Vec::new());
    reader
        .take(max as u64 + 1)
        .read_to_end(&mut data)
        .with_context(|| format!("could not read {label}"))?;
    ensure!(data.len() <= max, "{label} is too large");
    Ok(data)
}

fn read_regular(
    path: &Path,
    max: usize,
    label: &str,
    follow_links: bool,
) -> Result<Zeroizing<Vec<u8>>> {
    let flags = libc::O_NONBLOCK | if follow_links { 0 } else { libc::O_NOFOLLOW };
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(path)
        .with_context(|| format!("could not open {label}"))?;
    ensure!(file.metadata()?.is_file(), "{label} must be a regular file");
    bounded_read(file, max, label)
}

fn parse_envelope(bytes: &[u8], from_fnox_set: bool) -> Result<(Envelope, x25519::Recipient)> {
    let text = std::str::from_utf8(bytes).map_err(|_| anyhow!("invalid vault TOML encoding"))?;
    // None of the allowlisted values need '#'. Reject comments rather than
    // preserving arbitrary plaintext in an imported or Git-synced vault.
    ensure!(!text.contains('#'), "vault must not contain TOML comments");
    let envelope: Envelope =
        toml::from_str(text).map_err(|_| anyhow!("vault is not a supported fnox age config"))?;
    let record = &envelope.secrets.record;
    ensure!(
        envelope
            .default_provider
            .as_deref()
            .is_none_or(|p| p == "age")
            && envelope.providers.age.kind == "age"
            && record.provider == "age"
            && (record.env == Some(false) || (from_fnox_set && record.env.is_none())),
        "vault is not a supported fnox age config"
    );
    let recipient: x25519::Recipient = envelope.providers.age.recipients[0]
        .parse()
        .map_err(|_| anyhow!("vault must use one native age recipient"))?;
    ensure!(
        envelope.providers.age.recipients[0] == recipient.to_string(),
        "vault must use a canonical age recipient"
    );
    let ciphertext = STANDARD
        .decode(&record.value)
        .map_err(|_| anyhow!("vault record is not valid base64"))?;
    validate_age_header(&ciphertext)?;
    Ok((envelope, recipient))
}

fn validate_age_header(ciphertext: &[u8]) -> Result<()> {
    // Only inspect stanza tags. fnox authenticates the complete age header and
    // payload. A second native recipient or a different backend is forbidden.
    let mut lines = ciphertext[..ciphertext.len().min(4096)].split(|byte| *byte == b'\n');
    ensure!(
        lines.next() == Some(b"age-encryption.org/v1"),
        "invalid vault age header"
    );
    let mut native = false;
    for line in lines {
        if line.starts_with(b"--- ") {
            ensure!(native, "vault must use one native age recipient");
            return Ok(());
        }
        if let Some(stanza) = line.strip_prefix(b"-> ") {
            let tag = stanza
                .split(|byte| *byte == b' ')
                .next()
                .unwrap_or_default();
            if tag == b"X25519" && !native {
                native = true;
            } else if !tag.ends_with(b"-grease") {
                bail!("vault must use one native age recipient");
            }
        }
    }
    bail!("invalid vault age header")
}

fn open_snapshot(bytes: &[u8]) -> Result<Snapshot> {
    open_snapshot_with_identity(bytes, crate::settings::identity_path)
}

fn open_snapshot_with_identity(
    bytes: &[u8],
    identity_path: impl FnOnce() -> Result<PathBuf>,
) -> Result<Snapshot> {
    let (envelope, recipient) = parse_envelope(bytes, false)?;
    let identity = identity_path()?;
    let meta = fs::metadata(&identity)
        .context("select your local identity with `sshp settings set age-key-file PATH`")?;
    ensure!(
        meta.is_file() && meta.len() <= 64 * 1024,
        "invalid age identity file"
    );
    let vault = Fnox::new()?.open_vault(&envelope, &recipient, &identity)?;
    ensure!(
        vault.recipient == recipient.to_string(),
        "declared age recipient does not match the encrypted vault record"
    );
    vault.validate()?;
    Ok(Snapshot { recipient, vault })
}

fn snapshot_file(path: &Path) -> Result<(Zeroizing<Vec<u8>>, Snapshot)> {
    let bytes = read_regular(path, MAX_VAULT, "vault file", false)?;
    let snapshot = open_snapshot(&bytes)?;
    Ok((bytes, snapshot))
}

fn seal(snapshot: &Snapshot) -> Result<String> {
    snapshot.vault.validate()?;
    ensure!(
        snapshot.vault.recipient == snapshot.recipient.to_string(),
        "invalid vault recipient"
    );
    let record = Zeroizing::new(
        serde_json::to_vec(&snapshot.vault)
            .map_err(|_| anyhow!("could not encode vault record"))?,
    );
    ensure!(record.len() <= MAX_RECORD, "vault record is too large");
    let isolated = Fnox::new()?;
    let config = isolated.directory.path().join(FILE);
    fs::write(
        &config,
        format!(
            "[providers.age]\ntype = \"age\"\nrecipients = [\"{}\"]\n",
            snapshot.recipient
        ),
    )
    .context("could not initialize isolated fnox config")?;
    let output = Fnox::run(
        isolated
            .command(&config, None)
            .args(["set", "SSHP_VAULT", "--provider", "age"]),
        Some(&record),
        4096,
    );
    output.context("fnox could not encrypt the vault")?;
    let bytes = read_regular(&config, MAX_VAULT, "fnox age envelope", false)?;
    let (mut envelope, recipient) = parse_envelope(&bytes, true)?;
    ensure!(
        recipient.to_string() == snapshot.vault.recipient,
        "fnox changed the age recipient"
    );
    envelope.default_provider = Some("age".into());
    envelope.secrets.record.env = Some(false);
    let text = toml::to_string(&envelope).map_err(|_| anyhow!("could not encode vault TOML"))?;
    ensure!(text.len() <= MAX_VAULT, "vault is too large");
    Ok(text)
}

struct Fnox {
    directory: tempfile::TempDir,
}

impl Fnox {
    fn new() -> Result<Self> {
        let directory = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .context("could not create an isolated fnox directory")?;
        Ok(Self { directory })
    }

    fn command(&self, config: &Path, identity: Option<&Path>) -> Command {
        let mut command =
            Command::new(env::var_os("SSHP_FNOX_BIN").unwrap_or_else(|| "fnox".into()));
        command
            .env_clear()
            .current_dir(self.directory.path())
            .env("FNOX_CONFIG_DIR", self.directory.path())
            .env("FNOX_STATE_DIR", self.directory.path())
            .env("FNOX_DATA_DIR", self.directory.path())
            .env("FNOX_PLUGINS_DIR", self.directory.path())
            .env("FNOX_AUDIT", "off")
            .env("FNOX_PROMPT_AUTH", "false")
            .env("RUST_LOG", "off")
            .args(["--no-daemon", "--no-color", "--config"])
            .arg(config)
            .stderr(Stdio::null());
        // PATH and HOME support shims such as mise. No fnox configuration,
        // identity contents, vault references or Debug settings are inherited.
        for name in ["PATH", "HOME", "USER", "XDG_DATA_HOME"] {
            if let Some(value) = env::var_os(name) {
                command.env(name, value);
            }
        }
        if let Some(identity) = identity {
            command.env("FNOX_AGE_KEY_FILE", identity);
        }
        if identity.is_some() && io::stdin().is_terminal() && io::stderr().is_terminal() {
            command.stderr(Stdio::inherit());
            if let Some(value) = env::var_os("FNOX_NON_INTERACTIVE") {
                command.env("FNOX_NON_INTERACTIVE", value);
            }
        } else {
            command.arg("--non-interactive").stdin(Stdio::null());
        }
        command
    }

    fn open_vault(
        &self,
        envelope: &Envelope,
        recipient: &x25519::Recipient,
        identity: &Path,
    ) -> Result<Vault> {
        // Anyone can encrypt a record to us while naming *their* recipient in
        // both the manifest and its payload. Before trusting that recipient for
        // future writes, prove fnox can decrypt a fresh message addressed to it.
        // Resolve both records together so fnox unlocks the identity only once.
        const CHECK: &str = "sshp recipient check";
        let probe = age::encrypt(recipient, CHECK.as_bytes())?;
        let mut config = toml::to_string(envelope)?;
        config.push_str(&format!(
            "\n[secrets.SSHP_RECIPIENT_CHECK]\nprovider = \"age\"\nenv = false\nvalue = \"{}\"\n",
            STANDARD.encode(probe)
        ));
        // This private file contains ciphertext only. Leave stdin available to
        // fnox for a terminal prompt; its plaintext stdout is a separate pipe.
        let path = self.directory.path().join(FILE);
        fs::write(&path, config)?;
        let output = Self::run(
            self.command(&path, Some(identity)).args([
                "export",
                "--format",
                "json",
                "--if-missing",
                "error",
                "SSHP_VAULT",
                "SSHP_RECIPIENT_CHECK",
            ]),
            None,
            2 * MAX_RECORD + 4096, // JSON escaping of the serialized record
        ).context("could not decrypt the vault and verify its recipient; check the age identity (a protected identity needs a terminal)")?;
        #[derive(Deserialize)]
        struct Export {
            secrets: Records,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
        struct Records {
            sshp_vault: Secret,
            sshp_recipient_check: String,
        }
        let Export { secrets } = serde_json::from_slice(&output)
            .map_err(|_| anyhow!("fnox did not return both requested vault records"))?;
        ensure!(
            secrets.sshp_recipient_check == CHECK,
            "age identity does not match the vault recipient"
        );
        let record = secrets.sshp_vault.as_str();
        ensure!(record.len() <= MAX_RECORD, "vault record is too large");
        serde_json::from_str(record).map_err(|_| anyhow!("invalid encrypted vault schema"))
    }

    fn run(command: &mut Command, input: Option<&[u8]>, max: usize) -> Result<Zeroizing<Vec<u8>>> {
        if input.is_some() {
            command.stdin(Stdio::piped());
        }
        let mut child = command
            .stdout(Stdio::piped())
            .spawn()
            .context("could not start fnox (check PATH or SSHP_FNOX_BIN)")?;
        let pipe = child.stdin.take().zip(input);
        let stdout = child.stdout.take().context("missing fnox stdout")?;
        std::thread::scope(|scope| {
            // Drain stdout while sending input to avoid a pipe deadlock.
            let writing =
                pipe.map(|(mut stdin, input)| scope.spawn(move || stdin.write_all(input)));
            let output = bounded_read(stdout, max, "fnox response");
            if output.is_err() {
                let _ = child.kill();
            }
            let status = child.wait().context("could not wait for fnox")?;
            if let Some(writing) = writing {
                writing
                    .join()
                    .map_err(|_| anyhow!("could not send fnox input"))?
                    .context("could not send fnox input")?;
            }
            let output = output?;
            ensure!(
                status.success(),
                "fnox could not resolve the requested secret"
            );
            Ok(output)
        })
    }
}

fn atomic_write(path: &Path, data: &[u8], replace: bool) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let directory = File::open(parent).context("could not open vault destination directory")?;
    let mut staging = NamedTempFile::new_in(parent).context("could not stage encrypted vault")?;
    staging
        .write_all(data)
        .context("could not write encrypted vault")?;
    staging
        .as_file()
        .sync_all()
        .context("could not sync encrypted vault")?;
    let result = if replace {
        staging.persist(path)
    } else {
        staging.persist_noclobber(path)
    };
    result.map_err(|err| {
        if err.error.kind() == io::ErrorKind::AlreadyExists {
            anyhow!("vault destination already exists")
        } else {
            anyhow!("could not publish encrypted vault: {}", err.error)
        }
    })?;
    // Publication is the commit point; not all platforms support directory fsync.
    let _ = directory.sync_all();
    Ok(())
}

fn ensure_repo_directory(p: &Paths, create: bool) -> Result<()> {
    if create {
        fs::create_dir_all(&p.repo).context("could not create vault repository")?;
    }
    ensure!(
        fs::symlink_metadata(&p.repo)
            .context("could not inspect vault repository")?
            .is_dir(),
        "vault repository must be a real directory"
    );
    Ok(())
}

pub fn init(p: &Paths, recipient: &str) -> Result<()> {
    let _lock = p.lock_repo()?;
    let recipient: x25519::Recipient = recipient
        .parse()
        .map_err(|_| anyhow!("init requires a native public age recipient (age1…)"))?;
    ensure_repo_directory(p, true)?;
    let path = p.repo.join(FILE);
    match fs::symlink_metadata(&path) {
        Ok(_) => {
            let (_, current) = snapshot_file(&path)?;
            ensure!(
                current.recipient.to_string() == recipient.to_string(),
                "vault already exists for a different age recipient"
            );
            return Ok(());
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => (),
        Err(e) => return Err(e).context("could not check for an existing vault"),
    }
    let snapshot = Snapshot {
        vault: Vault {
            version: VERSION,
            recipient: recipient.to_string(),
            config: String::new(),
            legacy_providers: BTreeMap::new(),
            keys: BTreeMap::new(),
        },
        recipient,
    };
    atomic_write(&path, seal(&snapshot)?.as_bytes(), false)
}

pub fn load(p: &Paths) -> Result<Vault> {
    ensure_repo_directory(p, false)?;
    Ok(snapshot_file(&p.repo.join(FILE))?.1.vault)
}

pub fn validate_file(file: &Path) -> Result<()> {
    snapshot_file(file).map(|_| ())
}

pub fn edit_config(p: &Paths, f: impl FnOnce(&mut String) -> Result<()>) -> Result<()> {
    mutate(p, |vault| f(&mut vault.config))
}

fn mutate(p: &Paths, f: impl FnOnce(&mut Vault) -> Result<()>) -> Result<()> {
    let _lock = p.lock_repo()?;
    ensure_repo_directory(p, false)?;
    let path = p.repo.join(FILE);
    let (_, mut snapshot) = snapshot_file(&path)?;
    f(&mut snapshot.vault)?;
    snapshot.vault.version = VERSION;
    snapshot.vault.legacy_providers.retain(|label, _| {
        snapshot.vault.keys.values().any(
            |key| matches!(&key.source, Source::Provider { provider, .. } if provider == label),
        )
    });
    atomic_write(&path, seal(&snapshot)?.as_bytes(), true)
}

fn valid_label(label: &str) -> bool {
    label.len() <= 64
        && label
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
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

fn valid_reference(text: &Secret) -> bool {
    let text = text.as_str();
    !text.is_empty() && text.len() <= MAX_REFERENCE && !text.chars().any(char::is_control)
}

fn acceptable_algorithm(algorithm: Algorithm) -> bool {
    matches!(algorithm, Algorithm::Ed25519 | Algorithm::Rsa { .. })
}

impl Vault {
    fn validate(&self) -> Result<()> {
        ensure!(
            matches!(self.version, 1 | VERSION),
            "unsupported vault schema version"
        );
        ensure!(
            self.config.len() <= MAX_CONFIG
                && !self
                    .config
                    .chars()
                    .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t')),
            "invalid vault SSH configuration"
        );
        let mut fingerprints = BTreeSet::new();
        for (name, key) in &self.keys {
            ensure!(valid_label(name), "invalid key label");
            key.validate(self)?;
            ensure!(
                fingerprints.insert(&key.fingerprint),
                "vault contains a duplicate SSH key fingerprint"
            );
        }
        Ok(())
    }

    fn new_key(&self, name: &str, key: &Key) -> Result<()> {
        ensure!(valid_label(name), "invalid key label");
        ensure!(!self.keys.contains_key(name), "key label already exists");
        ensure!(
            !self
                .keys
                .values()
                .any(|other| other.fingerprint == key.fingerprint),
            "SSH key is already registered"
        );
        Ok(())
    }
}

fn validate_secret_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty() && name.len() <= MAX_REFERENCE && !name.chars().any(char::is_control),
        "invalid fnox secret name"
    );
    Ok(())
}

fn resolve_fnox_key(secret: &str) -> Result<PrivateKey> {
    validate_secret_name(secret)?;
    // Only the name travels in the vault. Config (including imports/plugins),
    // profile selection and provider credentials are local to this client.
    let config = match env::var_os("SSHP_FNOX_CONFIG") {
        Some(path) => PathBuf::from(path),
        None => env::var_os("XDG_CONFIG_HOME")
            .filter(|p| !p.is_empty())
            .map(PathBuf::from)
            .unwrap_or(crate::home()?.join(".config"))
            .join("sshp/fnox.toml"),
    };
    ensure!(
        config.is_absolute() && config.is_file(),
        "external keys need a local fnox config: set SSHP_FNOX_CONFIG to an absolute file or create ~/.config/sshp/fnox.toml"
    );
    let mut cmd = Command::new(env::var_os("SSHP_FNOX_BIN").unwrap_or_else(|| "fnox".into()));
    if let Some(identity) = crate::settings::load()?.age_key_file {
        cmd.env("FNOX_AGE_KEY_FILE", identity);
    }
    if !(io::stdin().is_terminal() && io::stderr().is_terminal()) {
        cmd.arg("--non-interactive")
            .stdin(Stdio::null())
            .stderr(Stdio::null());
    }
    cmd.current_dir(config.parent().context("invalid fnox config path")?)
        .args(["--no-daemon", "--no-color", "--config"])
        .arg(&config)
        .args(["get", "--if-missing", "error", "--", secret]);
    let mut data = Fnox::run(&mut cmd, None, MAX_KEY + 1)
        .context("fnox key lookup failed; check the local config, profile and provider login")?;
    if data.last() == Some(&b'\n') {
        data.pop(); // fnox get appends a newline.
    }
    let key = parse_private(&data)?;
    ensure!(
        !key.is_encrypted(),
        "fnox secret must contain a private key without an SSH passphrase"
    );
    Ok(key)
}

impl Key {
    fn from_material(key: &PrivateKey, source: Source) -> Result<Self> {
        let (public, fingerprint) = public_metadata(key.public_key())?;
        Ok(Self {
            public,
            fingerprint,
            hosts: Vec::new(),
            source,
        })
    }

    fn validate(&self, vault: &Vault) -> Result<()> {
        let public = PublicKey::from_openssh(&self.public)
            .map_err(|_| anyhow!("invalid public key in vault"))?;
        let (canonical, fingerprint) = public_metadata(&public)?;
        ensure!(
            self.public == canonical && self.fingerprint == fingerprint,
            "invalid SSH public key metadata"
        );
        let mut seen = BTreeSet::new();
        for host in &self.hosts {
            ensure!(
                valid_host(host) && seen.insert(host.to_ascii_lowercase()),
                "invalid or duplicate SSH host association"
            );
        }
        match &self.source {
            Source::Age { pem } => {
                let key = parse_private(pem.as_str().as_bytes())?;
                ensure!(
                    !key.is_encrypted(),
                    "vault SSH key is unexpectedly passphrase-protected"
                );
                self.check_material(&key)?;
            }
            Source::Fnox { secret } => validate_secret_name(secret)?,
            Source::Provider {
                provider,
                reference,
            } => ensure!(
                valid_label(provider)
                    && vault.legacy_providers.contains_key(provider)
                    && valid_reference(reference),
                "invalid legacy key reference"
            ),
        }
        Ok(())
    }

    fn check_material(&self, key: &PrivateKey) -> Result<()> {
        let (public, fingerprint) = public_metadata(key.public_key())?;
        ensure!(
            self.public == public && self.fingerprint == fingerprint,
            "SSH private key does not match its pinned public key"
        );
        Ok(())
    }

    fn material(&self) -> Result<Identity> {
        let key = match &self.source {
            Source::Age { pem } => parse_private(pem.as_str().as_bytes())?,
            Source::Fnox { secret } => resolve_fnox_key(secret)?,
            Source::Provider { .. } => {
                bail!("legacy provider key; use sshp key relink LABEL --fnox-secret NAME")
            }
        };
        ensure!(
            !key.is_encrypted(),
            "provider SSH key is passphrase-protected"
        );
        self.check_material(&key)?;
        Ok(Identity {
            pem: normalized_pem(key)?,
            public: self.public.clone(),
            fingerprint: self.fingerprint.clone(),
            hosts: self.hosts.clone(),
        })
    }
}

fn public_metadata(key: &PublicKey) -> Result<(String, String)> {
    ensure!(
        acceptable_algorithm(key.algorithm()),
        "only Ed25519 and RSA SSH keys are supported"
    );
    if let Some(rsa) = key.key_data().rsa() {
        let modulus = rsa.n.as_positive_bytes().unwrap_or_default();
        let bits = modulus.first().map_or(0, |first| {
            modulus.len() * 8 - first.leading_zeros() as usize
        });
        ensure!(
            (2048..=8192).contains(&bits),
            "RSA SSH keys must have a 2048–8192 bit modulus"
        );
    }
    let mut key = key.clone();
    key.set_comment("");
    let public = key
        .to_openssh()
        .map_err(|_| anyhow!("could not encode SSH public key"))?;
    Ok((public, key.fingerprint(HashAlg::Sha256).to_string()))
}

fn parse_private(bytes: &[u8]) -> Result<PrivateKey> {
    ensure!(bytes.len() <= MAX_KEY, "SSH key is too large");
    let key = PrivateKey::from_openssh(bytes)
        .map_err(|_| anyhow!("expected an OpenSSH private key (Ed25519 or RSA)"))?;
    public_metadata(key.public_key())?;
    validate_keypair(&key)?;
    Ok(key)
}

fn validate_keypair(key: &PrivateKey) -> Result<()> {
    let Some(key) = key.key_data().rsa() else {
        return Ok(());
    };
    let component = |value: &ssh_key::Mpint| -> Result<rsa::BigUint> {
        let bytes = value
            .as_positive_bytes()
            .context("invalid RSA SSH key component")?;
        ensure!(bytes.len() <= 1024, "invalid RSA SSH key component");
        Ok(rsa::BigUint::from_bytes_be(bytes))
    };
    // ssh-key 0.6.7 only checks the RSA public record and its rsa conversion
    // duplicates p in place of q, so reconstruct and validate independently.
    let material = rsa::RsaPrivateKey::from_components(
        component(&key.public.n)?,
        component(&key.public.e)?,
        component(&key.private.d)?,
        vec![component(&key.private.p)?, component(&key.private.q)?],
    )
    .map_err(|_| anyhow!("invalid RSA SSH private key"))?;
    let expected = Zeroizing::new(component(&key.private.iqmp)?);
    ensure!(
        material.crt_coefficient().map(Zeroizing::new).as_deref() == Some(&*expected),
        "invalid RSA SSH private key CRT coefficient"
    );
    Ok(())
}

fn normalized_pem(mut key: PrivateKey) -> Result<Zeroizing<String>> {
    key.set_comment("");
    key.to_openssh(LineEnding::LF)
        .map_err(|_| anyhow!("could not encode SSH private key"))
}

pub fn unlock_material(p: &Paths) -> Result<(String, Vec<Identity>)> {
    let Vault { config, keys, .. } = load(p)?;
    let keys = keys
        .into_iter()
        .map(|(name, key)| {
            key.material()
                .with_context(|| format!("could not unlock key {name}"))
        })
        .collect::<Result<_>>()?;
    Ok((config, keys))
}

#[derive(Subcommand)]
pub enum VaultCommand {
    /// Export an encrypted, validated copy. Use - for stdout.
    Export { file: PathBuf },
    /// Verify and atomically install an encrypted vault. Use - for stdin.
    Import { file: PathBuf },
}

#[derive(Subcommand)]
pub enum KeyCommand {
    /// Import an OpenSSH private key from a file, or from stdin with -.
    Import {
        name: String,
        file: PathBuf,
        /// Read the key passphrase from stdin instead of using a hidden prompt.
        #[arg(long)]
        passphrase_stdin: bool,
    },
    /// Register a named secret from the local fnox config and pin its public key.
    Add {
        name: String,
        #[arg(long)]
        fnox_secret: String,
    },
    /// Move an existing label to a fnox secret with the same public key; keep its hosts.
    Relink {
        name: String,
        #[arg(long)]
        fnox_secret: String,
    },
    /// List key labels, fingerprints, hosts, and source types (not references).
    List,
    /// Delete a key from the vault; does not delete any external item.
    #[command(alias = "remove")]
    Delete { name: String },
    /// Associate a key (by label or SHA256 fingerprint) with literal SSH host aliases.
    Associate {
        name: String,
        #[arg(required = true, num_args = 1..)]
        hosts: Vec<String>,
    },
    /// Remove associations for a key selected by label or SHA256 fingerprint.
    Disassociate {
        name: String,
        #[arg(required = true, num_args = 1..)]
        hosts: Vec<String>,
    },
}

pub fn vault_cmd(p: &Paths, command: VaultCommand) -> Result<()> {
    match command {
        VaultCommand::Export { file } => {
            ensure_repo_directory(p, false)?;
            let (bytes, _) = snapshot_file(&p.repo.join(FILE))?;
            if file == Path::new("-") {
                io::stdout().lock().write_all(&bytes)?;
                Ok(())
            } else {
                atomic_write(&file, &bytes, false)
            }
        }
        VaultCommand::Import { file } => {
            let _lock = p.lock_repo()?;
            let bytes = if file == Path::new("-") {
                let bytes = bounded_read(io::stdin().lock(), MAX_VAULT, "encrypted vault")?;
                open_snapshot(&bytes)?;
                bytes
            } else {
                snapshot_file(&file)?.0
            };
            ensure_repo_directory(p, true)?;
            atomic_write(&p.repo.join(FILE), &bytes, true)
        }
    }
}

fn hidden(prompt: &str, stdin: bool, max: usize) -> Result<Zeroizing<String>> {
    if !stdin {
        let value = Zeroizing::new(
            rpassword::prompt_password(prompt).context("could not read hidden input")?,
        );
        ensure!(value.len() <= max, "hidden input is too large");
        return Ok(value);
    }
    let mut bytes = bounded_read(io::stdin().lock(), max + 2, "hidden input from stdin")?;
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    ensure!(bytes.len() <= max, "hidden input is too large");
    let text = std::str::from_utf8(&bytes).map_err(|_| anyhow!("hidden input must be UTF-8"))?;
    Ok(Zeroizing::new(text.to_owned()))
}

fn read_private(file: &Path, passphrase_stdin: bool) -> Result<PrivateKey> {
    let bytes = if file == Path::new("-") {
        ensure!(
            !passphrase_stdin,
            "key and passphrase cannot both be read from stdin"
        );
        bounded_read(io::stdin().lock(), MAX_KEY, "SSH key from stdin")?
    } else {
        read_regular(file, MAX_KEY, "SSH key file", true)?
    };
    let key = parse_private(&bytes)?;
    if !key.is_encrypted() {
        ensure!(!passphrase_stdin, "SSH key does not require a passphrase");
        return Ok(key);
    }
    ensure!(
        matches!(
            key.kdf(),
            Kdf::Bcrypt {
                rounds: 1..=1024,
                ..
            }
        ),
        "SSH key uses an unsupported passphrase work factor"
    );
    let passphrase = hidden("SSH key passphrase: ", passphrase_stdin, MAX_PASSPHRASE)?;
    let key = key.decrypt(passphrase.as_bytes()).map_err(|_| {
        anyhow!("could not decrypt SSH key (wrong passphrase or unsupported format)")
    })?;
    validate_keypair(&key)?;
    Ok(key)
}

pub fn key_cmd(p: &Paths, command: KeyCommand) -> Result<()> {
    match command {
        KeyCommand::Import {
            name,
            file,
            passphrase_stdin,
        } => {
            let key = read_private(&file, passphrase_stdin)?;
            let (public, fingerprint) = public_metadata(key.public_key())?;
            let pem = Secret(normalized_pem(key)?);
            mutate(p, |vault| {
                let key = Key {
                    public,
                    fingerprint,
                    hosts: Vec::new(),
                    source: Source::Age { pem },
                };
                vault.new_key(&name, &key)?;
                vault.keys.insert(name, key);
                Ok(())
            })
        }
        KeyCommand::Add { name, fnox_secret } => {
            let material = resolve_fnox_key(&fnox_secret)?;
            let key = Key::from_material(
                &material,
                Source::Fnox {
                    secret: fnox_secret,
                },
            )?;
            mutate(p, |vault| {
                vault.new_key(&name, &key)?;
                vault.keys.insert(name, key);
                Ok(())
            })
        }
        KeyCommand::Relink { name, fnox_secret } => {
            let material = resolve_fnox_key(&fnox_secret)?;
            mutate(p, |vault| {
                let key = vault.keys.get_mut(&name).context("unknown key")?;
                key.check_material(&material)?;
                key.source = Source::Fnox {
                    secret: fnox_secret,
                };
                Ok(())
            })
        }
        KeyCommand::List => {
            let vault = load(p)?;
            let mut out = io::stdout().lock();
            for (name, key) in &vault.keys {
                let source = match &key.source {
                    Source::Age { .. } => "encrypted in Git (age)",
                    Source::Fnox { .. } => "external (fnox)",
                    Source::Provider { .. } => "legacy (needs key relink)",
                };
                writeln!(
                    out,
                    "{name}\t{}\t{source}\t{}",
                    key.fingerprint,
                    key.hosts.join(",")
                )?;
            }
            Ok(())
        }
        KeyCommand::Delete { name } => mutate(p, |vault| {
            vault.keys.remove(&name).context("unknown key")?;
            Ok(())
        }),
        KeyCommand::Associate { name, hosts } => associate(p, &name, hosts, true),
        KeyCommand::Disassociate { name, hosts } => associate(p, &name, hosts, false),
    }
}

fn associate(p: &Paths, name: &str, hosts: Vec<String>, add: bool) -> Result<()> {
    ensure!(
        !hosts.is_empty() && hosts.iter().all(|host| valid_host(host)),
        "host associations must be literal SSH aliases, not patterns or options"
    );
    mutate(p, |vault| {
        let key = if name.starts_with("SHA256:") {
            vault.keys.values_mut().find(|key| key.fingerprint == name)
        } else {
            vault.keys.get_mut(name)
        }
        .context("unknown SSH key label or SHA256 fingerprint")?;
        for host in hosts {
            if let Some(index) = key.hosts.iter().position(|h| h.eq_ignore_ascii_case(&host)) {
                if !add {
                    key.hosts.remove(index);
                }
            } else if add {
                key.hosts.push(host);
            }
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::secrecy::ExposeSecret;

    fn example(recipient: x25519::Recipient) -> Snapshot {
        Snapshot {
            vault: Vault {
                version: VERSION,
                recipient: recipient.to_string(),
                config: "Host demo\n  HostName example.test\n".into(),
                legacy_providers: BTreeMap::new(),
                keys: BTreeMap::new(),
            },
            recipient,
        }
    }

    fn fake_envelope(payload: &[u8], recipients: &[x25519::Recipient]) -> Envelope {
        let enc = age::Encryptor::with_recipients(
            recipients
                .iter()
                .map(|recipient| recipient as &dyn age::Recipient),
        )
        .unwrap();
        let mut bytes = Vec::new();
        let mut writer = enc.wrap_output(&mut bytes).unwrap();
        writer.write_all(payload).unwrap();
        writer.finish().unwrap();
        Envelope {
            default_provider: Some("age".into()),
            providers: AgeProviders {
                age: AgeProvider {
                    kind: "age".into(),
                    recipients: [recipients[0].to_string()],
                },
            },
            secrets: AgeSecrets {
                record: AgeSecret {
                    provider: "age".into(),
                    value: STANDARD.encode(bytes),
                    env: Some(false),
                },
            },
        }
    }

    #[test]
    fn strict_outer_allowlist_and_single_recipient() {
        let first = x25519::Identity::generate().to_public();
        let second = x25519::Identity::generate().to_public();
        let envelope = fake_envelope(b"test", std::slice::from_ref(&first));
        let text = toml::to_string(&envelope).unwrap();
        assert!(parse_envelope(text.as_bytes(), false).is_ok());
        assert!(
            open_snapshot_with_identity(
                format!("imports = [\"/untrusted\"]\n{text}").as_bytes(),
                || panic!("an unsafe config must be rejected before calling fnox")
            )
            .is_err()
        );
        assert!(
            parse_envelope(
                text.replace("env = false", "as_file = true").as_bytes(),
                false
            )
            .is_err()
        );
        assert!(parse_envelope(text.replace("env = false", "").as_bytes(), false).is_err());
        assert!(
            parse_envelope(format!("{text}\n# fixture plaintext\n").as_bytes(), false).is_err()
        );
        let text = toml::to_string(&fake_envelope(b"test", &[first, second])).unwrap();
        assert!(parse_envelope(text.as_bytes(), false).is_err());
    }

    #[test]
    fn strict_encrypted_schema_and_literal_host_associations() {
        let snap = example(x25519::Identity::generate().to_public());
        let text = serde_json::to_string(&snap.vault).unwrap();
        assert!(
            serde_json::from_str::<Vault>(
                &text.replace("\"keys\":", "\"fnox_config\":\"/untrusted\",\"keys\":")
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<Source>(
                r#"{"type":"fnox","secret":"KEY","config":"/untrusted"}"#
            )
            .is_err()
        );
        assert!(valid_host("test-alias_1.example"));
        for invalid in [
            "-option",
            "a*",
            "!test",
            "test other",
            "a,b",
            "one\nHost evil",
        ] {
            assert!(!valid_host(invalid));
        }
    }

    #[test]
    fn fnox_roundtrip_and_recipient_binding() {
        if !Command::new(env::var_os("SSHP_FNOX_BIN").unwrap_or_else(|| "fnox".into()))
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success())
        {
            eprintln!("skipping roundtrip: fnox is not installed");
            return;
        }
        let identity = x25519::Identity::generate();
        let path = NamedTempFile::new().unwrap();
        fs::write(path.path(), identity.to_string().expose_secret()).unwrap();
        let snapshot = example(identity.to_public());
        let text = seal(&snapshot).unwrap();
        assert!(!text.contains(&snapshot.vault.config));
        let restored =
            open_snapshot_with_identity(text.as_bytes(), || Ok(path.path().into())).unwrap();
        assert_eq!(restored.vault.config, snapshot.vault.config);

        let false_claim = example(x25519::Identity::generate().to_public());
        let data = serde_json::to_vec(&false_claim.vault).unwrap();
        let text = toml::to_string(&fake_envelope(&data, &[identity.to_public()])).unwrap();
        let result = open_snapshot_with_identity(text.as_bytes(), || Ok(path.path().into()));
        assert_eq!(
            result.err().unwrap().to_string(),
            "declared age recipient does not match the encrypted vault record"
        );

        // Both claims agree, but neither is the local recipient. Simply
        // decrypting the record successfully must not authorize future writes.
        let mut envelope = fake_envelope(&data, &[identity.to_public()]);
        envelope.providers.age.recipients = [false_claim.recipient.to_string()];
        let forged = toml::to_string(&envelope).unwrap();
        assert!(open_snapshot_with_identity(forged.as_bytes(), || Ok(path.path().into())).is_err());
    }

    #[test]
    fn atomic_publish_never_clobbers_export_targets() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.toml");
        atomic_write(&path, b"old", false).unwrap();
        assert!(atomic_write(&path, b"new", false).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"old");
        atomic_write(&path, b"new", true).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"new");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
