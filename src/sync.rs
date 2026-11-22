//! Explicit synchronization of a single encrypted file on `origin`.
//!
//! Incoming objects are inspected before any checkout or branch update. Git's
//! index is constructed without checkout or clean/smudge filters, so the bytes
//! validated by the vault parser are the bytes installed or committed.

use crate::{Paths, vault};
use anyhow::{Context, Result, ensure};
use std::{
    collections::{HashMap, HashSet, hash_map::Entry},
    fs::{self, File, OpenOptions, Permissions},
    io::{self, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};
use tempfile::{NamedTempFile, tempdir_in};

const VAULT: &str = "vault.toml";

fn git(dir: Option<&Path>) -> Command {
    let mut cmd = Command::new("git");
    if let Some(dir) = dir {
        cmd.current_dir(dir);
    }
    // Never let an enclosing Git invocation redirect us to its repository or
    // change the ancestry we inspect. Keep normal SSH/credential configuration.
    for var in [
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_COMMON_DIR",
        "GIT_CONFIG",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_PARAMETERS",
        "GIT_DIR",
        "GIT_INDEX_FILE",
        "GIT_NAMESPACE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_QUARANTINE_PATH",
        "GIT_SHALLOW_FILE",
        "GIT_WORK_TREE",
    ] {
        cmd.env_remove(var);
    }
    cmd.env("GIT_GRAFT_FILE", "/dev/null")
        .env("GIT_ALLOW_PROTOCOL", "file:git:http:https:ssh")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .args([
            "--no-pager",
            "--no-replace-objects",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.splitIndex=false",
            "-c",
            "core.sparseCheckout=false",
            "-c",
            "core.sparseCheckoutCone=false",
            "-c",
            "maintenance.auto=false",
            "-c",
            "gc.auto=0",
            "-c",
            "fetch.fsckObjects=true",
            "-c",
            "fetch.followRemoteHEAD=never",
            "-c",
            "remote.origin.followRemoteHEAD=never",
            "-c",
            "transfer.fsckObjects=true",
            "-c",
            "remote.origin.mirror=false",
            "-c",
            "push.gpgSign=false",
        ]);
    cmd
}

fn run(cmd: &mut Command, input: Option<&[u8]>) -> Result<Output> {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    if let Some(input) = input {
        let mut child = cmd
            .stdin(Stdio::piped())
            .spawn()
            .context("start Git subprocess")?;
        let written = child
            .stdin
            .take()
            .context("Git stdin unavailable")?
            .write_all(input);
        let output = child.wait_with_output()?;
        if output.status.success() {
            written?;
        }
        Ok(output)
    } else {
        cmd.stdin(Stdio::null())
            .output()
            .context("run Git subprocess")
    }
}

fn checked(output: Output, operation: &str) -> Result<Vec<u8>> {
    ensure!(
        output.status.success(),
        "git {operation} failed ({}): {}",
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(output.stdout)
}

fn line(bytes: Vec<u8>) -> Result<String> {
    let text = String::from_utf8(bytes).context("expected UTF-8 Git output")?;
    Ok(text.strip_suffix('\n').unwrap_or(&text).to_owned())
}

fn oid(text: &str) -> bool {
    matches!(text.len(), 40 | 64) && text.bytes().all(|b| b.is_ascii_hexdigit())
}

struct Repo {
    dir: PathBuf,
}

struct Head {
    branch: String,
    commit: Option<String>,
}

impl Repo {
    fn open(dir: &Path) -> Result<Self> {
        ensure!(
            fs::symlink_metadata(dir).is_ok_and(|m| m.is_dir())
                && fs::symlink_metadata(dir.join(".git")).is_ok_and(|m| m.is_dir()),
            "{} is not an sshp Git checkout; run sshp init or clone first",
            dir.display()
        );
        let repo = Self {
            dir: dir.canonicalize()?,
        };
        let git_dir = repo.text(&["rev-parse", "--git-dir"])?;
        ensure!(
            git_dir == ".git"
                && repo.text(&["rev-parse", "--is-inside-work-tree"])? == "true"
                && repo.text(&["rev-parse", "--show-prefix"])?.is_empty(),
            "{} is not the root of its own Git checkout",
            dir.display()
        );
        Ok(repo)
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut cmd = git(Some(&self.dir));
        cmd.args(args);
        cmd
    }

    fn output(&self, args: &[&str]) -> Result<Output> {
        run(&mut self.cmd(args), None)
    }

    fn checked(&self, args: &[&str]) -> Result<Vec<u8>> {
        checked(self.output(args)?, args[0])
    }

    fn text(&self, args: &[&str]) -> Result<String> {
        line(self.checked(args)?)
    }

    fn input(&self, args: &[&str], data: &[u8]) -> Result<String> {
        line(checked(run(&mut self.cmd(args), Some(data))?, args[0])?)
    }

    fn head(&self) -> Result<Head> {
        let branch = self
            .text(&["symbolic-ref", "--quiet", "HEAD"])
            .context("sshp sync requires a checked-out branch (not detached HEAD)")?;
        ensure!(
            branch.starts_with("refs/heads/") && !branch.ends_with('/'),
            "HEAD does not point at a local branch"
        );
        let out = self.output(&["rev-parse", "--verify", "--quiet", &branch])?;
        let commit = if out.status.code() == Some(1) {
            None
        } else {
            Some(line(checked(out, "rev-parse")?)?)
        };
        Ok(Head { branch, commit })
    }

    fn require_idle(&self) -> Result<()> {
        for name in [
            "MERGE_HEAD",
            "CHERRY_PICK_HEAD",
            "REVERT_HEAD",
            "rebase-apply",
            "rebase-merge",
            "sequencer",
            "BISECT_START",
        ] {
            ensure!(
                fs::symlink_metadata(self.dir.join(".git").join(name))
                    .is_err_and(|err| err.kind() == io::ErrorKind::NotFound),
                "a Git operation is in progress ({name}); finish or abort it first"
            );
        }
        Ok(())
    }

    fn check_index(&self, blob: Option<&str>) -> Result<()> {
        let expected = blob.map_or_else(String::new, |id| format!("100644 {id} 0\t{VAULT}\0"));
        ensure!(
            self.checked(&["ls-files", "--stage", "-z"])? == expected.as_bytes()
                && self.checked(&["ls-files", "-v", "-z"])?
                    == if blob.is_some() {
                        b"H vault.toml\0".as_slice()
                    } else {
                        b""
                    },
            "the Git index has staged changes, special flags, or foreign files; resolve them before syncing"
        );
        Ok(())
    }

    fn require_origin(&self, for_push: bool) -> Result<()> {
        let fetch = self
            .text(&["remote", "get-url", "--all", "origin"])
            .context("configure the 'origin' remote before syncing")?;
        ensure!(
            !fetch.is_empty() && !fetch.contains('\n'),
            "origin must have exactly one fetch URL"
        );
        if for_push {
            let push = self.text(&["remote", "get-url", "--push", "--all", "origin"])?;
            ensure!(
                fetch == push,
                "origin must use the same single URL for fetching and pushing to verify the push target"
            );
        }
        Ok(())
    }

    fn fetch(&self, branch: &str) -> Result<String> {
        // A rejected fetch may leave unreachable objects and FETCH_HEAD in
        // .git, but must not change any branch, index, or working vault.
        self.checked(&[
            "fetch",
            "--no-tags",
            "--no-prune",
            "--no-prune-tags",
            "--no-recurse-submodules",
            "--refmap=",
            "--",
            "origin",
            branch,
        ])?;
        self.text(&["rev-parse", "--verify", "FETCH_HEAD"])
    }

    fn remote_has_branch(&self, branch: &str) -> Result<bool> {
        let refs = self.text(&["ls-remote", "--refs", "--", "origin"])?;
        let found = refs.lines().any(|line| {
            line.split_once('\t')
                .is_some_and(|(_, name)| name == branch)
        });
        ensure!(
            found || refs.is_empty(),
            "origin has history but not the current branch {branch}; clone its vault instead of creating another history"
        );
        Ok(found)
    }

    fn track(&self, branch: &str, commit: &str) -> Result<()> {
        let short = branch
            .strip_prefix("refs/heads/")
            .context("invalid local branch")?;
        let tracking = format!("refs/remotes/origin/{short}");
        self.checked(&["update-ref", "--no-deref", &tracking, commit])?;
        self.checked(&[
            "config",
            "--local",
            &format!("branch.{short}.remote"),
            "origin",
        ])?;
        self.checked(&[
            "config",
            "--local",
            &format!("branch.{short}.merge"),
            branch,
        ])?;
        Ok(())
    }

    fn blob(&self, id: &str) -> Result<Vec<u8>> {
        let size: usize = self.text(&["cat-file", "-s", id])?.parse()?;
        ensure!(size <= vault::MAX_VAULT, "Git vault snapshot is too large");
        self.checked(&["cat-file", "blob", id])
    }
}

/// Ordered from tip to root. Every commit must be linear and contain exactly
/// one regular non-executable file, even if an unwanted file was later removed.
#[derive(Default)]
struct History(Vec<(String, String)>);

impl History {
    fn read(repo: &Repo, tip: Option<&str>) -> Result<Self> {
        ensure!(
            repo.text(&["rev-parse", "--is-shallow-repository"])? == "false",
            "refusing to sync a shallow Git history"
        );
        let Some(tip) = tip else {
            return Ok(Self::default());
        };
        ensure!(
            oid(tip) && repo.text(&["cat-file", "-t", tip])? == "commit",
            "invalid Git branch tip"
        );
        let commits = repo.text(&[
            "log",
            "--format=%H %T %P",
            "--no-notes",
            "--no-show-signature",
            "--no-decorate",
            "--no-color",
            tip,
            "--",
        ])?;
        let mut entries = Vec::new();
        let mut trees = HashMap::<&str, String>::new();
        let mut next = Some(tip);
        for entry in commits.lines() {
            let ids: Vec<_> = entry.split_ascii_whitespace().collect();
            ensure!(
                matches!(ids.len(), 2 | 3) && ids.iter().all(|id| oid(id)),
                "refusing a merge commit or malformed vault history"
            );
            ensure!(
                next == Some(ids[0]),
                "vault history is not linear and complete"
            );
            next = ids.get(2).copied();
            let tree = ids[1];
            if let Entry::Vacant(entry) = trees.entry(tree) {
                let contents = repo.checked(&["ls-tree", "-z", tree])?;
                let blob = contents
                    .strip_prefix(b"100644 blob ")
                    .and_then(|rest| rest.strip_suffix(b"\tvault.toml\0"))
                    .and_then(|id| std::str::from_utf8(id).ok())
                    .filter(|id| oid(id))
                    .with_context(|| {
                        format!(
                            "unsafe Git tree in {}: expected only a regular {VAULT}",
                            ids[0]
                        )
                    })?;
                entry.insert(blob.to_owned());
            }
            entries.push((ids[0].to_owned(), trees[tree].clone()));
        }
        ensure!(
            !entries.is_empty() && next.is_none(),
            "incomplete vault history"
        );
        Ok(Self(entries))
    }

    fn contains(&self, commit: &str) -> bool {
        self.0.iter().any(|(id, _)| id == commit)
    }

    fn tip_blob(&self) -> Option<&str> {
        self.0.first().map(|(_, blob)| blob.as_str())
    }

    // Don't validate already shared ancestors on every sync, but never import
    // or publish a new historical snapshot that would fail as a working vault.
    fn validate_new(&self, repo: &Repo, stop: Option<&str>) -> Result<()> {
        let mut seen = HashSet::new();
        for (commit, blob) in &self.0 {
            if stop == Some(commit.as_str()) {
                break;
            }
            if seen.insert(blob) {
                let bytes = repo.blob(blob)?;
                let candidate = temp_vault(&repo.dir.join(".git"), &bytes)?;
                vault::validate_file(candidate.path())
                    .with_context(|| format!("invalid vault snapshot in Git commit {commit}"))?;
            }
        }
        Ok(())
    }
}

fn read_vault(dir: &Path) -> Result<Option<Vec<u8>>> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(dir.join(VAULT))
    {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err).context("open working vault (must not be a symlink)"),
    };
    ensure!(
        file.metadata()?.is_file(),
        "working vault is not a regular file"
    );
    let mut bytes = Vec::new();
    file.take(vault::MAX_VAULT as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= vault::MAX_VAULT,
        "working vault is too large"
    );
    Ok(Some(bytes))
}

fn temp_vault(dir: &Path, bytes: &[u8]) -> Result<NamedTempFile> {
    let mut file = NamedTempFile::new_in(dir)?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    Ok(file)
}

fn persist(file: NamedTempFile, target: &Path) -> Result<()> {
    file.persist(target)
        .map(|_| ())
        .map_err(|err| err.error)
        .with_context(|| format!("install {}", target.display()))
}

struct IndexLock {
    path: PathBuf,
    file: File,
    committed: bool,
}

impl IndexLock {
    fn acquire(repo: &Repo) -> Result<Self> {
        let path = repo.dir.join(".git/index.lock");
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .context("lock Git index; is another Git operation running?")?;
        Ok(Self {
            path,
            file,
            committed: false,
        })
    }

    fn prepare(&mut self, repo: &Repo, commit: &str) -> Result<()> {
        // The separate, initially nonexistent index prevents read-tree from
        // touching the real index or working tree before we advance the branch.
        let dir = tempdir_in(repo.dir.join(".git"))?;
        let path = dir.path().join("index");
        let mut cmd = repo.cmd(&["read-tree", commit]);
        cmd.env("GIT_INDEX_FILE", &path);
        checked(run(&mut cmd, None)?, "read-tree")?;
        io::copy(&mut File::open(path)?, &mut self.file)?;
        self.file.sync_all()?;
        Ok(())
    }

    fn commit(&mut self, repo: &Repo) -> Result<()> {
        fs::rename(&self.path, repo.dir.join(".git/index")).context("install Git index")?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for IndexLock {
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Move the current branch and keep its index in sync. Only pull supplies a
/// working-tree replacement; push never writes to the user's working vault.
fn advance(
    repo: &Repo,
    head: &Head,
    commit: &str,
    index: &mut IndexLock,
    replacement: Option<(&[u8], Option<&[u8]>)>,
) -> Result<()> {
    index.prepare(repo, commit)?;
    let target = repo.dir.join(VAULT);
    let (candidate, backup) = if let Some((new, old)) = replacement {
        (
            Some(temp_vault(&repo.dir, new)?),
            old.map(|bytes| temp_vault(&repo.dir, bytes)).transpose()?,
        )
    } else {
        (None, None)
    };
    ensure!(
        repo.head()?.branch == head.branch,
        "current branch changed during sync"
    );
    let zero = "0".repeat(commit.len());
    let previous = head.commit.as_deref().unwrap_or(&zero);
    repo.checked(&["update-ref", "--no-deref", &head.branch, commit, previous])?;

    let mut replaced = false;
    let result = (|| {
        if let Some(candidate) = candidate {
            persist(candidate, &target)?;
            replaced = true;
        }
        index.commit(repo)
    })();
    if let Err(err) = result {
        let restore_vault = if replaced {
            match backup {
                Some(backup) => persist(backup, &target),
                None => fs::remove_file(&target).context("restore absent working vault"),
            }
        } else {
            Ok(())
        };
        let restore_ref =
            repo.checked(&["update-ref", "--no-deref", &head.branch, previous, commit]);
        restore_vault
            .with_context(|| format!("{err:#}; also failed to restore the working vault"))?;
        restore_ref.with_context(|| format!("{err:#}; also failed to restore the Git branch"))?;
        return Err(err);
    }
    Ok(())
}

/// Initialize Git around an existing vault; the first push creates its first commit.
pub fn init(p: &Paths, remote: Option<&str>) -> Result<()> {
    let _lock = p.lock_repo()?;
    ensure!(
        fs::symlink_metadata(&p.repo).is_ok_and(|m| m.is_dir())
            && fs::symlink_metadata(p.repo.join(VAULT)).is_ok_and(|m| m.is_file()),
        "no regular {VAULT} to initialize"
    );
    if let Some(url) = remote {
        ensure!(
            !url.trim().is_empty() && !url.contains(['\n', '\r']),
            "invalid Git remote URL"
        );
    }
    match fs::symlink_metadata(p.repo.join(".git")) {
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            let mut cmd = git(Some(&p.repo));
            cmd.args(["init", "--quiet", "--template="]);
            checked(run(&mut cmd, None)?, "init")?;
        }
        Ok(_) => {}
        Err(err) => return Err(err).context("inspect Git metadata"),
    }
    let repo = Repo::open(&p.repo)?;
    if let Some(url) = remote {
        let existing = repo.output(&["config", "--local", "--get", "remote.origin.url"])?;
        if existing.status.code() == Some(1) {
            repo.checked(&["remote", "add", "--", "origin", url])?;
        } else {
            ensure!(
                line(checked(existing, "config")?)? == url,
                "origin already has a different URL; refusing to replace it"
            );
        }
    }
    Ok(())
}

fn require_empty_destination(dir: &Path) -> Result<()> {
    match fs::symlink_metadata(dir) {
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).context("inspect clone destination"),
        Ok(meta) => {
            ensure!(
                meta.is_dir() && fs::read_dir(dir)?.next().transpose()?.is_none(),
                "clone destination {} is not an empty directory",
                dir.display()
            );
            Ok(())
        }
    }
}

fn clone_into(url: &str, checkout: &Path, branch: Option<&str>) -> Result<Repo> {
    let mut cmd = git(None);
    cmd.args([
        "clone",
        "--quiet",
        "--no-local",
        "--no-checkout",
        "--no-tags",
        "--single-branch",
        "--template=",
        "--origin",
        "origin",
    ]);
    if let Some(branch) = branch {
        cmd.arg(format!("--branch={branch}"));
    }
    cmd.args(["--", url]).arg(checkout);
    checked(run(&mut cmd, None)?, "clone")?;
    fs::set_permissions(checkout, Permissions::from_mode(0o700))?;
    Repo::open(checkout)
}

/// Validate a clone privately and publish it only after the entire checkout is ready.
pub fn clone_repo(p: &Paths, url: &str) -> Result<()> {
    let _lock = p.lock_repo()?;
    ensure!(
        !url.trim().is_empty() && !url.contains(['\n', '\r']),
        "invalid Git remote URL"
    );
    require_empty_destination(&p.repo)?;
    let temp = tempdir_in(
        p.repo
            .parent()
            .context("repository has no parent directory")?,
    )?;
    let mut repo = clone_into(url, &temp.path().join("repo"), None)?;
    let mut head = repo.head()?;
    // An empty bare remote may retain its default HEAD name after a push to
    // the only branch, if the client used a different init.defaultBranch.
    if head.commit.is_none() {
        let refs = repo.text(&["ls-remote", "--refs", "--", "origin", "refs/heads/*"])?;
        let mut names = refs.lines().filter_map(|line| {
            line.split_once('\t')
                .and_then(|(_, name)| name.strip_prefix("refs/heads/"))
        });
        let branch = names.next().context("remote has no vault branch")?;
        ensure!(
            names.next().is_none(),
            "remote has no unambiguous default vault branch"
        );
        repo = clone_into(url, &temp.path().join("fallback"), Some(branch))?;
        head = repo.head()?;
    }
    let tip = head
        .commit
        .as_deref()
        .context("remote has no checked-out vault branch")?;
    let history = History::read(&repo, Some(tip))?;
    history.validate_new(&repo, None)?;
    let bytes = repo.blob(history.tip_blob().context("remote is missing its vault")?)?;
    persist(temp_vault(&repo.dir, &bytes)?, &repo.dir.join(VAULT))?;
    repo.checked(&["read-tree", tip])?;
    require_empty_destination(&p.repo)?;
    fs::rename(repo.dir, &p.repo).context("install the validated vault repository")?;
    Ok(())
}

/// Display the branch and working/index status without contacting the remote.
pub fn status(p: &Paths) -> Result<()> {
    let repo = Repo::open(&p.repo)?;
    let out = repo.checked(&[
        "status",
        "--porcelain=v1",
        "--branch",
        "--ignore-submodules=all",
    ])?;
    io::stdout().lock().write_all(&out)?;
    Ok(())
}

/// Accept only a validated fast-forward, preserving unpublished local changes.
pub fn pull(p: &Paths) -> Result<()> {
    let _lock = p.lock_repo()?;
    let repo = Repo::open(&p.repo)?;
    let head = repo.head()?;
    repo.require_idle()?;
    repo.require_origin(false)?;
    let local = History::read(&repo, head.commit.as_deref())?;
    let mut index = IndexLock::acquire(&repo)?;
    repo.check_index(local.tip_blob())?;
    let fetched = repo.fetch(&head.branch)?;

    if local.contains(&fetched) {
        repo.track(&head.branch, &fetched)?;
        return Ok(());
    }
    let remote = History::read(&repo, Some(&fetched))?;
    if let Some(current) = &head.commit {
        ensure!(
            remote.contains(current),
            "local and remote vault histories have diverged; refusing to merge"
        );
    }
    let working = read_vault(&repo.dir)?;
    let candidate = repo.blob(remote.tip_blob().context("remote is missing its vault")?)?;
    let previous = local.tip_blob().map(|id| repo.blob(id)).transpose()?;
    // An unborn branch can adopt the remote only if there is no local vault
    // yet or if the vault already has exactly the incoming bytes.
    ensure!(
        working == previous
            || (head.commit.is_none() && working.as_deref() == Some(candidate.as_slice())),
        "working vault has unpublished changes; refusing to overwrite it"
    );
    remote.validate_new(&repo, head.commit.as_deref())?;
    advance(
        &repo,
        &head,
        &fetched,
        &mut index,
        Some((&candidate, working.as_deref())),
    )?;
    repo.track(&head.branch, &fetched)?;
    Ok(())
}

/// Snapshot just the vault into Git and publish the branch without force.
pub fn push(p: &Paths) -> Result<()> {
    let _lock = p.lock_repo()?;
    let repo = Repo::open(&p.repo)?;
    let head = repo.head()?;
    repo.require_idle()?;
    repo.require_origin(true)?;
    let local = History::read(&repo, head.commit.as_deref())?;
    let mut index = IndexLock::acquire(&repo)?;
    repo.check_index(local.tip_blob())?;
    let remote = if repo.remote_has_branch(&head.branch)? {
        let tip = repo.fetch(&head.branch)?;
        ensure!(
            local.contains(&tip),
            "remote is ahead or has diverged; pull before pushing (no force push)"
        );
        Some(tip)
    } else {
        None
    };
    local.validate_new(&repo, remote.as_deref())?;

    let bytes = read_vault(&repo.dir)?.context("missing working vault")?;
    let candidate = temp_vault(&repo.dir.join(".git"), &bytes)?;
    vault::validate_file(candidate.path()).context("invalid working vault; refusing to commit")?;
    let previous = local.tip_blob().map(|id| repo.blob(id)).transpose()?;
    let commit = if previous.as_deref() == Some(&bytes) {
        head.commit.clone().context("missing local vault commit")?
    } else {
        let blob = repo.input(&["hash-object", "-w", "--no-filters", "--stdin"], &bytes)?;
        let tree = repo.input(
            &["mktree"],
            format!("100644 blob {blob}\t{VAULT}\n").as_bytes(),
        )?;
        let mut args = vec![
            "commit-tree",
            &tree,
            "--no-gpg-sign",
            "-m",
            "Update encrypted vault",
        ];
        if let Some(parent) = &head.commit {
            args.extend(["-p", parent]);
        }
        let commit = repo
            .text(&args)
            .context("create vault commit; check your Git author identity")?;
        ensure!(oid(&commit), "invalid new Git commit ID");
        advance(&repo, &head, &commit, &mut index, None)?;
        commit
    };
    // Normal Git upload still enforces the fast-forward check if the remote
    // advances after our fetch. A failed transfer leaves the valid local
    // commit available for a later retry.
    repo.checked(&[
        "push",
        "--no-follow-tags",
        "--recurse-submodules=no",
        "--",
        "origin",
        &format!("{commit}:{}", head.branch),
    ])?;
    repo.track(&head.branch, &commit)?;
    Ok(())
}
