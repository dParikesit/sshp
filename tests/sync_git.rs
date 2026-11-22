#![cfg(unix)]

use age::secrecy::ExposeSecret;
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

struct Fixture {
    _dir: tempfile::TempDir,
    home: PathBuf,
    origin: PathBuf,
    a: PathBuf,
    b: PathBuf,
    recipient: String,
}

fn success(out: Output) -> String {
    assert!(
        out.status.success(),
        "command failed: {}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

fn failure(out: Output, expected: &str) {
    let error = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "command unexpectedly succeeded");
    assert!(error.contains(expected), "expected {expected:?} in {error}");
}

fn text(path: &Path) -> &str {
    path.to_str().unwrap()
}

impl Fixture {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        fs::create_dir(&home).unwrap();
        fs::write(home.join("gitconfig"), "[init]\n\tdefaultBranch = main\n").unwrap();
        let identity = age::x25519::Identity::generate();
        let recipient = identity.to_public().to_string();
        fs::write(
            home.join("identity"),
            identity.to_string().expose_secret().as_bytes(),
        )
        .unwrap();
        let f = Self {
            origin: tmp.path().join("origin.git"),
            a: tmp.path().join("first"),
            b: tmp.path().join("second"),
            home,
            _dir: tmp,
            recipient,
        };
        f.git(
            f._dir.path(),
            &["init", "--bare", "--initial-branch=main", text(&f.origin)],
        );
        f
    }

    fn command(&self, program: &str) -> Command {
        let mut cmd = Command::new(program);
        cmd.env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", self.home.join("gitconfig"))
            .env("GIT_AUTHOR_NAME", "sshp test")
            .env("GIT_AUTHOR_EMAIL", "sshp@example.invalid")
            .env("GIT_COMMITTER_NAME", "sshp test")
            .env("GIT_COMMITTER_EMAIL", "sshp@example.invalid")
            .env("LC_ALL", "C")
            .stdin(Stdio::null());
        // Tool shims may need HOME to find the installed fnox executable.
        for key in ["HOME", "USER", "SSHP_FNOX_BIN"] {
            if let Some(value) = std::env::var_os(key) {
                cmd.env(key, value);
            }
        }
        if let Some(value) = std::env::var_os("SSHP_TEST_FNOX") {
            cmd.env("SSHP_FNOX_BIN", value);
        }
        cmd
    }

    fn git(&self, dir: &Path, args: &[&str]) -> String {
        success(
            self.command("git")
                .current_dir(dir)
                .args(args)
                .output()
                .unwrap(),
        )
    }

    fn cli(&self, repo: &Path, args: &[&str]) -> Output {
        self.command(env!("CARGO_BIN_EXE_sshp"))
            .env("SSHP_REPO", repo)
            .env("SSHP_RUNTIME_DIR", self._dir.path().join("runtime"))
            .env("FNOX_AGE_KEY_FILE", self.home.join("identity"))
            .args(args)
            .output()
            .unwrap()
    }

    fn init(&self) {
        success(self.cli(
            &self.a,
            &[
                "init",
                "--recipient",
                &self.recipient,
                "--remote",
                text(&self.origin),
            ],
        ));
    }

    fn ready(&self) {
        self.init();
        success(self.cli(&self.a, &["push"]));
        success(self.cli(&self.b, &["clone", text(&self.origin)]));
    }

    fn edit(&self, repo: &Path, content: &str) {
        let file = self._dir.path().join("source");
        fs::write(&file, content).unwrap();
        success(self.cli(repo, &["config", "import", text(&file)]));
    }

    fn snapshot(&self, repo: &Path) -> (String, String, Vec<u8>) {
        (
            self.git(repo, &["rev-parse", "HEAD"]),
            self.git(repo, &["ls-files", "--stage"]),
            fs::read(repo.join("vault.toml")).unwrap(),
        )
    }
}

#[test]
fn vault_with_plaintext_comment_is_rejected_on_import_and_push() {
    let f = Fixture::new();
    f.init();
    success(f.cli(&f.a, &["push"]));
    let (head, index, clean) = f.snapshot(&f.a);
    let mut commented = clean.clone();
    commented.extend_from_slice(b"\n# fixture plaintext\n");
    let incoming = f._dir.path().join("incoming.toml");
    fs::write(&incoming, &commented).unwrap();

    failure(
        f.cli(&f.a, &["vault", "import", text(&incoming)]),
        "must not contain TOML comments",
    );
    assert_eq!(fs::read(f.a.join("vault.toml")).unwrap(), clean);

    fs::write(f.a.join("vault.toml"), &commented).unwrap();
    failure(f.cli(&f.a, &["push"]), "must not contain TOML comments");
    assert_eq!(f.git(&f.origin, &["rev-parse", "main"]), head);
    assert_eq!(f.snapshot(&f.a), (head, index, commented));
}

#[test]
fn git_round_trip_and_local_only_status() {
    let f = Fixture::new();
    f.init();
    assert!(success(f.cli(&f.a, &["status"])).contains("No commits yet"));

    // Untracked files are left untouched and must never appear in a commit.
    fs::write(f.a.join("local-only"), "not for Git").unwrap();
    success(f.cli(&f.a, &["push"]));
    assert_eq!(
        f.git(&f.origin, &["ls-tree", "--name-only", "main"]),
        "vault.toml\n"
    );
    assert_eq!(
        fs::read_to_string(f.a.join("local-only")).unwrap(),
        "not for Git"
    );

    fs::create_dir(&f.b).unwrap();
    success(f.cli(&f.b, &["clone", text(&f.origin)]));
    assert_eq!(f.snapshot(&f.a), f.snapshot(&f.b));
    assert_eq!(
        fs::metadata(f.b.join("vault.toml"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert!(!f.b.join("local-only").exists());

    f.edit(&f.a, "Host alice\n    HostName alice.example\n");
    success(f.cli(&f.a, &["push"]));
    assert_ne!(f.snapshot(&f.a), f.snapshot(&f.b));
    success(f.cli(&f.b, &["pull"]));
    assert_eq!(f.snapshot(&f.a), f.snapshot(&f.b));
    assert!(success(f.cli(&f.b, &["config", "export"])).contains("Host alice"));
    assert!(!success(f.cli(&f.b, &["status"])).contains(" M "));

    // Neither invoking status nor its branch display should query the remote.
    fs::rename(&f.origin, f._dir.path().join("offline.git")).unwrap();
    assert!(success(f.cli(&f.b, &["status"])).contains("origin/main"));
}

#[test]
fn dirty_and_diverged_copies_are_not_overwritten() {
    let f = Fixture::new();
    f.ready();
    f.edit(&f.a, "Host alice\n    HostName alice.example\n");
    success(f.cli(&f.a, &["push"]));
    f.edit(&f.b, "Host bob\n    HostName bob.example\n");
    let dirty = f.snapshot(&f.b);
    failure(f.cli(&f.b, &["pull"]), "unpublished changes");
    failure(f.cli(&f.b, &["push"]), "remote is ahead or has diverged");
    assert_eq!(f.snapshot(&f.b), dirty);

    f.git(&f.b, &["add", "--", "vault.toml"]);
    f.git(&f.b, &["commit", "-m", "Local edit"]);
    let diverged = f.snapshot(&f.b);
    failure(f.cli(&f.b, &["pull"]), "histories have diverged");
    failure(f.cli(&f.b, &["push"]), "remote is ahead or has diverged");
    assert_eq!(f.snapshot(&f.b), diverged);
}

#[test]
fn rejects_a_foreign_staged_file_without_consuming_the_index() {
    let f = Fixture::new();
    f.ready();
    fs::write(f.b.join("private"), "never stage this via sshp").unwrap();
    f.git(&f.b, &["add", "--", "private"]);
    let before = f.snapshot(&f.b);
    failure(f.cli(&f.b, &["push"]), "staged changes");
    failure(f.cli(&f.b, &["pull"]), "staged changes");
    assert_eq!(f.snapshot(&f.b), before);
}

#[test]
fn invalid_vault_does_not_advance_working_copy_or_publish_clone() {
    let f = Fixture::new();
    f.ready();
    let before = f.snapshot(&f.b);
    fs::write(f.a.join("vault.toml"), "invalid vault data").unwrap();
    f.git(&f.a, &["add", "--", "vault.toml"]);
    f.git(&f.a, &["commit", "-m", "Invalid snapshot"]);
    f.git(&f.a, &["push", "origin", "main"]);

    failure(f.cli(&f.b, &["pull"]), "invalid vault snapshot");
    assert_eq!(f.snapshot(&f.b), before);
    assert!(success(f.cli(&f.b, &["status"])).contains("## main...origin/main\n"));
    let rejected = f._dir.path().join("rejected");
    failure(
        f.cli(&rejected, &["clone", text(&f.origin)]),
        "invalid vault snapshot",
    );
    assert!(!rejected.exists());
}

#[test]
fn rejects_foreign_files_even_when_removed_from_tip() {
    let f = Fixture::new();
    f.ready();
    let before = f.snapshot(&f.b);
    fs::write(f.a.join("foreign"), "could have been a plaintext key").unwrap();
    f.git(&f.a, &["add", "--", "foreign"]);
    f.git(&f.a, &["commit", "-m", "Add foreign file"]);
    failure(f.cli(&f.a, &["push"]), "unsafe Git tree");
    f.git(&f.a, &["rm", "--", "foreign"]);
    f.git(&f.a, &["commit", "-m", "Remove foreign file"]);
    f.git(&f.a, &["push", "origin", "main"]);

    failure(f.cli(&f.b, &["pull"]), "unsafe Git tree");
    assert_eq!(f.snapshot(&f.b), before);
    let rejected = f._dir.path().join("rejected");
    fs::create_dir(&rejected).unwrap();
    failure(
        f.cli(&rejected, &["clone", text(&f.origin)]),
        "unsafe Git tree",
    );
    assert_eq!(fs::read_dir(rejected).unwrap().count(), 0);
}

#[test]
fn rejects_symlink_vaults_and_preserves_nonempty_clone_destination() {
    let f = Fixture::new();
    f.ready();
    let before = f.snapshot(&f.b);
    fs::remove_file(f.a.join("vault.toml")).unwrap();
    symlink("/path/which/must/not/be/used", f.a.join("vault.toml")).unwrap();
    failure(f.cli(&f.a, &["push"]), "must not be a symlink");
    f.git(&f.a, &["add", "--", "vault.toml"]);
    f.git(&f.a, &["commit", "-m", "Replace vault with symlink"]);
    f.git(&f.a, &["push", "origin", "main"]);
    failure(f.cli(&f.b, &["pull"]), "unsafe Git tree");
    failure(
        f.cli(&f.b, &["clone", text(&f.origin)]),
        "not an empty directory",
    );
    assert_eq!(f.snapshot(&f.b), before);
}

#[test]
fn clone_uses_sole_branch_if_bare_remote_head_points_nowhere() {
    let f = Fixture::new();
    f.git(&f.origin, &["symbolic-ref", "HEAD", "refs/heads/unborn"]);
    f.ready();
    assert_eq!(f.git(&f.b, &["branch", "--show-current"]), "main\n");
    f.edit(&f.b, "Host new\n    HostName new.example\n");
    success(f.cli(&f.b, &["push"]));
    success(f.cli(&f.a, &["pull"]));
    assert_eq!(f.snapshot(&f.a), f.snapshot(&f.b));
}

#[test]
fn pull_of_behind_remote_does_not_roll_back_local_commit_or_edit() {
    let f = Fixture::new();
    f.ready();
    f.edit(&f.a, "Host committed\n");
    f.git(&f.a, &["add", "--", "vault.toml"]);
    f.git(&f.a, &["commit", "-m", "Local commit"]);
    f.edit(&f.a, "Host uncommitted\n");
    let before = f.snapshot(&f.a);
    success(f.cli(&f.a, &["pull"]));
    assert_eq!(f.snapshot(&f.a), before);
    success(f.cli(&f.a, &["push"]));
    success(f.cli(&f.b, &["pull"]));
    assert!(success(f.cli(&f.b, &["config", "export"])).contains("Host uncommitted"));
}

#[test]
fn merge_commit_is_rejected_even_when_its_vault_is_valid() {
    let f = Fixture::new();
    f.ready();
    let before = f.snapshot(&f.b);
    f.git(&f.a, &["checkout", "-b", "another"]);
    f.git(&f.a, &["commit", "--allow-empty", "-m", "New branch"]);
    f.git(&f.a, &["checkout", "main"]);
    f.git(&f.a, &["merge", "--no-ff", "--no-edit", "another"]);
    failure(f.cli(&f.a, &["push"]), "merge commit");
    f.git(&f.a, &["push", "origin", "main"]);
    failure(f.cli(&f.b, &["pull"]), "merge commit");
    assert_eq!(f.snapshot(&f.b), before);
}
