use std::{
    fs,
    os::unix::fs::symlink,
    process::{Command, Stdio},
};
use tempfile::{tempdir, tempdir_in};

fn wrapper() -> std::path::PathBuf {
    // Some shell-based rustc launchers drop environment names with a dash.
    std::path::Path::new(env!("CARGO_BIN_EXE_sshp")).with_file_name("sshp-ssh")
}

#[test]
fn wrapper_is_transparent_without_a_vault() {
    let tmp = tempdir().unwrap();
    let ssh = tmp.path().join("ssh");
    symlink(wrapper(), &ssh).unwrap();
    let nonexistent = tmp.path().join("absent-vault");
    for args in [
        &["-V"][..],
        &["-Q", "key"],
        &["-F", "none", "-G", "invalid.example"],
        &["-G", "unmanaged-sshp-test.invalid"],
        &["-o", "sshp-invalid=yes"],
        &[],
    ] {
        let run = |exe| {
            Command::new(exe)
                .args(args)
                .stdin(Stdio::null())
                .env_remove("SSHP_OPENSSH")
                .env("SSHP_REPO", &nonexistent)
                .env("SSHP_RUNTIME_DIR", &nonexistent)
                .output()
                .unwrap()
        };
        let expected = run(std::path::Path::new("/usr/bin/ssh"));
        assert_eq!(run(&ssh), expected, "ssh {args:?}");
        assert!(!nonexistent.exists());
    }
}

#[test]
fn recursion_via_hardlink_is_rejected() {
    let tmp = tempdir_in(wrapper().parent().unwrap()).unwrap();
    let hardlink = tmp.path().join("ssh");
    fs::hard_link(wrapper(), &hardlink).unwrap();
    let result = Command::new(wrapper())
        .env("SSHP_OPENSSH", hardlink)
        .arg("-V")
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(126));
    assert!(result.stdout.is_empty());
    assert!(String::from_utf8_lossy(&result.stderr).contains("this wrapper"));
}

#[test]
fn native_include_preserves_user_bytes_and_openssh_precedence() {
    let home = tempdir().unwrap();
    let runtime = home.path().join("run dir");
    let user = home.path().join(".ssh/config");
    let managed = runtime.join("managed.conf");
    fs::create_dir(home.path().join(".ssh")).unwrap();
    let original = b"# existing comments\r\nHost fixture\n  Port 44\n  IdentityFile /user.pub\nHost *\n ServerAliveInterval 9\n";
    fs::write(&user, original).unwrap();
    for _ in 0..2 {
        let r = Command::new(env!("CARGO_BIN_EXE_sshp"))
            .env("HOME", home.path())
            .env("SSHP_RUNTIME_DIR", &runtime)
            .env("SSHP_REPO", home.path().join("vault"))
            .args(["install-config", "--apply"])
            .output()
            .unwrap();
        assert!(r.status.success(), "{r:?}");
    }
    assert_eq!(
        fs::read(&user).unwrap(),
        [
            format!("Include \"{}\"\n", managed.display()).as_bytes(),
            original,
        ]
        .concat()
    );
    fs::write(
        &managed,
        "Host fixture\n Port 33\n IdentityFile /managed.pub\n",
    )
    .unwrap();
    let g = |args: &[&str]| {
        let r = Command::new(wrapper())
            .env_remove("SSHP_OPENSSH")
            .args(args)
            .output()
            .unwrap();
        assert!(r.status.success(), "{r:?}");
        String::from_utf8(r.stdout).unwrap()
    };
    let file = user.to_str().unwrap();
    let effective = g(&[
        "-G",
        "-F",
        file,
        "-o",
        "IdentityFile=/one.pub",
        "-i",
        "/dev/null",
        "-i",
        file,
        "fixture",
    ]);
    let identities: Vec<_> = effective
        .lines()
        .filter_map(|s| s.strip_prefix("identityfile "))
        .collect();
    assert_eq!(
        identities,
        ["/one.pub", "/dev/null", file, "/managed.pub", "/user.pub"]
    );
    assert!(effective.lines().any(|s| s == "port 33"));
    assert!(effective.lines().any(|s| s == "serveraliveinterval 9"));
    assert!(
        g(&["-G", "-F", file, "-p", "55", "fixture"])
            .lines()
            .any(|s| s == "port 55")
    );
    assert!(!g(&["-G", "-F", "none", "fixture"]).contains("/managed.pub"));
}
