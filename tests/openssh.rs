use std::{fs, process::Command};
use tempfile::tempdir;

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
        let r = Command::new("/usr/bin/ssh").args(args).output().unwrap();
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
