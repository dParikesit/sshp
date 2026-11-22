//! No option parser, vault access, TTY detection, prompts or environment edits.
use std::{
    env, fs, io,
    os::unix::{fs::MetadataExt, process::CommandExt},
    path::PathBuf,
    process::{Command, ExitCode},
};

fn exec() -> io::Result<()> {
    let exe = env::var_os("SSHP_OPENSSH")
        .map(PathBuf::from)
        .unwrap_or_else(|| "/usr/bin/ssh".into());
    if !exe.is_absolute() {
        return Err(io::Error::other("SSHP_OPENSSH must be an absolute path"));
    }
    let target = fs::metadata(&exe)?;
    let me = fs::metadata(env::current_exe()?)?;
    if (me.dev(), me.ino()) == (target.dev(), target.ino()) {
        return Err(io::Error::other("SSHP_OPENSSH refers to this wrapper"));
    }
    Err(Command::new(exe)
        .arg0("ssh")
        .args(env::args_os().skip(1))
        .exec())
}

fn main() -> ExitCode {
    match exec() {
        Ok(()) => unreachable!(),
        Err(e) => {
            eprintln!("sshp-ssh: {e}");
            ExitCode::from(if e.kind() == io::ErrorKind::NotFound {
                127
            } else {
                126
            })
        }
    }
}
