//! An ordinary user-config Include is the only integration with OpenSSH.
//! In particular, no synthetic `ssh -F` or global IdentityAgent override.
use anyhow::{Context, Result, ensure};
use std::{
    fs::{self, DirBuilder, OpenOptions},
    io::{ErrorKind, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::Path,
};

pub fn include_line(file: &Path) -> Result<String> {
    let s = file
        .to_str()
        .context("OpenSSH include path must be UTF-8")?;
    ensure!(
        file.is_absolute()
            && !s
                .chars()
                .any(|c| c.is_control() || "\"'\\*?[]${}%`".contains(c)),
        "include path must be absolute and free of OpenSSH expansions, globs, and quotes"
    );
    Ok(format!("Include \"{s}\"\n"))
}

pub fn install_include(file: &Path) -> Result<()> {
    let line = include_line(file)?;
    let dir = crate::home()?.join(".ssh");
    DirBuilder::new().mode(0o700).recursive(true).create(&dir)?;
    let m = fs::metadata(&dir)?;
    ensure!(
        m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o022 == 0,
        "unsafe ~/.ssh ownership or permissions"
    );
    let _lock = crate::lock_file(&dir.join(".sshp-config.lock"))?;
    let path = dir.join("config");
    let mut prev = Vec::new();
    match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)
    {
        Ok(mut f) => {
            let m = f.metadata()?;
            ensure!(
                m.is_file() && m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o022 == 0,
                "unsafe ~/.ssh/config; add the Include manually"
            );
            f.read_to_end(&mut prev)?;
        }
        Err(e) if e.kind() == ErrorKind::NotFound => (),
        Err(e) => {
            return Err(e).context("read ~/.ssh/config; for a symlink, add the Include manually");
        }
    }
    // Multiple sshp-managed includes may have been prepended over time. Do
    // not introduce duplicates: IdentityFile and other directives accumulate.
    if prev
        .split_inclusive(|b| *b == b'\n')
        .take_while(|l| l.starts_with(b"Include "))
        .any(|l| l == line.as_bytes())
    {
        return Ok(());
    }
    let mut next = tempfile::NamedTempFile::new_in(dir)?;
    next.write_all(line.as_bytes())?;
    next.write_all(&prev)?;
    next.as_file().sync_all()?;
    next.persist(path)?;
    Ok(())
}
