//! Treat the SSH config as source code, not as evaluated OpenSSH settings.
//! Import/export preserve the source bytes verbatim. Only `Host` and `Match`
//! start new blocks; comments and unknown options travel with the block that
//! contains them. We never run `ssh -G` (which can run `Match exec`).

use crate::{Paths, integration, vault};
use anyhow::{Context, Result, ensure};
use clap::Subcommand;
use std::{
    borrow::Cow,
    collections::BTreeSet,
    fs::{self, DirBuilder, Metadata, OpenOptions, Permissions},
    io::{self, ErrorKind, Read, Write},
    ops::Range,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

mod editor;
pub use editor::tui;

#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Replace the encrypted config with a source file (default: ~/.ssh/config).
    Import {
        /// Read from this file, or use "-" for standard input.
        file: Option<PathBuf>,
    },
    /// List numbered source blocks, including global options and shared blocks.
    List,
    /// Print the complete original text, or preview explicitly selected blocks.
    Export {
        /// One or more block numbers from `config list`, in any order.
        #[arg(long, value_name = "N", value_delimiter = ',')]
        entry: Vec<usize>,
        /// Write selected blocks in plaintext to ~/.ssh/sshp-selected.conf.
        #[arg(long, requires = "entry")]
        install: bool,
        /// Also add the corresponding Include to ~/.ssh/config.
        #[arg(long, requires = "install")]
        include: bool,
    },
}

pub fn config_cmd(p: &Paths, c: ConfigCommand) -> Result<()> {
    match c {
        ConfigCommand::Import { file } => {
            let file = match file {
                Some(file) => file,
                None => crate::home()?.join(".ssh/config"),
            };
            let bytes = if file == Path::new("-") {
                let mut bytes = Vec::new();
                io::stdin()
                    .lock()
                    .read_to_end(&mut bytes)
                    .context("read SSH config from stdin")?;
                bytes
            } else {
                fs::read(&file)
                    .with_context(|| format!("read SSH config from {}", file.display()))?
            };
            let text = crate::source::from_bytes(&bytes);
            vault::edit_config(p, |config| {
                *config = text;
                Ok(())
            })
        }
        ConfigCommand::List => {
            let config = vault::load(p)?.config;
            let mut out = io::stdout().lock();
            for (i, block) in blocks(&config).iter().enumerate() {
                writeln!(out, "{}\t{}", i + 1, visible(&block.label(&config)))?;
            }
            Ok(())
        }
        ConfigCommand::Export {
            entry,
            install,
            include,
        } => {
            ensure!(!include || install, "--include requires --install");
            let config = vault::load(p)?.config;
            if entry.is_empty() {
                ensure!(!install, "--install requires explicit --entry selections");
                return Ok(io::stdout()
                    .lock()
                    .write_all(&crate::source::to_bytes(&config))?);
            }
            let preview = Selection::new(&config, &entry.into_iter().collect())?;
            let mut notes = io::stderr().lock();
            for warning in &preview.warnings {
                writeln!(notes, "warning: {warning}")?;
            }
            if install {
                writeln!(notes, "{}", preview.install(include)?)?;
            } else {
                writeln!(
                    notes,
                    "Proposed Include (not installed): {}",
                    preview.include_line.trim_end()
                )?;
                io::stdout()
                    .lock()
                    .write_all(&crate::source::to_bytes(&preview.text))?;
            }
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Global,
    Host,
    Match,
}

#[derive(Clone, Debug)]
struct Block {
    kind: Kind,
    range: Range<usize>,
}

impl Block {
    fn text<'a>(&self, config: &'a str) -> &'a str {
        &config[self.range.clone()]
    }

    fn header_arg<'a>(&self, config: &'a str) -> &'a str {
        let line = first_line(self.text(config));
        directive(line).map_or("", |d| &line[d.value])
    }

    fn shared_host(&self, config: &str) -> bool {
        if self.kind != Kind::Host {
            return false;
        }
        let value = self.header_arg(config);
        value.split_ascii_whitespace().count() != 1 || value.contains(['*', '?', '!'])
    }

    fn label(&self, config: &str) -> String {
        match self.kind {
            Kind::Global => "Global (preamble)".into(),
            Kind::Host => {
                let value = self.header_arg(config);
                let suffix = if self.shared_host(config) {
                    "  [shared]"
                } else {
                    ""
                };
                format!("Host {value}{suffix}")
            }
            Kind::Match => {
                let value = self.header_arg(config);
                format!("Match {value}  [shared]")
            }
        }
    }
}

fn blocks(config: &str) -> Vec<Block> {
    let mut blocks = Vec::new();
    let mut kind = Kind::Global;
    let mut start = 0;
    let mut pos = 0;
    for line in config.split_inclusive('\n') {
        let key = keyword(line);
        let next = if key.eq_ignore_ascii_case("Host") {
            Some(Kind::Host)
        } else if key.eq_ignore_ascii_case("Match") {
            Some(Kind::Match)
        } else {
            None
        };
        if let Some(next) = next {
            if start != pos {
                blocks.push(Block {
                    kind,
                    range: start..pos,
                });
            }
            kind = next;
            start = pos;
        }
        pos += line.len();
    }
    if start != pos {
        blocks.push(Block {
            kind,
            range: start..pos,
        });
    }
    blocks
}

fn first_line(s: &str) -> &str {
    s.split_inclusive('\n').next().unwrap_or("")
}

fn line_ending(s: &str) -> &'static str {
    if first_line(s).ends_with("\r\n") {
        "\r\n"
    } else {
        "\n"
    }
}

fn separator(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\r' | '\n')
}

fn keyword_span(line: &str) -> (Cow<'_, str>, Range<usize>) {
    let content = line.trim_start_matches(separator);
    let start = line.len() - content.len();
    let delimiter = content
        .find(|c| separator(c) || matches!(c, '=' | '"'))
        .unwrap_or(content.len());
    if content[delimiter..].starts_with('"') {
        // OpenSSH's first-token parser joins an unquoted prefix with the
        // following double-quoted fragment, e.g. `"Host"` or `Ho"st"`.
        let remainder = &content[delimiter + 1..];
        let Some(close) = remainder.find('"') else {
            return (Cow::Borrowed(""), start..start);
        };
        let prefix = &content[..delimiter];
        let quoted = &remainder[..close];
        let key = if prefix.is_empty() {
            Cow::Borrowed(quoted)
        } else if quoted.is_empty() {
            Cow::Borrowed(prefix)
        } else {
            Cow::Owned(format!("{prefix}{quoted}"))
        };
        (key, start..start + delimiter + close + 2)
    } else {
        (
            Cow::Borrowed(&content[..delimiter]),
            start..start + delimiter,
        )
    }
}

fn keyword(line: &str) -> Cow<'_, str> {
    keyword_span(line).0
}

struct Directive<'a> {
    name: Cow<'a, str>,
    key: Range<usize>,
    value: Range<usize>,
}

/// Find a line's argument span. A # starts a comment only where an unquoted
/// argument could begin. Never normalize text outside the edited argument.
fn directive(line: &str) -> Option<Directive<'_>> {
    let (name, key) = keyword_span(line);
    if name.is_empty() || name.starts_with('#') {
        return None;
    }
    let tail = line[key.end..].trim_start_matches(separator);
    // With a quoted keyword, OpenSSH does not consume an equals separator.
    let has_equals = !line[..key.end].ends_with('"') && tail.starts_with('=');
    let tail = if has_equals { &tail[1..] } else { tail };
    let args = tail
        .trim_start_matches(separator)
        .trim_end_matches(|c| separator(c) || c == '\x0c');
    let mut start = line.len() - tail.trim_start_matches(separator).len();
    if args.is_empty() {
        // Leave whitespace and CRLF on an empty directive as a suffix.
        start = if has_equals {
            line.len() - tail.len()
        } else {
            key.end
        };
    }
    let mut quote = None;
    let mut at_boundary = true;
    let mut end = 0;
    let mut chars = args.char_indices().peekable();
    while let Some((_, ch)) = chars.next() {
        match ch {
            '\\' => {
                if chars.peek().is_some_and(|(_, next)| {
                    matches!(next, '\\' | '\'' | '"') || (quote.is_none() && *next == ' ')
                }) {
                    chars.next();
                }
                at_boundary = false;
            }
            '\'' | '"' if quote.is_none() => {
                quote = Some(ch);
                at_boundary = false;
            }
            ch if quote == Some(ch) => quote = None,
            '#' if quote.is_none() && at_boundary => break,
            ch => at_boundary = quote.is_none() && matches!(ch, ' ' | '\t'),
        }
        if !at_boundary {
            end = chars.peek().map_or(args.len(), |(i, _)| *i);
        }
    }
    Some(Directive {
        name,
        key,
        value: start..start + end,
    })
}

// Sanitize terminal display without changing the source or exported bytes.
fn visible(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '\t' => out.push_str("    "),
            c if c.is_control()
                || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}') =>
            {
                out.push('�');
            }
            c => out.push(c),
        }
    }
    out
}

fn append_block(doc: &mut String, block: &str, eol: &str) {
    if !block.is_empty() {
        if !doc.is_empty() && !doc.ends_with('\n') {
            doc.push_str(eol);
        }
        doc.push_str(block);
    }
}

fn move_block(config: &str, from: usize, to: usize) -> Option<String> {
    let mut blocks = blocks(config);
    if from == to || blocks.get(from)?.kind == Kind::Global || blocks.get(to)?.kind == Kind::Global
    {
        return None;
    }
    let moved = blocks.remove(from);
    blocks.insert(to, moved);
    let mut doc = String::with_capacity(config.len());
    for block in blocks {
        append_block(&mut doc, block.text(config), line_ending(config));
    }
    Some(doc)
}

fn replace_block(config: &mut String, index: usize, mut raw: String) -> Result<()> {
    let current = blocks(config);
    let block = current.get(index).context("block is no longer present")?;
    let replacement = blocks(&raw);
    if block.kind == Kind::Global {
        ensure!(
            replacement.iter().all(|b| b.kind == Kind::Global),
            "edit the full config to add Host or Match blocks to the preamble"
        );
    } else {
        ensure!(
            replacement.len() == 1 && replacement[0].kind != Kind::Global,
            "an entry must start with Host or Match and contain exactly one block; use full raw to change the structure"
        );
    }
    if block.range.end < config.len() && !raw.is_empty() && !raw.ends_with('\n') {
        raw.push_str(line_ending(block.text(config)));
    }
    config.replace_range(block.range.clone(), &raw);
    Ok(())
}

const FIELDS: [&str; 5] = ["Host", "HostName", "User", "Port", "IdentityFile"];

fn form_values(block: &str) -> [String; FIELDS.len()] {
    FIELDS.map(|field| {
        block
            .split_inclusive('\n')
            .find(|line| keyword(line).eq_ignore_ascii_case(field))
            .and_then(|line| directive(line).map(|d| line[d.value].to_owned()))
            .unwrap_or_default()
    })
}

fn apply_form(block: &str, values: [&str; FIELDS.len()], fallback_eol: &str) -> Result<String> {
    let old = form_values(block);
    let mut changes = [false; FIELDS.len()];
    let mut value = values;
    for (i, field) in FIELDS.into_iter().enumerate() {
        if value[i] == old[i] {
            continue;
        }
        value[i] = value[i].trim_matches([' ', '\t']);
        changes[i] = value[i] != old[i];
        let valid = |v: &str| {
            !v.is_empty()
                && !v.starts_with('=')
                && !v
                    .chars()
                    .any(|c| c.is_whitespace() || c.is_control() || "'\"#\\".contains(c))
        };
        if i == 0 {
            ensure!(
                !value[i].is_empty()
                    && value[i]
                        .split([' ', '\t'])
                        .filter(|v| !v.is_empty())
                        .all(valid),
                "enter one or more simple Host patterns separated by spaces; use raw for quoting"
            );
        } else if !value[i].is_empty() {
            if field == "Port" {
                ensure!(
                    value[i].bytes().all(|c| c.is_ascii_digit())
                        && value[i].parse::<u16>().is_ok_and(|n| n > 0),
                    "Port must be between 1 and 65535"
                );
            } else {
                ensure!(
                    valid(value[i]),
                    "{field} must be a single unquoted value; use raw for quoting"
                );
            }
        }
    }

    let mut updated = String::with_capacity(block.len());
    for line in block.split_inclusive('\n') {
        if let Some((i, d)) = directive(line).and_then(|d| {
            FIELDS
                .iter()
                .position(|key| d.name.eq_ignore_ascii_case(key))
                .filter(|&i| changes[i])
                .map(|i| (i, d))
        }) {
            if value[i].is_empty() {
                // Keep indentation, inline comment, and line ending.
                updated.push_str(&line[..d.key.start]);
            } else {
                updated.push_str(&line[..d.value.start]);
                if d.value.start == d.key.end && d.value.is_empty() {
                    updated.push(' ');
                }
                updated.push_str(value[i]);
                if d.value.is_empty() && line[d.value.end..].starts_with('#') {
                    updated.push(' ');
                }
            }
            updated.push_str(&line[d.value.end..]);
            changes[i] = false;
        } else {
            updated.push_str(line);
        }
    }

    let header = first_line(&updated);
    let at = header.len();
    let terminated = header.ends_with('\n');
    let eol = if terminated {
        line_ending(header)
    } else {
        fallback_eol
    };
    let mut extra = String::new();
    for (i, field) in FIELDS.into_iter().enumerate().skip(1) {
        if changes[i] && !value[i].is_empty() {
            if !terminated {
                extra.push_str(eol);
            }
            extra.push_str(&format!("    {field} {}", value[i]));
            if terminated {
                extra.push_str(eol);
            }
        }
    }
    updated.insert_str(at, &extra);
    Ok(updated)
}

const MANAGED_HEADER: &str = "# sshp-managed selected SSH config; replace through sshp.\n";
const SELECTED_FILE: &str = "sshp-selected.conf";
const PRECEDENCE_WARNING: &str = "OpenSSH uses the first value for most options; some options accumulate. Review Include order if the runtime config is also included.";
const AGENT_WARNING: &str = "This export does not contain vaulted keys or runtime key associations; it stays on disk when the agent locks.";
const INCLUDE_WARNING: &str =
    "An existing Include or glob can activate this file as soon as it is installed.";

struct Selection {
    text: String,
    warnings: Vec<&'static str>,
    file: PathBuf,
    include_line: String,
}

impl Selection {
    fn new(config: &str, entries: &BTreeSet<usize>) -> Result<Self> {
        let (text, warnings) = selected_text(config, entries)?;
        let file = crate::home()?.join(".ssh").join(SELECTED_FILE);
        let include_line = integration::include_line(&file)?;
        Ok(Self {
            text,
            warnings,
            file,
            include_line,
        })
    }

    fn install(&self, include: bool) -> Result<String> {
        write_selected(&self.file, &self.text)?;
        if include {
            integration::install_include(&self.file).with_context(|| {
                format!(
                    "plaintext was installed at {}, but the user Include was not updated",
                    self.file.display()
                )
            })?;
            Ok(format!(
                "Installed plaintext at {} and ensured its Include in ~/.ssh/config.",
                self.file.display()
            ))
        } else {
            Ok(format!(
                "Installed plaintext at {}. Did not edit ~/.ssh/config; review and add: {}",
                self.file.display(),
                self.include_line.trim_end()
            ))
        }
    }
}

fn has_option(block: &str, names: &[&str]) -> bool {
    block.split_inclusive('\n').any(|line| {
        let key = keyword(line);
        names.iter().any(|name| key.eq_ignore_ascii_case(name))
    })
}

fn selected_text(config: &str, entries: &BTreeSet<usize>) -> Result<(String, Vec<&'static str>)> {
    let blocks = blocks(config);
    ensure!(!entries.is_empty(), "select at least one block");
    for &n in entries {
        ensure!(
            n >= 1 && n <= blocks.len(),
            "block {n} not found; use `sshp config list`"
        );
    }

    let mut text = MANAGED_HEADER.to_owned();
    let mut warnings = Vec::new();
    let mut omitted_global = false;
    let mut omitted_scopes = false;
    let mut included_shared = false;
    let mut included_paths = false;
    let mut included_jump = false;
    let mut included_file = false;
    let mut omitted_file = false;
    let mut included_match = false;
    for (index, block) in blocks.iter().enumerate() {
        let raw = block.text(config);
        let has_include = has_option(raw, &["Include"]);
        if entries.contains(&(index + 1)) {
            text.push_str(raw);
            included_file |= has_include;
            included_match |= block.kind == Kind::Match;
            included_shared |=
                (block.kind == Kind::Global && directive_lines(raw)) || block.shared_host(config);
            included_jump |= has_option(raw, &["ProxyJump"]);
            included_paths |= has_option(
                raw,
                &[
                    "CertificateFile",
                    "ControlPath",
                    "GlobalKnownHostsFile",
                    "IdentityAgent",
                    "IdentityFile",
                    "KnownHostsCommand",
                    "LocalCommand",
                    "LocalForward",
                    "PKCS11Provider",
                    "ProxyCommand",
                    "RemoteCommand",
                    "RemoteForward",
                    "SecurityKeyProvider",
                    "UserKnownHostsFile",
                ],
            );
        } else {
            omitted_global |= block.kind == Kind::Global && directive_lines(raw);
            omitted_scopes |= block.kind != Kind::Global;
            omitted_file |= has_include;
        }
    }
    if omitted_global {
        warnings
            .push("Global options were omitted; select the preamble if these blocks depend on it.");
    }
    if omitted_scopes {
        warnings.push("Omitted Host or Match blocks may also apply to the selected hosts; review defaults and precedence.");
    }
    if included_shared {
        warnings.push("Selected global options or shared Host patterns can also affect hosts you did not intend to export.");
    }
    if included_match {
        warnings.push("Selected Match conditions are not evaluated here and may affect other hosts or execute local commands.");
    }
    if included_file {
        warnings.push("Selected Include directives are copied, not expanded; their referenced files are not exported.");
    }
    if omitted_file {
        warnings.push("An omitted block contains Include directives that may supply options or additional hosts.");
    }
    if included_jump {
        warnings.push("ProxyJump may depend on other aliases or SSH settings; explicitly select any needed blocks.");
    }
    if included_paths {
        warnings.push("Paths, sockets and commands are copied literally; their files, keys and programs are not exported.");
    }
    warnings.extend([AGENT_WARNING, INCLUDE_WARNING, PRECEDENCE_WARNING]);
    Ok((text, warnings))
}

fn directive_lines(block: &str) -> bool {
    block.split_inclusive('\n').any(|s| {
        let key = keyword(s);
        !key.is_empty() && !key.starts_with('#')
    })
}

fn ssh_dir(path: &Path) -> Result<()> {
    match DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e).with_context(|| format!("create {}", path.display())),
    }
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.is_dir() && meta.uid() == unsafe { libc::geteuid() } && meta.mode() & 0o022 == 0,
        "{} must be a real directory owned by you and not writable by other users",
        path.display()
    );
    Ok(())
}

fn selected_metadata(path: &Path) -> Result<Option<Metadata>> {
    let mut current = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("open existing {}", path.display())),
    };
    let meta = current.metadata()?;
    ensure!(
        meta.is_file()
            && meta.uid() == unsafe { libc::geteuid() }
            && meta.nlink() == 1
            && meta.mode() & 0o077 == 0,
        "refusing to replace unsafe existing {}",
        path.display()
    );
    let mut header = [0; MANAGED_HEADER.len()];
    ensure!(
        current.read_exact(&mut header).is_ok() && header == MANAGED_HEADER.as_bytes(),
        "refusing to replace {}; it is not an sshp-managed selected export",
        path.display()
    );
    Ok(Some(meta))
}

fn write_selected(path: &Path, text: &str) -> Result<()> {
    ensure!(
        text.starts_with(MANAGED_HEADER),
        "missing selected export marker"
    );
    let dir = path
        .parent()
        .context("selected export has no parent directory")?;
    ssh_dir(dir)?;
    let _lock = crate::lock_file(&dir.join(".sshp-selected.lock"))?;
    let old = selected_metadata(path)?;
    let mut next = tempfile::NamedTempFile::new_in(dir)?;
    next.as_file()
        .set_permissions(Permissions::from_mode(0o600))?;
    next.write_all(&crate::source::to_bytes(text))?;
    next.as_file().sync_all()?;
    if let Some(old) = old {
        let current = selected_metadata(path)?;
        ensure!(
            current.is_some_and(|m| (m.dev(), m.ino()) == (old.dev(), old.ino())),
            "{} changed while preparing the export; retry",
            path.display()
        );
        next.persist(path)?;
    } else {
        next.persist_noclobber(path)?;
    }
    let _ = fs::File::open(dir).and_then(|dir| dir.sync_all());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn source_partition_round_trips_mixed_endings_and_unknown_options() {
        let config = "# 説明\r\n Include local.d/*\r\n\r\n\
                      \tHoSt = test !bad # comment\r\n\tUnrecognized value\n\
                      # stays with previous block\n\
                      \"Match\" all\n\tUser backup\n\
                      Ho\"st\" last\n\tPort 2222";
        let blocks = blocks(config);
        assert_eq!(
            blocks.iter().map(|b| b.kind).collect::<Vec<_>>(),
            [Kind::Global, Kind::Host, Kind::Match, Kind::Host]
        );
        assert_eq!(
            blocks.iter().map(|b| b.text(config)).collect::<String>(),
            config
        );
        assert_eq!(blocks[1].label(config), "Host test !bad  [shared]");
        assert!(
            blocks[1]
                .text(config)
                .ends_with("# stays with previous block\n")
        );
        assert_eq!(blocks[3].label(config), "Host last");
    }

    #[test]
    fn form_changes_only_first_argument_and_keeps_unmodified_syntax() {
        let original = "Host = \"test\" # hosts\r\n\
                        \tHostName\t=  example.org  # inline\r\n\
                        \tUser 'a # b'\r\n\
                        \tIdentityFile ~/.ssh/key#1\r\n\
                        \tIdentityFile ~/.ssh/key2\r\n\
                        \tUser duplicate\r\n\
                        \tSomethingUnknown x";
        let old = form_values(original);
        assert_eq!(old[2], "'a # b'");
        assert_eq!(old[4], "~/.ssh/key#1");
        assert_eq!(
            apply_form(original, old.each_ref().map(String::as_str), "\n").unwrap(),
            original
        );
        let edited = apply_form(
            original,
            [
                "\"test\"",
                "new.example.org",
                "'a # b'",
                "2200",
                "~/.ssh/other",
            ],
            "\n",
        )
        .unwrap();
        assert_eq!(
            edited,
            original
                .replace("  example.org", "  new.example.org")
                .replace("~/.ssh/key#1", "~/.ssh/other")
                .replace("# hosts\r\n", "# hosts\r\n    Port 2200\r\n")
        );
        assert!(apply_form(original, ["test", "", "x\nHost *", "", ""], "\n").is_err());
        assert!(apply_form(original, ["test", "", "", "65536", ""], "\n").is_err());
    }

    #[test]
    fn form_preserves_comments_when_clearing_and_can_fill_empty_args() {
        let original = "Host test\r\n\tHostName # empty\r\n\tUser old # keep\r\nPort= \t\r\n";
        assert_eq!(
            apply_form(original, ["test", "example.org", "", "2222", ""], "\n").unwrap(),
            "Host test\r\n\tHostName example.org # empty\r\n\t # keep\r\nPort=2222 \t\r\n"
        );
        assert_eq!(
            apply_form("Host test", ["test", "example.org", "me", "", ""], "\r\n").unwrap(),
            "Host test\r\n    HostName example.org\r\n    User me"
        );
    }

    #[test]
    fn recognizes_escaped_spaces_before_an_inline_comment() {
        let line = "IdentityFile ~/a\\  # inline\n";
        assert_eq!(&line[directive(line).unwrap().value], "~/a\\ ");
    }

    #[test]
    fn reorders_shared_scopes_without_moving_implicit_global_preamble() {
        let config = "User defaults\r\nHost work\r\n\tPort 23\r\nHost *\r\n\tPort 24\r\nMatch all";
        assert!(move_block(config, 1, 0).is_none());
        assert_eq!(
            move_block(config, 3, 1).unwrap(),
            "User defaults\r\nMatch all\r\nHost work\r\n\tPort 23\r\nHost *\r\n\tPort 24\r\n"
        );
        assert_eq!(
            move_block(config, 2, 1).unwrap(),
            "User defaults\r\nHost *\r\n\tPort 24\r\nHost work\r\n\tPort 23\r\nMatch all"
        );
    }

    #[test]
    fn raw_entry_changes_do_not_spill_into_adjacent_entries() {
        let original = "User defaults\r\nHost a\r\nHost b\r\nHost c";
        let mut config = original.to_owned();
        assert!(replace_block(&mut config, 1, "Host x\nHost y".into()).is_err());
        assert!(replace_block(&mut config, 1, "# comment\nHost x".into()).is_err());
        assert!(replace_block(&mut config, 0, "Match all".into()).is_err());
        assert_eq!(config, original);
        replace_block(&mut config, 2, "Host bee".into()).unwrap();
        assert_eq!(config, "User defaults\r\nHost a\r\nHost bee\r\nHost c");
    }

    #[test]
    fn selected_export_only_includes_numbered_blocks_in_source_order() {
        let original = "Include extra.conf\nUser defaults\n\
                        Host jump\n\tHostName localhost\n\
                        Host *\n\tPort 2222\n\
                        Match canonical\n\tUser nobody\n\
                        Host work\n\tProxyJump jump\n\tIdentityFile ~/.ssh/secret";
        let (out, warnings) = selected_text(original, &BTreeSet::from([5, 3])).unwrap();
        assert_eq!(
            out,
            format!(
                "{MANAGED_HEADER}Host *\n\tPort 2222\nHost work\n\tProxyJump jump\n\tIdentityFile ~/.ssh/secret"
            )
        );
        for needle in [
            "Global",
            "Omitted Host",
            "shared Host",
            "Include",
            "ProxyJump",
            "Paths",
            "first value",
        ] {
            assert!(
                warnings.iter().any(|w| w.contains(needle)),
                "missing {needle}: {warnings:?}"
            );
        }
        assert!(selected_text(original, &BTreeSet::new()).is_err());
        assert!(selected_text(original, &BTreeSet::from([0, 1])).is_err());
        assert!(selected_text(original, &BTreeSet::from([6])).is_err());
    }

    #[test]
    fn managed_install_is_private_and_does_not_touch_user_config() {
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join(".ssh");
        let output = dir.join(SELECTED_FILE);
        let first = format!("{MANAGED_HEADER}Host first\n");
        let second = format!("{MANAGED_HEADER}Host second\r\n");
        write_selected(&output, &first).unwrap();
        let user = dir.join("config");
        fs::write(&user, b"# my own config\r\nHost personal").unwrap();
        let opened_before = fs::File::open(&output).unwrap();
        write_selected(&output, &second).unwrap();
        assert_eq!(fs::read_to_string(&output).unwrap(), second);
        assert_eq!(fs::metadata(&output).unwrap().mode() & 0o777, 0o600);
        assert_eq!(
            fs::read(&user).unwrap(),
            b"# my own config\r\nHost personal"
        );
        let mut before = String::new();
        (&opened_before).read_to_string(&mut before).unwrap();
        assert_eq!(before, first);
    }

    #[test]
    fn managed_install_refuses_foreign_files_links_and_symlinked_ssh_dir() {
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join(".ssh");
        let output = dir.join(SELECTED_FILE);
        let candidate = format!("{MANAGED_HEADER}Host app\n");
        ssh_dir(&dir).unwrap();
        let user = dir.join("config");
        fs::write(&user, b"Host personal").unwrap();
        fs::copy(&user, &output).unwrap();
        fs::set_permissions(&output, Permissions::from_mode(0o600)).unwrap();
        assert!(write_selected(&output, &candidate).is_err());
        assert_eq!(fs::read(&output).unwrap(), b"Host personal");
        fs::remove_file(&output).unwrap();
        symlink(&user, &output).unwrap();
        assert!(write_selected(&output, &candidate).is_err());
        assert!(fs::symlink_metadata(&output).unwrap().is_symlink());
        assert_eq!(fs::read(&user).unwrap(), b"Host personal");
        let alias = home.path().join("alias");
        symlink(&dir, &alias).unwrap();
        assert!(write_selected(&alias.join("fresh"), &candidate).is_err());
        assert!(!dir.join("fresh").exists());
    }
}
