# sshp

Keep an OpenSSH configuration and signing keys in an age-encrypted Git vault.
Use `sshp` to manage it; use `ssh`, Git, scp and sftp as usual. Neither Git nor
fnox runs in the SSH connection path.

## Install

Install all three executables from the [GitHub releases](https://github.com/dParikesit/sshp/releases)
with [mise](https://mise.jdx.dev/). Prebuilt archives are available for macOS
and Linux (glibc), on Intel/AMD x86-64 and ARM64. No Rust toolchain is needed.

```sh
mise use -g github:dParikesit/sshp@latest
sshp --version
```

With mise activated in your shell, `sshp`, `sshp-ssh` and `sshp-agent` are now
on `PATH`. Run `mise upgrade github:dParikesit/sshp` to update, or pin a build
by replacing `latest` with its release tag without the leading `v`.
Each pushed commit gets its own release; commits on other branches are
prereleases, and `latest` follows the default branch.

Runtime requirements: OpenSSH (client and agent), Git, and
[fnox](https://fnox.jdx.dev) (tested with 1.50). Install `age` for `age-keygen`.

| Executable | Role |
| --- | --- |
| `sshp` | Vault, keys, Git, configuration management and Ratatui editor |
| `sshp-ssh` | Direct replacement for an invocation of `/usr/bin/ssh` |
| `sshp-agent` | Standalone user agent and lifecycle commands |

The wrapper is optional: stock OpenSSH honors the same Include and agent socket.
To select the wrapper for Git, `export GIT_SSH="$(command -v sshp-ssh)"`.
To install it as `ssh`, symlink `sshp-ssh` to `ssh` in a personal bin directory
ahead of `/usr/bin` on `PATH`. `scp -S /path/to/sshp-ssh` and
`sftp -S /path/to/sshp-ssh` select it explicitly.

## First vault

Keep the age **identity** outside the repository; the public **recipient** may
be shared. Back up the identity separately. For a new identity:

```sh
mkdir -p -m 700 ~/.config/sshp
age-keygen -o ~/.config/sshp/age.txt
export FNOX_AGE_KEY_FILE="$HOME/.config/sshp/age.txt"
sshp init --recipient "$(age-keygen -y "$FNOX_AGE_KEY_FILE")" --remote <git-url>
```

`SSHP_REPO` selects a dedicated vault repository (default
`$XDG_DATA_HOME/sshp/vault`, usually `~/.local/share/sshp/vault`). Omit
`--remote` for local use. Git operations are explicit.

```sh
sshp config import ./my-openssh-config
sshp tui
sshp key import work ~/.ssh/my_key
sshp key associate work my-alias
sshp install-config          # preview the required Include
sshp install-config --apply  # opt in; prepends the Include to ~/.ssh/config
sshp agent start
sshp agent unlock
ssh -G my-alias              # inspect what OpenSSH actually chose
ssh my-alias
sshp agent lock
```

Import **copies** the configuration and key. Original plaintext files and
their backups remain yours to manage. Importing your entire existing
`~/.ssh/config` and also keeping it active can evaluate its accumulating
directives twice. Move the portion you intend to manage out of the active
file yourself after verifying the round trip. Don't reimport sshp's own
runtime Include into the managed configuration.

## How OpenSSH chooses settings

The wrapper `exec`s `/usr/bin/ssh` with the original argument vector, file
descriptors, environment, and terminal. It doesn't inspect hostname syntax,
parse flags, start an agent, print a banner, or open the vault. To use a
different installed OpenSSH, set `SSHP_OPENSSH` to its absolute executable
path. Device/inode comparison detects a symlink or hard link back to the wrapper.

With the recommended Include at the **top** of `~/.ssh/config`, the order is:

1. OpenSSH command-line settings.
2. The included runtime file: identity associations for exact aliases and the
   managed raw OpenSSH text, in its original order.
3. The rest of `~/.ssh/config`.
4. The installed OpenSSH's system configuration and defaults.

Most directives take their first matching value; `IdentityFile`, forwarding
directives, etc. can accumulate. `-i` does **not** erase other identity files.
An intentional managed `Host *`, global setting or `Match` can affect any
matching connection. In the absence of such a setting or an explicit key
assignment, sshp does not set `IdentityAgent` for other hosts and never replaces
`SSH_AUTH_SOCK` in the wrapper. Place the Include manually at a different global
position if you want different precedence. Relative user-config Include paths
resolve under `~/.ssh` per OpenSSH, **not** beside the vault; include targets
are not automatically copied into Git.

There is no injected `-F`. An explicit `-F file` replaces the normal user config
**and suppresses the system config** as documented by [OpenSSH](https://man.openbsd.org/ssh).
It sees managed entries only if that file includes them. `-F none` bypasses
all configuration files. This also preserves option boundaries for remote
commands, binary streams, signals, exit status and pseudo-terminal handling.

## Runtime and trust

Run `sshp install-config` to print the actual runtime path. Set an absolute
`SSHP_RUNTIME_DIR` to use a different private directory; keep this setting
consistent between management invocations. By default sshp uses `sshp/` under
the private `$XDG_RUNTIME_DIR`, or on macOS the private per-user `$TMPDIR`,
falling back to `~/.sshp/run`. Use a parent controlled by you and a short
path (Unix socket paths have a platform-specific size limit).

The unlocked agent publishes a **plaintext** `managed.conf` and public
identity files in the user-only runtime directory. It never writes decrypted
private keys there. `lock` and `stop` remove the runtime configuration;
the persistent Include then matches no file. A locked vault doesn't turn
its aliases into a denylist: normal user config and DNS still apply.
Choose an in-memory or login-scoped runtime directory if you don't want
runtime config included in backups. Deliberate plaintext exports are separate
and are **not** revoked by agent lock.

Associations tell OpenSSH which public key to offer, using `IdentityAgent`,
`IdentityFile` and `IdentitiesOnly yes`. They are **not destination restrictions**:
a process with access to the unlocked socket can request signatures with any
listed identity. Set `SSH_AUTH_SOCK` to the agent socket only for clients that
should use it as their default. Do not forward that socket to an untrusted
machine. Lock/timeout protects against future signatures, not established
connections, ControlMaster sessions, or access by someone who possesses the
age identity. OpenSSH config can execute programs (e.g. `Match exec`,
`ProxyCommand`); trust the authors of vault contents and included files.

The socket is `agent.sock` beside `managed.conf`; `sshp agent start` prints
its path. `sshp-agent start --foreground` is suitable for a terminal or service
supervisor. The default idle timeout is 900 seconds, measured since unlock
or the most recent successful signature. Set it with e.g.
`sshp-agent start --idle-timeout 300`. Listing identities doesn't keep the
agent unlocked. The public agent interface does not accept key additions,
deletions or constraints. A separate same-user control socket handles explicit
management. A watchdog cleans up on daemon death; after a power loss or
simultaneous hard kills, `sshp agent status`, `lock`, `stop` or the next `start`
cleans stale runtime files. For noninteractive SSH authentication in scripts
use OpenSSH's normal `-o BatchMode=yes`; sshp itself never prompts in the
wrapper or signing path.

## Edit and selectively export

`sshp tui` works on the original source. Comments, line endings and even
non-UTF-8 bytes survive import/export; the text editor represents non-UTF-8
bytes with private-use characters. Use ↑/↓ to pick a block,
`e` for common fields, `r` for raw block text, `R` for the whole document,
`n`/`d` to add/remove and `J`/`K` to reorder. Ctrl-S (or F2) stages the form
or raw edit; use it again in the block list to save. Reordering changes
evaluation order. To export from the TUI, select blocks with Space and
press `p` to preview.

```sh
sshp config export > backup.conf                 # complete plaintext source
sshp config list                                 # numbered source blocks
sshp config export --entry 2,5                   # exact preview on stdout
sshp config export --entry 2,5 --install         # ~/.ssh/sshp-selected.conf
sshp config export --entry 2,5 --install --include
```

The last command also adds an Include to your user config. Inspect the
warnings printed on stderr for omitted global options, wildcard or Match
blocks and Includes. Exported blocks retain source order. The export is an
explicit plaintext copy, not a standalone replica of external dependencies
or the agent's identity associations. Remove its Include and app-owned file
yourself when you no longer want it active.

## Key storage and providers

`sshp key list` shows key labels, SHA-256 fingerprints, host associations,
and storage type. `key import` copies an Ed25519 or RSA OpenSSH-format key;
a protected file prompts for a passphrase. For automation `--passphrase-stdin`
accepts it via a pipe. Keep the source until the independent restore works.
`key associate LABEL HOST…` and `key disassociate LABEL HOST…` change the
exact host aliases; either accepts a full `SHA256:…` fingerprint instead of
the label. `key delete LABEL` removes the record, not the source
file or an existing external item.

* **Stored encrypted in Git** (default): the age record includes the SSH key.
  Restore with the ciphertext and its authorized native X25519 age identity.
* **External provider reference**: only the provider settings, item reference,
  public fingerprint and associations go into the age record. Supply access to
  the same provider on each machine. Unlock checks that the fetched key matches
  the pinned fingerprint. Bitwarden Password Manager is read-only.

```sh
sshp vault provider set-bitwarden passwords
sshp key add work --provider passwords        # enter the existing item reference
sshp key associate work work-box
sshp vault provider set-keychain local        # prompts for the keychain service
sshp key add laptop --provider local          # reference an existing entry
sshp key import new-key ./id_ed25519 --provider local   # create a keychain item
```

Bitwarden uses fnox's Password Manager provider, not Bitwarden Secrets
Manager. Authenticate `bw` separately and provide its unlocked session
(`BW_SESSION` or `FNOX_BW_SESSION`); use a reference such as `Work key/notes`
for a PEM stored in a secure note. Upstream fnox passes the session token to
`bw` as a command argument. To avoid that, configure fnox's `rbw` backend
with `printf 'backend = "rbw"\n' | sshp vault provider set-bitwarden passwords --config-stdin`
and run `rbw unlock` separately. External entries are expected
to contain an OpenSSH private key without an additional SSH-key passphrase;
the encrypted-file import path handles passphrase-protected source files.
Keychain access requires an available OS credential store; a local keychain
item on one machine is not transferred by Git. Use `sshp key --help` and
`sshp vault provider --help` for these commands.

`sshp vault export backup.toml` creates an encrypted standalone snapshot;
`sshp vault import backup.toml` validates it with your age identity before
replacing the working file. Neither command requires Git. Back up provider
items separately. The portable file uses one fixed fnox record name independent
of its contents. The public recipient, ciphertext size, Git author and history
are not secret; host names, labels, public fingerprints, references and keys
are inside the encrypted payload. The `plain` provider is not supported.

## Synchronization and recovery

```sh
sshp status
sshp push
# On another machine: install sshp/fnox, provision the authorized age identity,
# set FNOX_AGE_KEY_FILE, then:
sshp clone <git-url>
sshp install-config --apply
sshp agent start
sshp agent unlock
```

For the first clone, use HTTPS with your credential manager, a separate
bootstrap SSH key, or an already-unlocked external agent. The vault cannot
provide the key needed to fetch itself. Provision external provider access
separately on each machine. Run `sshp pull` explicitly to update. Treat a
divergence as two valuable versions: keep both, export an encrypted backup,
and reconcile deliberately; sshp never force-pushes. For example, leave the
diverged checkout intact, `SSHP_REPO=/absolute/new/vault sshp clone <git-url>`
into a second checkout, then reapply the intended local edits there and push
that fast-forward. Keep the original checkout or backup until you've verified
the result. The sync format is a linear history of regular `vault.toml` files;
it doesn't merge encrypted blobs or accept merge commits. An unlocked agent
represents a snapshot: explicitly lock/unlock after changing or pulling keys
or configuration.

## Verification

```sh
cargo test --locked
cargo build --locked
python3 tests/acceptance.py
```

The acceptance runner uses throwaway keys, repositories, client homes and a
loopback-only `sshd` on a high port. It uses `-F` with the temporary users'
real config files: OpenSSH resolves `~/.ssh/config` using the login account,
not an overridden `HOME`. No changes to your own `.ssh` are necessary.
On Linux, the server needs its distribution's privilege-separation directory
(often `/run/sshd`) and an account permitted to log in. If `fnox` is installed
through a home-dependent version-manager shim, set `SSHP_TEST_FNOX` to the
real installed executable; similarly, `SSHP_TEST_AGE_KEYGEN` selects
`age-keygen`. `--agent-only` skips tests requiring a server.

`bash tests/secret-service.sh` additionally exercises native Linux keychain
creation, fnox resolution, and stock `ssh-add -T` using an isolated
`dbus-run-session` and `gnome-keyring-daemon`. The main interoperability suite
uses the real fnox Bitwarden provider with a fixture `bw` executable; it
doesn't require or access a personal Bitwarden account.
