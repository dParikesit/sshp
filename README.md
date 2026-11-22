# sshp

Keep an OpenSSH configuration and signing keys in an age-encrypted Git vault.
Use `sshp` to manage it; use `ssh`, Git, scp and sftp as usual. Neither Git nor
fnox runs in the SSH connection path.

## Install

Install the CLI and agent from the [GitHub releases](https://github.com/dParikesit/sshp/releases)
with [mise](https://mise.jdx.dev/). Prebuilt archives are available for macOS
and Linux (glibc), on Intel/AMD x86-64 and ARM64. No Rust toolchain is needed.

```sh
mise use -g github:dParikesit/sshp@latest
sshp --version
```

With mise activated in your shell, `sshp` and `sshp-agent` are now
on `PATH`. Run `mise upgrade github:dParikesit/sshp` to update. Each pushed
commit gets its own release; commits on other branches are prereleases.

mise's minimum release age can delay `@latest` (24 hours by default). To
install the newest default-branch release immediately, pin its exact version
from [Releases](https://github.com/dParikesit/sshp/releases/latest), omitting
the leading `v`. With the GitHub CLI:

```sh
tag=$(gh release view --repo dParikesit/sshp --json tagName --jq .tagName)
mise use -g "github:dParikesit/sshp@${tag#v}"
```

Runtime requirements: OpenSSH (client and agent), Git, and
[fnox](https://fnox.jdx.dev) (tested with 1.50). Install `age` for `age-keygen`.

| Executable | Role |
| --- | --- |
| `sshp` | Vault, keys, Git, configuration management and Ratatui editor |
| `sshp-agent` | Standalone user agent and lifecycle commands |

Use stock OpenSSH for SSH, Git, scp and sftp. If upgrading from `sshp-ssh`,
remove any `ssh` alias/symlink, Git SSH override, or `-S` option that points
to the old wrapper. Keep your managed Include; it works with stock OpenSSH.

## First vault

Keep the age **identity** outside the repository; the public **recipient** may
be shared. Back up the identity separately. For a new identity:

```sh
mkdir -p -m 700 ~/.config/sshp
age-keygen -o ~/.config/sshp/age.txt
sshp settings set age-key-file ~/.config/sshp/age.txt
sshp init --recipient "$(age-keygen -y ~/.config/sshp/age.txt)" --remote <git-url>
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

### Protect an existing vault with a passphrase

Protect **the existing age identity**, not `vault.toml`. The recipient stays
the same, so the vault, its Git history and all imported SSH keys stay as they
are. Set `identity` below to your current plaintext identity, then run this
in a terminal to create a protected copy (refuses to overwrite):

```sh
identity="$HOME/.config/sshp/age.txt"
(umask 077; set -C; age -p "$identity" > "$identity.age") &&
  sshp settings set age-key-file "$identity.age"
```

Run `sshp key list` and verify your existing fingerprints. To try the full
cycle, run `sshp agent start`, `sshp agent lock`, then `sshp agent unlock`.
fnox prompts for the identity passphrase in the terminal. It decrypts the
identity in memory; sshp verifies the recipient and loads the agent without
creating a plaintext identity file. An unattended unlock with a protected
identity fails rather than waiting for a passphrase on stdin.

Once verified, back up the protected identity separately from the vault.
Any remaining plaintext copy of the old identity can still open the vault
without a passphrase. Regular SSH signing and agent lock never require the
passphrase; management commands that reopen the vault can prompt again.

## How OpenSSH chooses settings

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
`SSH_AUTH_SOCK` in your shell. Place the Include manually at a different global
position if you want different precedence. Relative user-config Include paths
resolve under `~/.ssh` per OpenSSH, **not** beside the vault; include targets
are not automatically copied into Git.

There is no injected `-F`. An explicit `-F file` replaces the normal user config
**and suppresses the system config** as documented by [OpenSSH](https://man.openbsd.org/ssh).
It sees managed entries only if that file includes them. `-F none` bypasses
all configuration files. This also preserves option boundaries for remote
commands, binary streams, signals, exit status and pseudo-terminal handling.

## Local settings

`sshp settings` prints the current machine's identity path and lock policy.
Settings are kept in `$XDG_CONFIG_HOME/sshp/settings.toml` (normally
`~/.config/sshp/settings.toml`), outside the encrypted vault and its Git history.
Set them before or after cloning. `age-key-file` stores only the path; supply
the identity itself separately on every machine. Without a saved path sshp
looks for `$XDG_CONFIG_HOME/fnox/age.txt`. To migrate an existing environment
setting, run `sshp settings set age-key-file "$FNOX_AGE_KEY_FILE"` once.

```sh
sshp settings set agent-lock 1h
sshp agent stop
sshp agent start
sshp agent status                  # shows the policy actually running
```

* `15m` (default), `1h`, `4h`, `24h`: idle time since unlock or the last
  successful signature. Listing identities does not reset the timer.
* `machine-lock`: revoke keys when the desktop locks. Unlocking the screen
  does not unlock the agent. On macOS this uses the GUI session; on Linux
  it requires a desktop session bus with a freedesktop, GNOME, Cinnamon or
  MATE ScreenSaver service. Screen saver activation can lock the agent early.
  If no supported monitor is available the agent refuses to start in this mode.
  If the Linux locker disconnects, restart the agent once the locker is back.
* `restart`: no idle timer. Keys last for this agent process only; stopping
  it, losing it or rebooting always requires an explicit unlock.

`sshp agent lock` works in every mode. Policy changes take effect at the next
agent start; use `--idle-timeout SECONDS` on `agent start` for a one-run override.

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
supervisor. The public agent interface does not accept key additions,
deletions or constraints. A separate same-user control socket handles explicit
management. A watchdog cleans up on daemon death; after a power loss or
simultaneous hard kills, `sshp agent status`, `lock`, `stop` or the next `start`
cleans stale runtime files. For noninteractive SSH authentication in scripts
use OpenSSH's normal `-o BatchMode=yes`; signing never prompts.

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
* **External fnox secret**: the vault contains a logical secret name, public
  key, fingerprint and host associations. fnox owns the provider, item
  reference and authentication. Any provider (including an installed fnox
  plugin) that can return an OpenSSH private key through `fnox get` works.
  Write-only destinations and sign-only hardware keys cannot supply key bytes.

### Use a key from fnox

Configure a [fnox provider](https://fnox.jdx.dev/providers/overview) on your machine
and define a secret such as `WORK_SSH` in its config. The secret must resolve
to the **contents** of an Ed25519 or RSA OpenSSH private key without an SSH
passphrase (`as_file` must be off). Use `env = false` on the secret to keep
fnox shell activation from exporting it. Point sshp at that trusted config:

```sh
export SSHP_FNOX_CONFIG="$HOME/.config/sshp/fnox.toml"
sshp key add work --fnox-secret WORK_SSH
sshp key associate work work-box
sshp agent start
sshp agent unlock
```

The default is `$XDG_CONFIG_HOME/sshp/fnox.toml` (usually the path above).
Set `SSHP_FNOX_CONFIG` to an absolute path to use an existing config instead.
Set `FNOX_PROFILE` if needed. The management client runs `fnox get` with your
normal provider credentials, imports and plugins. A terminal allows fnox's
authentication prompts; scripts run non-interactively and need credentials
provisioned first. Keep the config outside the synced
vault: a clone must not choose which fnox config your machine executes.

For a writable provider you can provision the secret with fnox itself, e.g.
`fnox --config "$SSHP_FNOX_CONFIG" set WORK_SSH --provider my_store --from-file ./id_ed25519`.
For read-only providers, configure a reference to an existing item instead.
Each machine may use a different backend for `WORK_SSH`; registration pins the
public key and unlock rejects a mismatch. The running agent never calls fnox
to sign. Deleting a key from sshp does not change the external item.

### Upgrade from the per-provider CLI

Existing age-stored keys and SSH configuration need no migration. Upgrade all
clients before editing: the first vault edit writes schema v2. To keep a
pre-upgrade snapshot, use `sshp vault export backup.toml` before editing.
`sshp key list` marks old external keys as `legacy (needs key relink)`.
Define each existing item as a secret in your local fnox config, then run:

```sh
sshp key relink work --fnox-secret WORK_SSH
```

Relinking checks the existing fingerprint before changing anything and keeps
the label and hosts. Repeat for each legacy key before unlocking. This also
works to move an age-stored key to a provider after provisioning the same key
there; it does not remove the key from older encrypted backups or Git history.

`sshp vault export backup.toml` creates an encrypted standalone snapshot;
`sshp vault import backup.toml` validates it with your age identity before
replacing the working file. Neither command requires Git. Back up provider
items separately. The portable file uses one fixed fnox record name independent
of its contents. The public recipient, ciphertext size, Git author and history
are not secret; host names, labels, public fingerprints, references and keys
are inside the encrypted payload. The portable vault itself always uses age.

## Synchronization and recovery

```sh
sshp status
sshp push
# On another machine: install sshp/fnox, provision the authorized age identity,
# then save its local path during the first clone:
sshp clone <git-url> --age-key-file ~/.config/sshp/age.txt.age
sshp install-config --apply
sshp agent start
sshp agent unlock
```

For the first clone, use HTTPS with your credential manager, a separate
bootstrap SSH key, or an already-unlocked external agent. The vault cannot
provide the key needed to fetch itself. Provision external provider access
separately on each machine. `sshp pull` reuses the saved local identity path;
use `sshp pull --age-key-file PATH` if you moved it. Treat a
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

`bash tests/secret-service.sh` additionally exercises `fnox set` and `get` with
a private Linux keyring and stock `ssh-add -T`. The main suite resolves one
secret name across two machines using different fnox providers, tests missing
and changed keys, and migrates a v1 external key without a personal account.
