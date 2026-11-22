#!/usr/bin/env bash
# Optional Linux interoperability check: an isolated D-Bus, home and keyring.
set -euo pipefail
[[ "$(uname -s)" == Linux ]]
umask 077
bin="$(cd "$(dirname "$0")/../target/debug" && pwd)"
scratch="$(mktemp -d /tmp/sshp-keyring.XXXXXXXX)"
trap 'rm -rf -- "$scratch"' EXIT
export HOME="$scratch/home" XDG_RUNTIME_DIR="$scratch/run"
export XDG_DATA_HOME="$HOME/data" XDG_CONFIG_HOME="$HOME/config"
export SSHP_REPO="$scratch/vault" SSHP_RUNTIME_DIR="$scratch/agent"
export FNOX_AGE_KEY_FILE="$HOME/identity"
export SSHP_FNOX_CONFIG="$HOME/fnox.toml"
mkdir -m 700 "$HOME" "$XDG_RUNTIME_DIR"
age-keygen -o "$FNOX_AGE_KEY_FILE"
ssh-keygen -q -t ed25519 -N '' -f "$HOME/key"
dbus-run-session -- bash -eu -c '
    printf "%s" fixture | gnome-keyring-daemon --unlock --components=secrets >/dev/null
    cli="$1/sshp"
    "$cli" init --recipient "$(age-keygen -y "$FNOX_AGE_KEY_FILE")"
    printf "[providers.os]\ntype = \"keychain\"\nservice = \"sshp-fixture\"\n" > "$SSHP_FNOX_CONFIG"
    fnox --no-daemon --config "$SSHP_FNOX_CONFIG" set WORK_SSH --provider os --from-file "$HOME/key"
    "$cli" key add restored --fnox-secret WORK_SSH
    "$cli" agent start
    trap "\"$cli\" agent stop" EXIT
    "$cli" agent unlock
    SSH_AUTH_SOCK="$SSHP_RUNTIME_DIR/agent.sock" ssh-add -T "$HOME/key.pub"
' _ "$bin"
