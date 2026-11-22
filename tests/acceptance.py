#!/usr/bin/env python3
"""Loopback interoperability suite. Requires cargo build, fnox, age and OpenSSH.

Run with a real fnox binary on PATH (or set SSHP_TEST_FNOX if using a shim).
Does not write to your home, use your keys, or contact a hosted Git service.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import contextlib
import errno
import fcntl
import json
import os
import pathlib
import pty
import pwd
import select
import shlex
import shutil
import socket
import subprocess
import struct
import sys
import tempfile
import termios
import time

P = pathlib.Path
ROOT = P(__file__).resolve().parents[1]
BIN = P(os.environ.get("SSHP_TEST_BIN", ROOT / "target/debug")).resolve()
CLI = BIN / "sshp"
USER = pwd.getpwuid(os.getuid()).pw_name


def run(*cmd, env=None, data=None, code=0):
    result = subprocess.run([str(x) for x in cmd], input=data or b"", env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45)
    if code is not None and result.returncode != code:
        raise AssertionError(f"{cmd[:4]} returned {result.returncode}, expected {code}:\n"
                             + result.stderr.decode(errors="replace"))
    return result


def keys(directory):
    for name, kind in [("server", "ed25519"), ("assigned", "ed25519"), ("unrelated", "rsa")]:
        path = directory / name
        phrase = "fixture passphrase" if name == "assigned" else ""
        run("ssh-keygen", "-q", "-t", kind, "-N", phrase, "-C", "fixture-" + name, "-f", path)


@contextlib.contextmanager
def sshd(directory):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    conf = directory / "sshd_config"
    conf.write_text(f"""Port {port}
ListenAddress 127.0.0.1
HostKey "{directory}/server"
AuthorizedKeysFile "{directory}/assigned.pub"
PidFile "{directory}/pid"
AllowUsers {USER}
AuthenticationMethods publickey
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
UsePAM no
StrictModes no
Subsystem sftp internal-sftp
""")
    binary = os.environ.get("SSHP_TEST_SSHD", "/usr/sbin/sshd")
    with (directory / "sshd.log").open("wb") as log, subprocess.Popen(
            [binary, "-D", "-e", "-f", conf], stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=log) as proc:
        try:
            for _ in range(100):
                if proc.poll() is not None:
                    raise AssertionError((directory / "sshd.log").read_text())
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=.2):
                        break
                except OSError:
                    time.sleep(.03)
            else:
                raise RuntimeError("loopback sshd did not become ready")
            yield port
        finally:
            proc.terminate()


def client_env(directory, tools, runtime):
    directory.mkdir()
    return {
        "HOME": str(directory), "PATH": str(tools) + os.pathsep + os.environ["PATH"],
        "SSHP_RUNTIME_DIR": str(runtime), "SSHP_REPO": str(directory / "vault"),
        "SSH_ASKPASS_REQUIRE": "never",
        "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "Fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
        "GIT_COMMITTER_NAME": "Fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
        "LC_ALL": "C",
    }


def fingerprint(pub):
    return run("ssh-keygen", "-lf", pub).stdout.decode().split()[1]


def answer_prompts(argv, env, prompts, reply, retry_prompt=None):
    """Drive the real age/fnox password prompts without a passphrase in argv or env."""
    pid, term = pty.fork()
    if pid == 0:
        os.execvpe(str(argv[0]), list(map(str, argv)), env)
    pending = list(prompts)
    output = b""
    deadline = time.monotonic() + 45
    try:
        while time.monotonic() < deadline:
            if not select.select([term], [], [], .2)[0]:
                continue
            try:
                chunk = os.read(term, 8192)
            except OSError as exc:
                if exc.errno != errno.EIO:
                    raise
                break
            if not chunk:
                break
            output += chunk
            if pending and pending[0] in output.lower():
                pending.pop(0)
                os.write(term, reply + b"\n")
                output = b""
            elif not pending and retry_prompt and retry_prompt in output.lower():
                os.write(term, reply + b"\n")
                retry_prompt = None
                output = b""
        else:
            raise AssertionError("terminal command did not finish after expected prompts")
        _, status = os.waitpid(pid, 0)
        pid = 0
        assert not pending, f"terminal command exited before prompt {pending}"
        return os.waitstatus_to_exitcode(status)
    finally:
        if pid:
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, 9)
            os.waitpid(pid, 0)
        os.close(term)


def protected_unlock(env, d, identity, age_keygen):
    wrapped = d / "protected.age"
    phrase = b"disposable fixture passphrase"
    age = P(shutil.which(str(age_keygen))).resolve().with_name("age")
    assert answer_prompts([age, "-p", "-o", wrapped, identity], env,
                          [b"enter passphrase", b"confirm passphrase"], phrase) == 0
    run(CLI, "settings", "set", "age-key-file", wrapped, env=env)
    protected = env
    sock = P(env["SSHP_RUNTIME_DIR"]) / "agent.sock"
    config = sock.with_name("managed.conf")
    client = {**protected, "SSH_AUTH_SOCK": str(sock)}
    cli = [CLI, "agent", "unlock"]
    vault_file = P(env["SSHP_REPO"]) / "vault.toml"
    before = vault_file.read_bytes()
    run(CLI, "agent", "lock", env=env)
    assert run(*cli, env=protected, code=None).returncode, "headless unlock must fail"
    prompt = b"passphrase for age identity"
    assert answer_prompts(cli, protected, [prompt], b"incorrect", retry_prompt=prompt) != 0
    assert not config.exists()
    assert run("ssh-add", "-T", d / "assigned.pub", env=client, code=None).returncode
    assert answer_prompts(cli, protected, [b"passphrase for age identity"], phrase) == 0
    assert config.exists() and before == vault_file.read_bytes()
    wrapped.unlink()  # Subsequent signing and locking cannot reopen this identity.
    run("ssh-add", "-T", d / "assigned.pub", env=client)
    run(CLI, "agent", "lock", env=protected)
    assert not config.exists()
    assert run("ssh-add", "-T", d / "assigned.pub", env=client, code=None).returncode
    run(CLI, "settings", "set", "age-key-file", identity, env=env)


def agent_packet(sock, request):
    def receive(count):
        data = bytearray()
        while len(data) < count:
            part = sock.recv(count - len(data))
            assert part, "agent closed stream instead of replying"
            data.extend(part)
        return bytes(data)
    sock.sendall(struct.pack(">I", len(request)) + request)
    return receive(struct.unpack(">I", receive(4))[0])


def edit_alias(env):
    """Drive the actual Ratatui form through a PTY; do not use an $EDITOR file."""
    pid, term = pty.fork()
    if pid == 0:
        fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 100, 0, 0))
        os.execve(CLI, [str(CLI), "tui"], {**env, "TERM": "xterm-256color"})
    display = bytearray()
    sent = False
    try:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if not select.select([term], [], [], .2)[0]:
                continue
            try:
                chunk = os.read(term, 16384)
            except OSError as e:
                if e.errno == errno.EIO:
                    break
                raise
            if not chunk:
                break
            display += chunk
            if not sent and b"Navigate" in display:
                # Down past the preamble; edit the Host field. Stage, save, quit.
                os.write(term, b"\x1b[Be-edited\x13\x13q")
                sent = True
        else:
            raise AssertionError("TUI did not finish the edit")
        assert sent and os.waitpid(pid, 0)[1] == 0, "TUI failed to save"
        pid = 0
    finally:
        if pid:
            with contextlib.suppress(ProcessLookupError, ChildProcessError):
                os.kill(pid, 9)
                os.waitpid(pid, 0)
        os.close(term)


def transports(d, env, file, alias, native_login):
    assigned = fingerprint(d / "assigned.pub").encode()
    unrelated = fingerprint(d / "unrelated.pub").encode()
    trace = run("ssh", "-vv", "-F", file, alias, "exit", "43", env=env, code=43).stderr
    offers = [l for l in trace.splitlines() if b"Offering public key:" in l]
    assert any(assigned in l for l in offers) and not any(unrelated in l for l in offers), offers
    assert unrelated not in trace, "the unrelated key entered OpenSSH's identity selection"
    quoted = "spaces, 'quotes', $dollar; and *"
    args = ["printf", "'%s'", shlex.quote(quoted)]
    assert run("ssh", "-F", file, alias, *args, env=env).stdout == quoted.encode()
    blob = bytes(range(256)) * 1024
    original = d / "binary"
    original.write_bytes(blob)
    remote = d / "scp-copy"
    run("scp", "-F", file, original, f"{alias}:{remote}", env=env)
    assert remote.read_bytes() == blob
    target = d / "sftp-copy"
    run("sftp", "-F", file, "-b", "-", alias, env=env,
        data=f'get "{remote}" "{target}"\n'.encode())
    assert target.read_bytes() == blob
    work = d / "git-fixture"
    run("git", "init", "-q", work, env=env)
    (work / "payload").write_bytes(blob)
    run("git", "-C", work, "add", "payload", env=env)
    run("git", "-C", work, "commit", "-qm", "fixture", env=env)
    checkout = d / "via-ssh"
    run("git", "clone", "-q", f"{alias}:{work}", checkout, env={
        **env, "GIT_SSH_COMMAND": f"ssh -F {shlex.quote(str(file))}",
    })
    assert (checkout / "payload").read_bytes() == blob
    if native_login:
        # Caller provisions the real login account's ~/.ssh/config with an
        # Include pointing to the fixture; the test itself never changes it.
        ssh_path = "ssh"
        computed = run(ssh_path, "-vvG", "-p", "2222", alias, env=env)
        assert b"port 2222\n" in computed.stdout and b"hostname 127.0.0.1\n" in computed.stdout
        if P("/etc/ssh/ssh_config").exists():
            system = b"Reading configuration data /etc/ssh/ssh_config"
            assert system in computed.stderr
            assert system not in run(ssh_path, "-vvG", "-F", file, alias, env=env).stderr
        assert str(d/"r1/agent.sock").encode() not in run(
            ssh_path, "-G", "unmanaged.invalid", env=env).stdout
        assert run(ssh_path, alias, "printf", "native", env=env).stdout == b"native"
        remote_head = run("git", "ls-remote", f"{alias}:{work}", "HEAD",
                          env=env).stdout.split()[0]
        assert remote_head == run("git", "-C", work, "rev-parse", "HEAD", env=env).stdout.strip()


def inspect_history(remote, needles, env):
    commits = run("git", "-C", remote, "rev-list", "--all", env=env).stdout.decode().splitlines()
    assert commits
    for rev in commits:
        paths = run("git", "-C", remote, "ls-tree", "-r", "--name-only", rev, env=env).stdout
        assert paths.splitlines() == [b"vault.toml"], paths
        record = run("git", "-C", remote, "show", rev + ":vault.toml", env=env).stdout
        for value in needles:
            assert value not in record, "plaintext in reachable history"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent-only", action="store_true", help="omit live sshd and transfer checks")
    parser.add_argument("--native-login", action="store_true",
                        help="also test bare ssh ALIAS and default Git transport; requires a disposable login "
                             "with Include /ABSOLUTE/HOME/.sshp-e2e/sshp-*/first/.ssh/config")
    args = parser.parse_args()
    os.umask(0o077)
    # Short paths for sockaddr_un on macOS; all material inside mkdtemp(0700).
    base = P(pwd.getpwuid(os.getuid()).pw_dir) / ".sshp-e2e" if args.native_login else P("/tmp")
    if args.native_login and (base.is_symlink() or not base.is_dir() or base.stat().st_mode & 0o077):
        raise SystemExit("--native-login requires a pre-created private ~/.sshp-e2e (mode 0700)")
    with tempfile.TemporaryDirectory(prefix="sshp-e2e-", dir=base) as tmp:
        d = P(tmp)
        tools = d / "tools"
        tools.mkdir()
        (tools / "fnox").symlink_to(os.environ.get("SSHP_TEST_FNOX") or shutil.which("fnox"))
        identity = d / "age-id"
        age = os.environ.get("SSHP_TEST_AGE_KEYGEN", "age-keygen")
        run(age, "-o", identity)
        recipient = run(age, "-y", identity).stdout.decode().strip()
        keys(d)
        with contextlib.ExitStack() as cleanup:
            port = 22 if args.agent_only else cleanup.enter_context(sshd(d))
            env = client_env(d / "first", tools, d / "r1")
            run(CLI, "settings", "set", "age-key-file", identity, env=env)
            alias = "sshp-example-hidden"
            remote = d / "sync.git"
            run("git", "init", "--bare", "-q", remote, env=env)
            run(CLI, "init", "--recipient", recipient, "--remote", remote, env=env)
            fixture = d / "source.conf"
            fixture.write_bytes(f"""# private fixture round trip
Host {alias}
    HostName 127.0.0.1
    Port {port}
    User {USER}
    UserKnownHostsFile "{d}/known_hosts"
    GlobalKnownHostsFile /dev/null
    StrictHostKeyChecking accept-new
    BatchMode yes

Host *.example.invalid !excluded.example.invalid
    IdentityFile "first path"
    IdentityFile second
    Include no-such-sshp-fixture
Match originalhost another.invalid
    ConnectTimeout 2""".replace("\n", "\r\n").encode())
            fixture.write_bytes(fixture.read_bytes().replace(b"round trip", b"round trip \xff"))
            run(CLI, "config", "import", fixture, env=env)
            assert run(CLI, "config", "export", env=env).stdout == fixture.read_bytes()
            edit_alias(env)
            alias += "-edited"
            expected = fixture.read_bytes().replace(b"Host sshp-example-hidden\r\n",
                                                    b"Host " + alias.encode() + b"\r\n", 1)
            assert run(CLI, "config", "export", env=env).stdout == expected
            selected = run(CLI, "config", "export", "--entry", "2", env=env)
            assert b"warning:" in selected.stderr and b"Include " in selected.stderr
            run(CLI, "config", "export", "--entry", "2", "--install", env=env)
            assert (d / "first/.ssh/sshp-selected.conf").read_bytes() == selected.stdout
            original = (d / "assigned").read_bytes()
            run(CLI, "key", "import", "work", d / "assigned", "--passphrase-stdin",
                env=env, data=b"fixture passphrase\n")
            assert (d / "assigned").read_bytes() == original
            run(CLI, "key", "associate", fingerprint(d / "assigned.pub"), alias, env=env)
            run(CLI, "key", "import", "other", d / "unrelated", env=env)
            backup = d / "portable-backup"
            run(CLI, "vault", "export", backup, env=env)
            restored = client_env(d / "restored", tools, d / "r4")
            run(CLI, "settings", "set", "age-key-file", identity, env=restored)
            run(CLI, "vault", "import", backup, env=restored)
            assert run(CLI, "config", "export", env=restored).stdout == expected
            assert not (P(restored["SSHP_REPO"]) / ".git").exists()
            corrupt = d / "broken-backup"
            corrupt.write_bytes(backup.read_bytes() + b"\n# accidental plaintext\n")
            assert run(CLI, "vault", "import", corrupt, env=restored, code=None).returncode
            assert (P(restored["SSHP_REPO"]) / "vault.toml").read_bytes() == backup.read_bytes()
            run(CLI, "install-config", "--apply", env=env)
            run(CLI, "agent", "start", env=env)
            cleanup.callback(run, CLI, "agent", "stop", env=env, code=None)
            protected_unlock(env, d, identity, age)
            run(CLI, "agent", "unlock", env=env)
            sock = str(d / "r1/agent.sock")
            client = {**env, "SSH_AUTH_SOCK": sock}
            listing = run("ssh-add", "-L", env=client).stdout
            for name in ["assigned", "unrelated"]:
                pub = d / (name + ".pub")
                assert pub.read_bytes().split()[1] in listing
                run("ssh-add", "-T", pub, env=client)
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
                stream.settimeout(3)
                stream.connect(sock)
                identities = agent_packet(stream, b"\x0b")
                assert identities[0] == 12 and int.from_bytes(identities[1:5], "big") == 2
                n = int.from_bytes(identities[5:9], "big")
                key = identities[5:9+n]  # includes its wire length prefix
                sign = b"\x0d" + key + b"\0\0\0\x04test" + b"\0\0\0\0"
                run(CLI, "agent", "lock", env=env)
                assert agent_packet(stream, sign) == b"\x05"
                assert not (d / "r1/managed.conf").exists()
                assert run("ssh-add", "-T", d / "assigned.pub", env=client, code=None).returncode
                run(CLI, "agent", "unlock", env=env)
                assert agent_packet(stream, b"\x0b") == b"\x0c\0\0\0\0"
            run("ssh-add", "-T", d / "assigned.pub", env=client)
            if not args.agent_only:
                transports(d, env, d / "first/.ssh/config", alias, args.native_login)
            run(CLI, "push", env=env)
            inspect_history(remote, [alias.encode(), b"HostName 127.0.0.1", b"fixture-assigned",
                                     b"OPENSSH PRIVATE KEY", (d/"assigned").read_bytes().splitlines()[2]], env)
            env2 = client_env(d / "second", tools, d / "r2")
            second_key = d / "second/identity"
            shutil.copyfile(identity, second_key)
            run(CLI, "clone", remote, "--age-key-file", second_key, env=env2)
            run(CLI, "install-config", "--apply", env=env2)
            run(BIN / "sshp-agent", "start", "--idle-timeout", "2", env=env2)
            cleanup.callback(run, BIN / "sshp-agent", "stop", env=env2, code=None)
            run(CLI, "agent", "unlock", env=env2)
            ordinary = {**env2, "SSH_AUTH_SOCK": str(d/"r2/agent.sock")}
            with ThreadPoolExecutor(max_workers=6) as pool:
                list(pool.map(lambda name: run("ssh-add", "-T", d / name, env=ordinary),
                              ["assigned.pub", "unrelated.pub"] * 3))
            if not args.agent_only:
                run("ssh", "-F", d / "second/.ssh/config", alias, "true", env=env2)
            time.sleep(2.2)
            assert not (d / "r2/managed.conf").exists(), "idle lock left configuration published"
            assert run("ssh-add", "-T", d / "assigned.pub", env=ordinary, code=None).returncode
            # The client reads a named secret from a native fnox config. The
            # profile, provider, credentials and backing key stay on this machine.
            run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", d / "external")
            (d / "fixture.lua").write_text("""
return { get = function(ctx, ref)
    if ref ~= 'fixture-item' or os.getenv('FIXTURE_SESSION') ~= 'fixture-only' then return nil end
    local f = assert(io.open(ctx.options.path, 'rb'))
    local key = f:read('*a')
    f:close()
    return key
end }
""")
            external_config = d / "fnox-client.toml"
            external_config.write_text('[providers.manager]\ntype = "lua"\nplugin = "./fixture.lua"\n'
                                       f'options = {{ path = "{d}/external" }}\n'
                                       '[profiles.fixture.secrets.WORK_SSH]\nprovider = "manager"\n'
                                       'value = "fixture-item"\nenv = false\n')
            available = {**env, "FIXTURE_SESSION": "fixture-only",
                         "FNOX_PROFILE": "fixture", "SSHP_FNOX_CONFIG": str(external_config)}
            run(CLI, "key", "add", "ext", "--fnox-secret", "WORK_SSH", env=available)
            run(CLI, "key", "associate", "ext", "external-host", env=available)
            sources = run(CLI, "key", "list", env=available).stdout
            assert b"encrypted in Git (age)" in sources and b"external (fnox)" in sources
            run(CLI, "push", env=available)
            inspect_history(remote, [b"WORK_SSH", b"fixture-item", b"external-host", b"OPENSSH PRIVATE KEY",
                                     (d / "external").read_bytes().splitlines()[2]], env)
            run(CLI, "pull", env=env2)
            env3 = client_env(d / "third", tools, d / "r3")
            run(CLI, "clone", remote, "--age-key-file", identity, env=env3)
            # A stale pre-upgrade shell export cannot override the saved path,
            # even when fnox uses age for an external secret.
            env3["FNOX_AGE_KEY_FILE"] = str(d / "nonexistent-old-path")
            run(CLI, "settings", "set", "agent-lock", "restart", env=env3)
            run(CLI, "agent", "start", env=env3)
            assert b"auto-lock: restart" in run(CLI, "agent", "status", env=env3).stdout
            cleanup.callback(run, CLI, "agent", "stop", env=env3, code=None)
            # Clone/list do not require the external provider. Unlock does.
            missing = run(CLI, "agent", "unlock", env=env3, code=None)
            assert missing.returncode and b"SSHP_FNOX_CONFIG" in missing.stderr
            # The same logical secret may use a different backend on another
            # machine. Build a real encrypted fnox config, using the default path.
            cfg = P(env3["HOME"]) / ".config/sshp/fnox.toml"
            cfg.parent.mkdir(parents=True, exist_ok=True)
            cfg.write_text(f'[providers.other]\ntype = "age"\nrecipients = ["{recipient}"]\n')
            store = [tools / "fnox", "--no-daemon", "--config", cfg, "set", "WORK_SSH",
                     "--provider", "other", "--from-file"]
            missing = run(CLI, "agent", "unlock", env=env3, code=None)
            assert missing.returncode and b"fnox key lookup failed" in missing.stderr
            run(*store, d / "unrelated", env=env3)
            wrong = run(CLI, "agent", "unlock", env=env3, code=None)
            assert wrong.returncode and b"pinned public key" in wrong.stderr
            assert not (d / "r3/managed.conf").exists()
            run(*store, d / "external", env=env3)
            run(CLI, "agent", "unlock", env=env3)
            cfg.rename(cfg.with_suffix(".offline"))
            run("ssh-add", "-T", d / "external.pub", env={**env3, "SSH_AUTH_SOCK": str(d/"r3/agent.sock")})
            run(CLI, "agent", "stop", env=env3)
            run(CLI, "agent", "start", env=env3)
            assert b"(locked); auto-lock: restart" in run(CLI, "agent", "status", env=env3).stdout
            assert not (d / "r3/managed.conf").exists()
            cfg.with_suffix(".offline").rename(cfg)
            # A pre-upgrade vault may have both embedded and old provider
            # records. Registration must preserve labels/hosts and require the
            # same key, without executing its old backend configuration.
            vf = P(restored["SSHP_REPO"]) / "vault.toml"
            vault_fnox = [tools / "fnox", "--no-daemon", "--config", vf]
            direct_fnox = {**restored, "FNOX_AGE_KEY_FILE": str(identity)}
            record = json.loads(run(*vault_fnox, "get", "SSHP_VAULT", env=direct_fnox).stdout)
            record.update(version=1, providers={"old": {"type":"keychain","service":"fixture"}})
            record["keys"]["other"]["source"] = {"type":"provider","provider":"old","reference":"existing"}
            record["keys"]["other"]["hosts"] = ["legacy-alias"]
            run(*vault_fnox, "set", "SSHP_VAULT", "--provider", "age", env=direct_fnox,
                data=json.dumps(record).encode())
            assert b"legacy (needs key relink)" in run(CLI, "key", "list", env=restored).stdout
            restore_cfg = {**restored, "SSHP_FNOX_CONFIG": str(cfg)}
            before = vf.read_bytes()
            wrong = run(CLI, "key", "relink", "other", "--fnox-secret", "WORK_SSH", env=restore_cfg, code=None)
            assert wrong.returncode and b"pinned public key" in wrong.stderr and before == vf.read_bytes()
            run(*store, d / "unrelated", env=env3)
            run(CLI, "key", "relink", "other", "--fnox-secret", "WORK_SSH", env=restore_cfg)
            migrated = run(CLI, "key", "list", env=restore_cfg).stdout
            assert b"external (fnox)\tlegacy-alias" in migrated and b"encrypted in Git (age)" in migrated
            updated = json.loads(run(*vault_fnox, "get", "SSHP_VAULT", env=direct_fnox).stdout)
            assert updated["version"] == 2 and "providers" not in updated
            assert updated["keys"]["other"]["source"] == {"type":"fnox","secret":"WORK_SSH"}
            assert run(CLI, "config", "export", env=restore_cfg).stdout == expected
            print("Passed: lossless config round trip, TUI edit, selected export, "
                  "agent list/sign/lock/unlock/idle, passphrase-protected identity, encrypted Git restore"
                  ", named fnox secrets across providers, missing/changed keys and v1 relink"
                  + ("" if args.agent_only else ", assigned-only sshd login, quoting/status, Git/scp/sftp"))


if __name__ == "__main__":
    main()
