#!/usr/bin/env python3
"""Run on Linux under dbus-run-session: a private desktop lock service and real sshp-agent."""
import os
import pathlib
import subprocess
import sys
import tempfile
import time

import dbus
import dbus.service
from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GLib

SERVICE = "org.freedesktop.ScreenSaver"
PATH = "/org/freedesktop/ScreenSaver"
CLI = pathlib.Path(__file__).resolve().parents[1] / "target/debug/sshp"


class Locker(dbus.service.Object):
    active = True

    @dbus.service.method(SERVICE, out_signature="b")
    def GetActive(self):
        return self.active

    @dbus.service.method(SERVICE, in_signature="b")
    def SetActive(self, active):
        self.active = active
        self.ActiveChanged(active)

    @dbus.service.signal(SERVICE, signature="b")
    def ActiveChanged(self, active):
        pass


def test(d):
    env = {**os.environ, "HOME": str(d), "XDG_CONFIG_HOME": str(d / "config"),
           "SSHP_REPO": str(d / "vault"), "SSHP_RUNTIME_DIR": str(d / "run"),
           "SSH_AUTH_SOCK": str(d / "run/agent.sock")}

    def run(*args, ok=True):
        r = subprocess.run(args, env=env, capture_output=True, timeout=15)
        assert (r.returncode == 0) == ok, (args[:4], r.stderr.decode())
        return r.stdout

    run("age-keygen", "-o", d / "age")
    run(CLI, "settings", "set", "age-key-file", d / "age")
    run(CLI, "init", "--recipient", run("age-keygen", "-y", d / "age").decode().strip())
    run("ssh-keygen", "-qt", "ed25519", "-N", "", "-f", d / "key")
    run(CLI, "key", "import", "fixture", d / "key")
    run(CLI, "settings", "set", "agent-lock", "machine-lock")
    run(CLI, "agent", "start", ok=False)  # no available desktop monitor
    locker = subprocess.Popen([sys.executable, __file__, "--locker"], stdout=subprocess.PIPE)
    try:
        assert locker.stdout.readline() == b"ready\n"
        run(CLI, "agent", "start")
        assert b"machine-lock" in run(CLI, "agent", "status")
        service = dbus.Interface(dbus.SessionBus().get_object(SERVICE, PATH), SERVICE)
        run(CLI, "agent", "unlock", ok=False)  # already screen-locked at startup
        service.SetActive(False)
        run(CLI, "agent", "unlock")
        run("ssh-add", "-T", d / "key.pub")
        # Even adjacent lock/unlock signals must revoke the loaded generation.
        service.SetActive(True)
        service.SetActive(False)
        wait_locked(d)
        run("ssh-add", "-T", d / "key.pub", ok=False)
        run(CLI, "agent", "unlock")
        run("ssh-add", "-T", d / "key.pub")
        locker.terminate()
        locker.wait(timeout=5)
        wait_locked(d)
        run(CLI, "agent", "unlock", ok=False)
        run("ssh-add", "-T", d / "key.pub", ok=False)
    finally:
        locker.terminate()
        locker.wait(timeout=5)
        run(CLI, "agent", "stop")


def wait_locked(d):
    for _ in range(150):
        if not (d / "run/managed.conf").exists() and not (d / "run/identities").exists():
            return
        time.sleep(.02)
    raise AssertionError("lock did not revoke the managed configuration and identities")


if __name__ == "__main__":
    if sys.argv[1:] == ["--locker"]:
        DBusGMainLoop(set_as_default=True)
        name = dbus.service.BusName(SERVICE, bus=dbus.SessionBus(), do_not_queue=True)
        locker = Locker(name, PATH)
        print("ready", flush=True)
        GLib.MainLoop().run()
    else:
        # Never claim a name on a real user's desktop bus.
        if sys.argv[1:] != ["--private-bus"]:
            os.execvp("dbus-run-session", ["dbus-run-session", "--", sys.executable,
                                          __file__, "--private-bus"])
        with tempfile.TemporaryDirectory(prefix="sshp-screen-") as tmp:
            test(pathlib.Path(tmp))
        print("Passed: desktop lock revokes signing, unlock does not reload, monitor loss fails closed")
