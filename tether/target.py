"""Drive a QNX 8.0 virtual machine built by mkqnximage over ssh.

Everything the pipeline does on the target is one of these commands, kept
separate from execution so it can be inspected and tested on the host.
"""
from __future__ import annotations

import os
import shlex
import subprocess
from dataclasses import dataclass

STATE_FILE = "/var/tether.state"
POLICY_DEV = "/dev/secpolgenerate/policy"
UNUSED_DEV = "/dev/secpolgenerate/unused"
ERRORS_DEV = "/dev/secpolgenerate/errors"


@dataclass
class Target:
    host: str = "localhost"
    port: int = 6022
    user: str = "root"
    identity: str | None = None
    timeout: int = 60
    known_hosts: str = "~/.config/tether/known_hosts"

    def _host_opts(self) -> list[str]:
        kh = os.path.expanduser(self.known_hosts)
        os.makedirs(os.path.dirname(kh), exist_ok=True)
        return ["-o", "StrictHostKeyChecking=accept-new", "-o", f"UserKnownHostsFile={kh}"]

    def ssh_argv(self, command: str) -> list[str]:
        argv = ["ssh", "-p", str(self.port), *self._host_opts(), "-o", "LogLevel=ERROR",
                "-o", f"ConnectTimeout={self.timeout}"]
        if self.identity:
            argv += ["-i", self.identity]
        return argv + [f"{self.user}@{self.host}", command]

    def scp_argv(self, local: str, remote: str) -> list[str]:
        argv = ["scp", "-P", str(self.port), *self._host_opts(), "-o", "LogLevel=ERROR"]
        if self.identity:
            argv += ["-i", self.identity]
        return argv + [local, f"{self.user}@{self.host}:{remote}"]

    def run(self, command: str, check: bool = True) -> subprocess.CompletedProcess:
        return subprocess.run(self.ssh_argv(command), capture_output=True, text=True,
                              check=check, timeout=self.timeout * 10)

    def put(self, local: str, remote: str) -> None:
        subprocess.run(self.scp_argv(local, remote), capture_output=True, text=True,
                       check=True, timeout=self.timeout * 10)

    def cat(self, path: str) -> str:
        return self.run(f"cat {shlex.quote(path)}", check=False).stdout


def observe_cmd(state_file: str = STATE_FILE) -> str:
    """Start secpolgenerate from scratch, logging errors, saving state."""
    return f"secpolgenerate -N -n -l -f 1 -s {shlex.quote(state_file)} &"


def launch_cmd(binary: str, type_name: str, args: str = "") -> str:
    """Run the application under its own security type so its use of privilege is
    attributed to that type rather than to the shell's."""
    return f"secpollaunch -t {shlex.quote(type_name)} {shlex.quote(binary)} {args}".strip()


def push_cmd(policy_bin: str) -> str:
    return f"secpolpush {shlex.quote(policy_bin)}"


def compile_cmd(source: str, out: str) -> str:
    return f"secpolcompile -o {shlex.quote(out)} {shlex.quote(source)}"


def stop_cmd() -> str:
    return "slay -f -S SIGTERM secpolgenerate"
