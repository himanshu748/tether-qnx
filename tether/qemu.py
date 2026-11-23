"""Build and boot a QNX 8.0 QEMU image with mkqnximage (run qnxsdp-env.sh first)."""
from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from .target import Target


@dataclass
class Vm:
    image_dir: Path
    ssh_ident: str = "~/.ssh/id_ed25519.pub"
    memory: str = "1G"

    def build_argv(self, secpol: str, policy: str | None = None) -> list[str]:
        """secpol 'open' boots with secpolgenerate observing; 'secure' enforces policy."""
        return ["mkqnximage", "--type=qemu", f"--secpol={secpol}",
                f"--policy={Path(policy).resolve() if policy else 'none'}",
                f"--ssh-ident={os.path.expanduser(self.ssh_ident)}",
                "--sshd-pregen=yes", "--data-size=200"]

    def qemu_argv(self, port: int) -> list[str]:
        out = self.image_dir / "output"
        kvm = ["--enable-kvm", "-cpu", "host"] if os.path.exists("/dev/kvm") else []
        return ["qemu-system-x86_64", "-smp", "2", *kvm, "-m", self.memory,
                "-drive", f"file={out / 'disk-qemu.vmdk'},if=ide,id=drv0",
                "-netdev", f"user,id=net0,hostfwd=tcp:127.0.0.1:{port}-:22",
                "-device", "virtio-net-pci,netdev=net0",
                "-kernel", str(out / "ifs.bin"), "-serial", f"file:{out / 'qemu.out'}",
                "-object", "rng-random,filename=/dev/urandom,id=rng0",
                "-device", "virtio-rng-pci,rng=rng0",
                "-display", "none", "-pidfile", str(out / "qemu.pid"), "-daemonize"]

    def build(self, secpol: str, policy: str | None = None) -> None:
        if not shutil.which("mkqnximage"):
            raise RuntimeError("mkqnximage not found: source qnxsdp-env.sh from QNX SDP 8.0 first")
        self.image_dir.mkdir(parents=True, exist_ok=True)
        subprocess.run(self.build_argv(secpol, policy), cwd=self.image_dir, check=True,
                       capture_output=True, text=True)

    def pin_host_keys(self, t: Target) -> None:
        """Trust exactly the sshd keys mkqnximage pregenerated for this image."""
        keys = sorted((self.image_dir / "local" / "misc_files").glob("ssh_host_*_key.pub"))
        if not keys:
            raise FileNotFoundError(f"no pregenerated sshd keys under {self.image_dir}")
        kh = self.image_dir / "known_hosts"
        kh.write_text("".join(f"[{t.host}]:{t.port} {k.read_text().split(' ')[0]} "
                              f"{k.read_text().split(' ')[1].strip()}\n" for k in keys))
        t.known_hosts = str(kh)

    def boot(self, t: Target, wait: int = 120) -> None:
        self.stop()
        self.pin_host_keys(t)
        subprocess.run(self.qemu_argv(t.port), check=True)
        deadline = time.time() + wait
        while time.time() < deadline:
            if t.run("true", check=False).returncode == 0:
                return
            time.sleep(3)
        raise TimeoutError(f"QNX did not answer ssh on port {t.port} within {wait}s")

    def stop(self) -> None:
        pid = self.image_dir / "output" / "qemu.pid"
        if pid.exists():
            try:
                os.kill(int(pid.read_text()), 15)
            except (ProcessLookupError, ValueError):
                pass
            pid.unlink()
            time.sleep(1)


def compile_policy(source: str, out: str) -> None:
    """Host-side secpolcompile; raises with its message if the policy is invalid."""
    r = subprocess.run(["secpolcompile", "-o", out, source], capture_output=True, text=True)
    if r.returncode:
        raise RuntimeError(f"secpolcompile failed: {r.stderr.strip() or r.stdout.strip()}")
