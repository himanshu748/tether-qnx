from pathlib import Path

from tether.qemu import Vm


def test_build_argv_open_has_no_policy():
    argv = Vm(Path("/img"), ssh_ident="/k.pub").build_argv("open")
    assert "--secpol=open" in argv and "--policy=none" in argv
    assert "--ssh-ident=/k.pub" in argv


def test_build_argv_secure_points_at_policy(tmp_path):
    pol = tmp_path / "system.secpol"
    argv = Vm(tmp_path).build_argv("secure", str(pol))
    assert "--secpol=secure" in argv and f"--policy={pol}" in argv


def test_qemu_forwards_ssh_on_loopback_only():
    argv = Vm(Path("/img")).qemu_argv(6022)
    assert "user,id=net0,hostfwd=tcp:127.0.0.1:6022-:22" in argv
    assert argv[argv.index("-kernel") + 1] == "/img/output/ifs.bin"


def test_boot_pins_the_image_sshd_keys(tmp_path):
    from tether.target import Target
    misc = tmp_path / "local" / "misc_files"
    misc.mkdir(parents=True)
    (misc / "ssh_host_ed25519_key.pub").write_text("ssh-ed25519 AAAAkey root@qnx\n")
    t = Target()
    Vm(tmp_path).pin_host_keys(t)
    assert t.known_hosts == str(tmp_path / "known_hosts")
    assert (tmp_path / "known_hosts").read_text() == "[localhost]:6022 ssh-ed25519 AAAAkey\n"
