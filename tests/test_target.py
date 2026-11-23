from tether.target import Target, compile_cmd, launch_cmd, observe_cmd, push_cmd


def test_ssh_argv_includes_port_and_identity():
    t = Target(port=6022, identity="/k/id")
    argv = t.ssh_argv("ls /")
    assert argv[:3] == ["ssh", "-p", "6022"]
    assert "-i" in argv and argv[argv.index("-i") + 1] == "/k/id"
    assert argv[-2:] == ["root@localhost", "ls /"]


def test_scp_argv_uses_capital_p():
    assert Target().scp_argv("a", "/b")[:3] == ["scp", "-P", "6022"]


def test_commands_quote_arguments():
    assert observe_cmd("/var/my state").endswith("-s '/var/my state' &")
    assert launch_cmd("/bin/telemetryd", "telemetry_t", "-d") == (
        "secpollaunch -t telemetry_t /bin/telemetryd -d")
    assert push_cmd("/tmp/p.bin") == "secpolpush /tmp/p.bin"
    assert compile_cmd("/tmp/p.secpol", "/tmp/p.bin") == (
        "secpolcompile -o /tmp/p.bin /tmp/p.secpol")
