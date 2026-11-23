import json

from tether.cli import main


def test_tighten_writes_policy_and_summary(tmp_path):
    obs = tmp_path / "policy"
    obs.write_text("type app_t;\nallow app_t self:ability { nonroot spawn };\nallow x_t self:ability { io };\n")
    out, js = tmp_path / "app.secpol", tmp_path / "app.json"
    assert main(["tighten", str(obs), "--type", "app_t", "-o", str(out), "--json", str(js)]) == 0
    assert "x_t" not in out.read_text() and "spawn" in out.read_text()
    summary = json.loads(js.read_text())
    assert "setuid" in summary["withheld"] and summary["grants"][0]["name"] == "spawn"


def test_tighten_fails_on_unknown_type(tmp_path):
    obs = tmp_path / "policy"
    obs.write_text("type a_t;\n")
    assert main(["tighten", str(obs), "--type", "nope_t"]) == 1


def test_tighten_emits_type_only_policy_when_all_unused(tmp_path):
    obs, unused = tmp_path / "policy", tmp_path / "unused"
    obs.write_text("type app_t;\nallow app_t self:ability { spawn };\n")
    unused.write_text("allow app_t self:ability { spawn };\n")
    out, js = tmp_path / "app.secpol", tmp_path / "app.json"
    args = ["tighten", str(obs), "--type", "app_t", "--unused", str(unused), "-o", str(out), "--json", str(js)]
    assert main(args) == 0
    assert "type app_t;" in out.read_text() and "spawn" not in out.read_text()
    assert json.loads(js.read_text())["grants"] == []
