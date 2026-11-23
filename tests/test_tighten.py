from tether.secpol import parse
from tether.tighten import denied, extract, grants

OBSERVED = parse("""
type app_t, logd_t, other_t, sock_t;
allow app_t self:ability { nonroot public_channel channel_connect:logd_t setuid:0- };
allow app_t self:ability { prot_exec };
allow app_t logd_t:channel connect;
allow_attach app_t /dev/telemetry;
allow other_t self:ability { io mem_phys };
""")
UNUSED = parse("allow app_t self:ability { prot_exec };")


def test_extract_keeps_only_app_rules_and_referenced_types():
    p = extract(OBSERVED, "app_t", UNUSED)
    assert p.types == ["app_t", "logd_t"]
    assert all(r.subject == "app_t" for r in p.rules)
    assert "prot_exec" not in p.abilities_of("app_t")
    assert "other_t" not in p.render()


def test_grants_rank_unbounded_dangerous_first():
    g = grants(extract(OBSERVED, "app_t"), "app_t")
    assert (g[0].name, g[0].risk) == ("setuid", 3)
    bounded = next(x for x in g if x.name == "channel_connect")
    assert bounded.risk == 0


def test_denied_lists_withheld_root_abilities():
    p = extract(OBSERVED, "app_t")
    assert denied(["spawn", "setuid", "io"], p, "app_t") == ["io", "spawn"]


def test_extract_subtracts_single_unused_grant_from_grouped_rule():
    unused = parse("allow app_t self:ability { public_channel };")
    p = extract(OBSERVED, "app_t", unused)
    held = p.abilities_of("app_t")
    assert "public_channel" not in held and {"setuid", "channel_connect"} <= set(held)


def test_extract_keeps_declarations_and_undeclared_types():
    obs = parse("""
range cal_r 0x10 0x20;
allow app_t base_t:channel connect;
allow app_t self:ability { settypeid:cal_r };
""")
    out = extract(obs, "app_t").render()
    assert "type app_t;" in out and "type base_t;" in out
    assert "range cal_r" in out


def test_root_only_unused_grant_keeps_nonroot_grant():
    obs = parse("allow app_t self:ability { nonroot spawn };\nallow app_t self:ability { spawn };")
    p = extract(obs, "app_t", parse("allow app_t self:ability { spawn };"))
    assert [r.flags for r in p.rules] == [["nonroot"]] and "spawn" in p.abilities_of("app_t")


def test_extract_drops_other_types_link_rules():
    obs = parse("type app_t, logd_t;\nallow app_t logd_t:channel connect;\nallow_link logd_t /var/log;\nallow_link app_t /tmp/x;")
    out = extract(obs, "app_t").render()
    assert "allow_link app_t /tmp/x;" in out and "allow_link logd_t" not in out
