from tether.secpol import AbilityRule, AttachRule, ClassRule, parse

SAMPLE = """
# generated
type sensord_t, logger_t;
allow sensord_t self:ability {
    nonroot
    mem_phys:1024-4096, 0x1200000-0x24000000
    setuid:4-6,23
    public_channel
};
allow sensord_t logger_t:channel connect;
allow sensord_t file_t:file { read write };
allow_attach sensord_t /dev/sensor;
allow_attach io_sock_t /dev/socket/* socket_t;
default_spawn_type sensord_t child_t;
"""


def test_parse_kinds():
    p = parse(SAMPLE)
    assert p.types == ["sensord_t", "logger_t"]
    ab = p.rules[0]
    assert isinstance(ab, AbilityRule) and ab.flags == ["nonroot"]
    assert ab.abilities == {
        "mem_phys": ["1024-4096", "0x1200000-0x24000000"],
        "setuid": ["4-6", "23"],
        "public_channel": [],
    }
    assert p.rules[1] == ClassRule("sensord_t", "logger_t", "channel", ["connect"])
    assert p.rules[2].perms == ["read", "write"]
    assert p.rules[4] == AttachRule("io_sock_t", "/dev/socket/*", "socket_t")
    assert p.other == ["default_spawn_type sensord_t child_t;"]


def test_roundtrip_is_stable():
    once = parse(SAMPLE).render()
    assert parse(once).render() == once


def test_abilities_merge_across_rules():
    p = parse("allow a self:ability { setuid:1 };allow a self:ability { setuid:1,2 io };")
    assert p.abilities_of("a") == {"setuid": ["1", "2"], "io": []}
