"""Turn the policy secpolgenerate observed into a least-privilege policy for one
application type, and explain what it grants."""
from __future__ import annotations

import re
from dataclasses import dataclass

from .secpol import AbilityRule, AttachRule, ClassRule, Policy

# Abilities whose misuse gives a compromised process control over others or the
# machine. Score 3 = system takeover, 2 = escape or persistence, 1 = notable.
RISK = {
    "setuid": 3, "setgid": 3, "spawn_setuid": 3, "spawn_setgid": 3, "settypeid": 3,
    "mem_phys": 3, "mem_peer": 3, "io": 3, "interrupt": 3, "xprocess_debug": 3,
    "xprocess_mem_read": 3, "able_priv": 3, "mac_policy": 3, "path_trust": 3,
    "prot_write_and_exec": 3, "untrusted_exec": 3, "reboot": 3, "clockset": 2,
    "pathspace": 2, "public_channel": 2, "spawn": 2, "fork": 2, "trace": 2,
    "mountifs": 2, "chroot": 2, "signal": 2, "rsrcdbmgr": 2, "prot_exec": 1,
    "priority": 1, "rlimit": 1, "map_fixed": 1, "mem_lock": 1, "channel_connect": 1,
}


@dataclass
class Grant:
    kind: str  # ability | attach | channel | <class>
    name: str
    detail: str
    risk: int


def _subtract(rule, unused: list):
    """Remove the grants unused lists from rule; None when nothing is left."""
    if isinstance(rule, AttachRule):
        return None if any(isinstance(u, AttachRule) and u.render() == rule.render()
                           for u in unused) else rule
    same = [u for u in unused if type(u) is type(rule) and u.target == rule.target
            and sorted(getattr(u, "flags", [])) == sorted(getattr(rule, "flags", []))]
    if isinstance(rule, ClassRule):
        gone = {p for u in same if u.klass == rule.klass for p in u.perms}
        perms = [p for p in rule.perms if p not in gone]
        return ClassRule(rule.subject, rule.target, rule.klass, perms) if perms else None
    abilities = {}
    for name, ranges in rule.abilities.items():
        gone = [u.abilities[name] for u in same if name in u.abilities]
        if any(not g for g in gone):
            continue
        left = [x for x in ranges if not any(x in g for g in gone)]
        if left or not ranges:
            abilities[name] = left
    return AbilityRule(rule.subject, rule.target, abilities, rule.flags) if abilities else None


def extract(observed: Policy, app_type: str, unused: Policy | None = None) -> Policy:
    """Keep only the rules whose subject is app_type, minus anything secpolgenerate
    reported as unused, plus the declarations they reference."""
    drop = unused.rules_for(app_type) if unused else []
    rules = [r for r in (_subtract(r, drop) for r in observed.rules_for(app_type)) if r]
    needed = [app_type]
    for r in rules:
        if isinstance(r, ClassRule) and r.target != "self":
            needed.append(r.target)
        if isinstance(r, AbilityRule):
            for n in ("channel_connect", "settypeid"):
                needed += r.abilities.get(n, [])
        if isinstance(r, AttachRule) and r.ftype:
            needed.append(r.ftype)
    types = [t for t in observed.types if t in needed]
    types += [t for t in dict.fromkeys(needed) if t not in types]
    foreign = set(observed.types) - set(types)
    other = [o for o in observed.other if not foreign & set(re.findall(r"\w+", o))]
    return Policy(types=types, rules=rules, other=other)


def grants(policy: Policy, app_type: str) -> list[Grant]:
    out: list[Grant] = []
    for r in policy.rules_for(app_type):
        if isinstance(r, AbilityRule):
            for name, ranges in r.abilities.items():
                unbounded = not ranges or any(x.endswith("-") for x in ranges)
                risk = RISK.get(name, 0)
                if risk and not unbounded:
                    risk -= 1
                out.append(Grant("ability", name, ",".join(ranges) or "any", risk))
        elif isinstance(r, AttachRule):
            wild = r.path.endswith("/...") or r.path == "/"
            out.append(Grant("attach", r.path, r.ftype or "", 2 if wild else 1))
        elif isinstance(r, ClassRule):
            out.append(Grant(r.klass, r.target, " ".join(r.perms), 1 if r.klass == "channel" else 0))
    return sorted(out, key=lambda g: (-g.risk, g.kind, g.name))


def denied(root_abilities: list[str], policy: Policy, app_type: str) -> list[str]:
    """Abilities a root process would have that this policy withholds."""
    held = set(policy.abilities_of(app_type))
    return sorted(a for a in root_abilities if a not in held)
