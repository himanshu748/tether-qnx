"""Parser and writer for the subset of the QNX security policy language that
secpolgenerate emits (types, ability rules, channel/class rules, allow_attach)."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

FLAGS = {"nonroot", "unlock", "unlocked", "noinherit"}


@dataclass
class AbilityRule:
    subject: str
    target: str
    abilities: dict[str, list[str]] = field(default_factory=dict)
    flags: list[str] = field(default_factory=list)

    def render(self) -> str:
        body = [f"    {f}" for f in self.flags]
        for name, ranges in self.abilities.items():
            body.append(f"    {name}:{','.join(ranges)}" if ranges else f"    {name}")
        return f"allow {self.subject} {self.target}:ability {{\n" + "\n".join(body) + "\n};"


@dataclass
class ClassRule:
    subject: str
    target: str
    klass: str
    perms: list[str]

    def render(self) -> str:
        perms = self.perms[0] if len(self.perms) == 1 else "{ " + " ".join(self.perms) + " }"
        return f"allow {self.subject} {self.target}:{self.klass} {perms};"


@dataclass
class AttachRule:
    subject: str
    path: str
    ftype: str | None = None

    def render(self) -> str:
        return f"allow_attach {self.subject} {self.path}" + (f" {self.ftype};" if self.ftype else ";")


@dataclass
class Policy:
    types: list[str] = field(default_factory=list)
    rules: list = field(default_factory=list)
    other: list[str] = field(default_factory=list)

    def rules_for(self, subject: str) -> list:
        return [r for r in self.rules if r.subject == subject]

    def abilities_of(self, subject: str) -> dict[str, list[str]]:
        merged: dict[str, list[str]] = {}
        for r in self.rules_for(subject):
            if isinstance(r, AbilityRule):
                for name, ranges in r.abilities.items():
                    merged.setdefault(name, [])
                    merged[name] += [x for x in ranges if x not in merged[name]]
        return merged

    def render(self) -> str:
        out = [f"type {t};" for t in self.types] + self.other + [r.render() for r in self.rules]
        return "\n".join(out) + "\n"


def _statements(text: str) -> list[str]:
    text = re.sub(r"#[^\n]*", "", text)
    stmts, buf, depth = [], [], 0
    for ch in text:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        if ch == ";" and depth == 0:
            s = " ".join("".join(buf).split())
            if s:
                stmts.append(s)
            buf = []
        else:
            buf.append(ch)
    return stmts


_ALLOW = re.compile(r"^allow\s+(\S+)\s+(\S+?)\s*:\s*(\S+)\s*(.*)$", re.S)


def _parse_abilities(body: str) -> tuple[dict[str, list[str]], list[str]]:
    abilities: dict[str, list[str]] = {}
    flags: list[str] = []
    body = re.sub(r"\s*([:,])\s*", r"\1", body)
    for item in body.split():
        if ":" in item:
            name, ranges = item.split(":", 1)
            abilities.setdefault(name.strip(), []).extend(x.strip() for x in ranges.split(",") if x.strip())
        elif item in FLAGS:
            flags.append(item)
        else:
            abilities.setdefault(item, [])
    return abilities, flags


def parse(text: str) -> Policy:
    pol = Policy()
    for s in _statements(text):
        if s.startswith("type "):
            pol.types += [t.strip() for t in s[5:].split(",")]
        elif s.startswith("allow_attach "):
            head, _, rest = s[len("allow_attach "):].partition(" ")
            if rest.lstrip().startswith("{"):
                paths, _, tail = rest.lstrip()[1:].partition("}")
                ftype = tail.split()[0] if tail.split() else None
                pol.rules += [AttachRule(head, x, ftype) for x in paths.split()]
            else:
                parts = rest.split()
                pol.rules.append(AttachRule(head, parts[0], parts[1] if len(parts) > 1 else None))
        elif (m := _ALLOW.match(s)) is not None:
            subject, target, klass, rest = m.groups()
            rest = rest.strip()
            inner = rest[1:-1] if rest.startswith("{") else rest
            if klass == "ability":
                abilities, flags = _parse_abilities(inner)
                pol.rules.append(AbilityRule(subject, target, abilities, flags))
            else:
                pol.rules.append(ClassRule(subject, target, klass, inner.split()))
        else:
            pol.other.append(s + ";")
    return pol
