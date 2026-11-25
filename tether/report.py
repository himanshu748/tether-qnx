"""Render a self-contained HTML report for one tether run."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .tighten import Grant

TEMPLATE = Path(__file__).with_name("report_template.html")


@dataclass
class Run:
    app: str
    type_name: str
    image: str = "qnx800-qemu-x86_64"
    policy: str = ""
    grants: list[Grant] = field(default_factory=list)
    withheld: list[str] = field(default_factory=list)
    baseline_log: str = ""
    sandboxed_log: str = ""
    denials: list[str] = field(default_factory=list)
    blocked: bool = False

    def to_json(self) -> str:
        d = asdict(self)
        d["grants"] = [asdict(g) if not isinstance(g, dict) else g for g in self.grants]
        return json.dumps(d, indent=2)


def render(run: Run) -> str:
    data = json.dumps(json.loads(run.to_json())).replace("</", "<\\/")
    return TEMPLATE.read_text().replace("__RUN_DATA__", data)
