"""Render findings as text or JSON."""

from __future__ import annotations

import json
from typing import List

from .rules import Finding

_LABEL = {"high": "HIGH", "medium": "MED ", "low": "LOW "}


def render_text(findings: List[Finding], source: str) -> str:
    lines = []
    if not findings:
        return "mcptriage: no problems found in %s" % source
    lines.append("mcptriage: %d finding(s) in %s" % (len(findings), source))
    for f in findings:
        lines.append("")
        lines.append("[%s] %s: %s" % (_LABEL.get(f.severity, "?"), f.code, f.title))
        lines.append("  evidence: %s" % f.evidence)
        lines.append("  why: %s" % f.why)
        lines.append("  fix: %s" % f.fix)
    return "\n".join(lines)


def render_json(findings: List[Finding], source: str) -> str:
    payload = {
        "source": source,
        "finding_count": len(findings),
        "findings": [
            {
                "code": f.code,
                "severity": f.severity,
                "title": f.title,
                "evidence": f.evidence,
                "why": f.why,
                "fix": f.fix,
            }
            for f in findings
        ],
    }
    return json.dumps(payload, indent=2)
