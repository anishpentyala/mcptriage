"""Render findings as text or JSON."""

from __future__ import annotations

import json
from typing import List

from .rules import Finding, redact

_LABEL = {"high": "HIGH", "medium": "MED ", "low": "LOW "}


def render_text(findings: List[Finding], source: str) -> str:
    lines = []
    if not findings:
        return "mcptriage: no problems found in %s" % redact(source)
    lines.append("mcptriage: %d finding(s) in %s" % (len(findings), redact(source)))
    for f in findings:
        lines.append("")
        lines.append("[%s] %s: %s" % (_LABEL.get(f.severity, "?"), f.code, redact(f.title)))
        lines.append("  evidence: %s" % redact(f.evidence))
        lines.append("  why: %s" % redact(f.why))
        lines.append("  fix: %s" % redact(f.fix))
    return "\n".join(lines)


def render_json(findings: List[Finding], source: str) -> str:
    payload = {
        "source": redact(source),
        "finding_count": len(findings),
        "findings": [
            {
                "code": f.code,
                "severity": f.severity,
                "title": redact(f.title),
                "evidence": redact(f.evidence),
                "why": redact(f.why),
                "fix": redact(f.fix),
            }
            for f in findings
        ],
    }
    return json.dumps(payload, indent=2)
