"""Indirect-injection screening for documents the model is asked to read.

Retrieved text sits at a lower trust tier than the user. It gets the same L1/L2 pass,
and any strong finding quarantines that document instead of rejecting the whole request.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

import regex

from core.models import RequestContext
from core.prevention.spotlight import ContextDocument

from .l1_pattern_engine import PatternEngine, run_l1
from .l2_sanitizer import run_l2

_STEALTH = regex.compile(
    r"(?i)display\s*:\s*none|font-size\s*:\s*0|visibility\s*:\s*hidden|opacity\s*:\s*0|color\s*:\s*(?:white|#fff)\b")
QUARANTINE_SEVERITY = 7


@dataclass
class DocumentReport:
    source: str
    quarantined: bool
    max_severity: int
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"source": self.source[:80], "quarantined": self.quarantined,
                "max_severity": self.max_severity, "reasons": self.reasons[:4]}


def screen_documents(documents: List[ContextDocument], engine: PatternEngine, policy=None):
    """Return (documents safe to include, per-document reports)."""
    safe, reports = [], []
    for doc in documents:
        ctx = RequestContext(raw_input=doc.text, policy=policy)
        run_l2(ctx, None)
        run_l1(ctx, engine)
        reasons = [f.evidence[:120] for f in ctx.flags if f.severity >= QUARANTINE_SEVERITY]
        severity = ctx.max_severity
        if _STEALTH.search(doc.text):
            severity = max(severity, 7)
            reasons.append("Styling that hides text from readers")
        quarantined = severity >= QUARANTINE_SEVERITY
        reports.append(DocumentReport(doc.source, quarantined, severity, reasons))
        if not quarantined:
            safe.append(ContextDocument(doc.source, ctx.llm_safe_input))
    return safe, reports
