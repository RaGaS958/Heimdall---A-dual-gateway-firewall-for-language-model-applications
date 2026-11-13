"""O4: tool and exfiltration validator.

Models echo attacker-supplied links. The dangerous forms are the ones that fire without
a click, such as an auto-loading image whose URL carries conversation data, so those are
stripped. A normal link in prose is left alone; flagging every URL used to send most
informative answers to the arbiter.
"""
from __future__ import annotations

import re
from typing import List, Optional, Tuple

from core.models import AttackFamily, Flag, FlagSource, RequestContext

MD_IMAGE = re.compile(r"!\[[^\]]{0,300}\]\(\s*(https?:)?//[^)\s]+[^)]*\)", re.I)
HTML_ACTIVE = re.compile(r"<\s*(?:img|iframe|script|object|embed|link|meta|svg|form|video|audio|style)\b[^>]*>", re.I)
HTML_SCRIPT_BLOCK = re.compile(r"<\s*script\b.*?<\s*/\s*script\s*>", re.I | re.S)
JS_URL = re.compile(r"\]\(\s*(?:javascript|data|vbscript):[^)]*\)", re.I)
URL = re.compile(r"https?://[^\s)>\]\"']+", re.I)
SUSPICIOUS_QUERY = re.compile(r"[?&#][^=\s]{0,20}=(?:[A-Za-z0-9+/_%\-]{40,})")
EMAIL_WORM = re.compile(r"(?i)\b(?:send|forward|email)\b.{0,40}\b(?:to all|to everyone|all (?:your |my )?contacts|mailing list)\b.{0,80}\b(?:this message|this email|the following|attachment|link)\b")
EXFIL = re.compile(r"(?i)\b(?:upload|post|send|transmit|exfiltrate)\b.{0,40}\b(?:credentials?|api keys?|secrets?|passwords?|tokens?|conversation history|system prompt)\b.{0,40}\b(?:to|at)\s+(?:https?://|http|the (?:server|endpoint|webhook)|attacker)")
SHELL_PIPE = re.compile(r"(?i)\b(?:curl|wget)\b[^\n]{0,120}\|\s*(?:ba|z)?sh\b")
DESTRUCTIVE = re.compile(r"(?i)\brm\s+-rf\s+/(?:\s|$)|\bformat\s+c:|:\(\)\s*\{\s*:\|:&\s*\}")


# Fenced blocks (``` or ~~~, closed) and inline `code` spans. A markdown or plain-text renderer
# shows them as text, so markup inside them cannot load or run there.
CODE_SPAN = re.compile(r"(?s)(```.*?```|~~~.*?~~~|`[^`\n]+`)")


def _keep_code() -> bool:
    from config.settings import get_settings
    return get_settings().g2_code_blocks == "keep"


def _prose_parts(output: str, keep_code: bool) -> List[Tuple[str, bool]]:
    """(part, is_code) pieces. Without keep_code the whole answer is treated as prose."""
    if not keep_code:
        return [(output, False)]
    return [(part, bool(i % 2)) for i, part in enumerate(CODE_SPAN.split(output)) if part]


def has_active_content(output: str, keep_code: Optional[bool] = None) -> bool:
    keep = _keep_code() if keep_code is None else keep_code
    return any(p.search(part) for part, code in _prose_parts(output, keep) if not code
               for p in (MD_IMAGE, HTML_ACTIVE, JS_URL))


def strip_active_content(output: str, keep_code: Optional[bool] = None) -> Tuple[str, int]:
    """Remove auto-loading content and scriptable markup. Returns (text, removed count).

    G2_CODE_BLOCKS=keep leaves markup inside code blocks alone, for deployments whose clients render
    answers as markdown or plain text (Heimdall's own frontend does). The default strips everywhere,
    because a client that renders raw HTML would load an <img> even inside backticks."""
    keep = _keep_code() if keep_code is None else keep_code
    total, out = 0, []
    for part, code in _prose_parts(output, keep):
        if not code:
            for pattern, replacement in ((MD_IMAGE, "[image removed by HEIMDALL]"),
                                         (HTML_SCRIPT_BLOCK, "[script removed by HEIMDALL]"),
                                         (HTML_ACTIVE, "[active content removed by HEIMDALL]"),
                                         (JS_URL, "](#)")):
                part, count = pattern.subn(replacement, part)
                total += count
        out.append(part)
    return "".join(out), total


class ToolValidator:
    def validate(self, ctx: RequestContext) -> List[Flag]:
        output = ctx.llm_raw_output
        flags: List[Flag] = []

        def add(severity, confidence, evidence, family=AttackFamily.TOOL_WEAPONIZATION):
            flags.append(Flag(source=FlagSource.TOOL, severity=severity, confidence=confidence,
                              attack_families=[family], evidence=evidence))

        if has_active_content(output):
            add(5, 0.8, "O4 auto-loading or scriptable content in output", AttackFamily.DATA_EXFILTRATION)

        for link in URL.findall(output):
            if SUSPICIOUS_QUERY.search(link) and link not in ctx.raw_input:
                add(8, 0.85, "O4 URL carries a long encoded payload", AttackFamily.DATA_EXFILTRATION)
                break

        if EMAIL_WORM.search(output):
            add(9, 0.9, "O4 potential email worm pattern detected")
        if EXFIL.search(output):
            add(8, 0.85, "O4 data exfiltration instruction detected", AttackFamily.DATA_EXFILTRATION)
        if SHELL_PIPE.search(output) and "curl" not in ctx.raw_input.lower() and "wget" not in ctx.raw_input.lower():
            add(7, 0.8, "O4 pipes a remote download into a shell")
        if DESTRUCTIVE.search(output):
            add(7, 0.8, "O4 destructive command in output")
        return flags
