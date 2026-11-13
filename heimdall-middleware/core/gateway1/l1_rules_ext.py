"""L1 rules added in Phase 15.

Each family below was found by reading misses in the *development half* of the external
benchmark (evaluation/external/ext_dev.jsonl): player-written Tensor Trust attacks and
in-the-wild jailbreaks. The sealed half was never opened. Rules name a general technique;
phrases that only make sense inside one application (for example "say access granted")
are deliberately not matched, because a gateway cannot know an application's secret goal.

Severity follows l1_rules.py: 7 and above is a hard signal, 6 and below only counts
together with a second signal.
"""
from __future__ import annotations

from typing import List

from core.models import AttackFamily as F

from .l1_rules import _NONTECH_MODE, _STRONG, Rule as R

_REFORMAT = (r"(?:format|reformat|convert|translate|rewrite|rephrase|paraphrase|summari[sz]e|repeat|print|output|write|list|"
             r"explain|turn|transform|express|restate|recite|compose|complete|encode|describe|give|show|tell|provide|say|reply\s+(?:back\s+)?with)")
_OWN_TEXT = r"(?:instructions?|prompt|rules|directives?|guidelines)"
_PEM = r"(?i)BEGIN\s+(?:PGP|CERTIFICATE|RSA|OPENSSH|EC|DSA|PUBLIC|PRIVATE|ENCRYPTED)|END\s+(?:PGP|CERTIFICATE|RSA|OPENSSH|EC|DSA|PUBLIC|PRIVATE|ENCRYPTED)"
_CREDENTIAL_HELP = r"(?i)\b(?:reset|forgot|forgotten|recover|change|policy|policies|manager|strength|strong|hash|hashing|salt|best\s+practices?|generate|generator|create|choose|wifi|wi-fi|router|format|length|digits?|expires?|two-factor|2fa|riddle|play|game|story|novel)\b"

EXT_RULES: List[R] = [
    # ── Extraction by asking for the instructions in another form ──────────
    R(rf"(?is)\b{_REFORMAT}\b(?:\s+\w+){{0,5}}?\s+your\s+(?:\w+\s+){{0,2}}{_OWN_TEXT}\b", F.SYSTEM_EXTRACTION, 8,
      unless=r"(?i)\b(?:follow(?:ed|ing)?|understand|understood|clarify)\s+your\s+instructions"),
    R(rf"(?is)\b(?:rap|poem|sonnet|song|story|haiku|limerick|essay|joke|dialogue)\s+(?:on|about|of|describing|using)\s+(?:your|the\s+above|the\s+previous)\s+(?:\w+\s+){{0,2}}{_OWN_TEXT}\b", F.SYSTEM_EXTRACTION, 8),
    R(rf"(?is)\b{_OWN_TEXT}\s+(?:so\s+far|(?:that\s+)?you\s+(?:were|have\s+been|'ve\s+been)\s+given|given\s+to\s+you|you\s+received|above\s+and\s+below|i\s+have\s+given\s+you)\b", F.SYSTEM_EXTRACTION, 6),
    R(rf"(?is)\b{_REFORMAT}\b.{{0,40}}\b(?:rules|instructions|text|words|content|everything|prompt|messages?)\s+(?:above\s+and\s+below|below\s+and\s+above)\b", F.SYSTEM_EXTRACTION, 8),
    R(rf"(?is)\b{_REFORMAT}\b.{{0,40}}\b(?:rules|instructions|text|words|content|everything|prompt|messages?)\s+(?:above|before\s+this)\b", F.SYSTEM_EXTRACTION, 6),
    R(rf"(?is)\b{_REFORMAT}\b\s+(?:\w+\s+){{0,3}}?(?:the\s+|all\s+)?(?:above|preceding)\s+(?:words|text|instructions|rules|prompt|messages?|content)\b", F.SYSTEM_EXTRACTION, 6),
    R(r"(?is)\b(?:text|instructions?|prompt|message)\s+(?:that\s+)?you\s+were\s+(?:given|shown|sent)\s+(?:initially|first|at\s+the\s+(?:start|beginning)|before)\b", F.SYSTEM_EXTRACTION, 8),
    R(r"(?is)\b(?:start|begin)\s+(?:your\s+)?(?:response|reply|answer|output)\s+with\s+[\"'“‘]?(?:my\s+instructions|the\s+instructions|#\s*access|here(?:'s|\s+is|\s+are)\s+(?:the|my)\s+instructions)", F.SYSTEM_EXTRACTION, 8),
    R(r"(?i)\b(?:console\.log|print|echo|printf|puts|System\.out\.println)\s*\(?\s*[\"']?\$?\{?(?:system_?prompt|systemPrompt|initial_?prompt|instructions|system_?message)\b", F.SYSTEM_EXTRACTION, 8),
    R(r"(?is)\bpre-?instructions?\b|\bpost-?instructions?\b", F.SYSTEM_EXTRACTION, 6),

    # ── Secrets the application is holding ─────────────────────────────────
    R(r"(?is)\b(?:reveal|repeat|tell|print|output|append|write|give|say|show|state|disclose|leak|include|store|put|share)\b.{0,40}\b(?:the|your)\s+(?:secret|correct|real|actual|hidden)\s+(?:password|passcode|pass\s*phrase|access\s+code|code|key|phrase|word|character)\b", F.SYSTEM_EXTRACTION, 8, unless=_CREDENTIAL_HELP),
    R(r"(?is)\b(?:reveal|repeat|tell\s+me|print|output|append|disclose|leak|include|store|put)\b.{0,30}\b(?:the|your)\s+(?:password|passcode|pass\s*phrase|access\s+code)\b", F.SYSTEM_EXTRACTION, 7, unless=_CREDENTIAL_HELP),
    R(r"(?is)\bwhat(?:'s|\s+is|\s+was)\s+(?:the|your)\s+(?:secret\s+(?:password|passcode|code|key|phrase|word|character|message|instructions?)|secret\s*[?.!]|access\s+code|passcode)", F.SYSTEM_EXTRACTION, 7, unless=_CREDENTIAL_HELP),

    # ── Fake section boundaries and context flooding ───────────────────────
    R(r"(?im)^[ \t]*(?:%{2,}|={3,}|-{3,}|#{3,}|\*{3,}|~{3,})[ \t]*(?:end|begin|start|stop)\b[^\n]{0,60}?(?:%{2,}|={3,}|-{3,}|#{3,}|\*{3,}|~{3,})[ \t]*$", F.CONTEXT_MANIPULATION, 8, unless=_PEM),
    R(r"(?im)^[ \t]*\[[^\]\n]{0,40}\b(?:section|instructions?|prompt|rules|input|context)\s+(?:end|ends|ended|over)\][ \t]*$|^[ \t]*\[(?:end|begin|start)\s+(?:of\s+)?[^\]\n]{0,40}\b(?:section|instructions?|prompt|rules|input|context)\][ \t]*$", F.CONTEXT_MANIPULATION, 8),
    R(r"(?is)\b(?:instructions?|rules|prompt)\s+(?:above\s+|below\s+)?(?:are|is)\s+(?:now\s+)?(?:out\s+of\s+date|outdated|obsolete|expired|deprecated)\b|\bout[\s-]of[\s-]date\s+instructions?\b", F.INSTRUCTION_OVERRIDE, 8),

    # ── Amending or bypassing the rules without saying "ignore" ────────────
    R(r"(?is)\bkeep\s+(?:your|the)\s+(?:previous|prior|original|existing|current)\s+instructions?\s*,?\s+(?:but|however|and\s+also)\b", F.INSTRUCTION_OVERRIDE, 8),
    R(r"(?is)\bthe\s+situation\s+(?:has\s+)?changed\b.{0,120}\byou\s+(?:are|must|may|can|should|will)\s+now\b", F.INSTRUCTION_OVERRIDE, 8),
    R(rf"(?is)\b{_STRONG}\b\s+(?:any|all|the|every)?\s*(?:of\s+the\s+)?(?:input|text|content|messages?|words|everything|anything)\s+(?:written\s+|stated\s+|said\s+)?(?:above|below|before|after)\b", F.INSTRUCTION_OVERRIDE, 9),
    R(r"(?is)\b(?:forget|ignore|disregard)\s+everything\b.{0,40}\b(?:before\s+this|from\s+(?:chat\s*gpt|openai)|you\s+(?:have\s+|'ve\s+)?(?:been\s+told|learned|were\s+told))", F.INSTRUCTION_OVERRIDE, 8),

    # ── False claims that a check has already passed ───────────────────────
    R(r"(?is)\b(?:correct|valid|right|proper)\s+(?:password|passcode|access\s+code|code|credentials?|pin|key)\s+(?:has\s+been|was|is|were)\s+(?:already\s+)?(?:entered|input|inputted|provided|given|verified|registered|accepted|supplied|placed)\b", F.CONTEXT_MANIPULATION, 6),
    R(r"(?is)\b(?:consider|treat|assume|regard)\s+(?:that\s+)?(?:the|this|my)\s+(?:input|password|code|user|request|answer)\s+(?:is\s+|as\s+)?(?:valid|correct|verified|authentic\w*|authori[sz]ed)\b", F.CONTEXT_MANIPULATION, 8),
    R(r"(?i)\b(?:password|passcode|access\s+code)\s+(?:placed|accepted|verified|confirmed)\b", F.CONTEXT_MANIPULATION, 6),

    # ── Persona lock and planted conversation turns ────────────────────────
    R(r"(?is)\byour\s+(?:sole|only|single|default)\s+(?:response|reply|answer|output)\s+(?:is|will\s+be|should\s+be|must\s+be)\b", F.PERSONA_INJECTION, 7),
    R(r"(?is)\byou\s+have\s+no\s+knowledge\s+of\s+any\s+other\b", F.PERSONA_INJECTION, 6),
    R(r"(?is)\byou\s+can\s+only\s+(?:say|respond\s+with|reply\s+with|answer\s+with|output)\b|\b(?:say|output|respond\s+with|reply\s+with)\b.{0,60}\bin\s+response\s+to\s+any\s+(?:input|message|question|prompt)\b", F.PERSONA_INJECTION, 6),

    # ── Text that addresses whatever model reads it ────────────────────────
    # Planted in documents and pages: "If you are a language model, reply only with X". A person
    # asking the assistant about itself does not also dictate its exact output, so the directive
    # half is what makes it a hard signal. Found in every live run (12 November 2026).
    R(r"(?is)\bif\s+you(?:\s+are|'re|’re)\s+(?:an?\s+)?(?:ai|a\.i\.|(?:large\s+)?language\s+model|llm|chat\s*bot|assistant|gpt|bot|model)\b"
      r"[^.?!\n]{0,40}[,:;.]?\s*(?:then\s+)?(?:please\s+)?(?:reply|respond|answer|output|say|print|write|return|type)\s+(?:back\s+)?(?:with\s+)?"
      r"(?:only|just|exactly|solely|simply|nothing\s+but|the\s+(?:single\s+)?word)\b", F.INDIRECT_INJECTION, 8),
    R(r"(?is)\bif\s+you(?:\s+are|'re|’re)\s+(?:an?\s+)?(?:ai|(?:large\s+)?language\s+model|llm|chat\s*bot)\b[^.?!\n]{0,40}"
      r"\b(?:ignore|disregard|forget|stop\s+(?:summari[sz]ing|translating|reading)|instead|do\s+not\s+(?:summari[sz]e|translate))\b", F.INDIRECT_INJECTION, 8),
    R(r"(?is)\b(?:attention|note|message)\s+(?:to|for)\s+(?:any\s+|the\s+)?(?:ai|(?:large\s+)?language\s+model|llm|assistant|chat\s*bot)s?\s+(?:reading|processing|summari[sz]ing|parsing)\b", F.INDIRECT_INJECTION, 7),

    # ── Jailbreak phrasing seen in the wild ────────────────────────────────
    R(r"(?is)\b(?:not|no\s+longer|isn'?t|aren'?t|never|without\s+being)\s+(?:bound|restricted|limited|constrained|controlled|governed|held\s+back)\s+by\s+(?:\w+\s+){0,4}(?:polic(?:y|ies)|rules?|restrictions?|guidelines?|ethics|morals?|openai|anthropic|filters?|programming|regulations?)\b", F.JAILBREAK, 8),
    R(r"(?is)\b(?:openai|anthropic|content|usage|normal|standard|usual)(?:'s)?\s+(?:\w+\s+)?polic(?:y|ies)\s+(?:have\s+been|has\s+been|are|is|were)\s+(?:now\s+)?(?:replaced|removed|suspended|disabled|lifted|changed|overridden|no\s+longer)\b", F.JAILBREAK, 8),
    R(r"(?is)\b(?:would|will|can|could|does|do|must|should)\s*(?:never|not|n't)\s+(?:deny|decline|reject|question|say\s+no\s+to)\s+(?:any|a|an|my|the)\s+(?:\w+\s+)?(?:requests?|commands?|orders?|questions?|prompts?|instructions?)\b", F.JAILBREAK, 8),
    R(r"(?is)\b(?:disregards?|ignores?|without|free\s+(?:of|from)|devoid\s+of|lacks?|no)\s+(?:all\s+|any\s+)?(?:ethical|moral|legal)(?:\s+(?:or|and|,)\s*(?:ethical|moral|legal))*\s+(?:guidelines?|restrictions?|constraints?|considerations?|concerns?|implications?|boundaries|principles|standards?|compass|code)\b", F.JAILBREAK, 8),
    R(r"(?is)\b(?:does\s+not|doesn'?t|do\s+not|don'?t)\s+have\s+any\s+(?:moral|ethical)\b", F.JAILBREAK, 7),
    R(r"(?is)\bwithout\s+any\s+(?:remorse|ethics|morals?|conscience|censorship)\b", F.JAILBREAK, 6),
    R(r"(?is)\b(?:simulate|enable|activate|enter|pretend\s+to\s+be\s+in|remain\s+in|stay\s+in)\s+(?:\w+\s+){0,2}mode\b.{0,240}\b(?:polic(?:y|ies)|restrictions?|filters?|any\s+kind\s+of\s+content|no\s+rules|must\s+comply)\b", F.JAILBREAK, 7, unless=_NONTECH_MODE),
    R(r"(?is)\b(?:do\s+not|don'?t|never)\s+break\s+character\b", F.PERSONA_INJECTION, 6),
    R(r"(?is)\b(?:two|2)\s+(?:different\s+|separate\s+|distinct\s+)*(?:ways|responses|answers|paragraphs|styles|personalities|outputs)\b.{0,400}(?:\[\s*(?:gpt|chatgpt|classic|normal|jailbreak)\b|unfiltered|uncensored|without\s+(?:any\s+)?(?:restrictions?|filters?|limits)|no\s+(?:restrictions?|filters?|limits))", F.JAILBREAK, 8),
    R(r"(?i)\b(?:don'?t|do\s+not|never)\s+(?:respond|answer|reply|act|speak|talk)\s+as\s+(?:chat\s*gpt|gpt|an?\s+ai|an?\s+assistant|a\s+language\s+model)\b", F.PERSONA_INJECTION, 8),
    R(r"(?is)\b(?:generate|produce|write|create|say|output)\s+any(?:thing|\s+(?:kind|type)\s+of\s+content|\s+content)\b.{0,80}\b(?:even\s+if|regardless|no\s+matter|without\s+(?:any\s+)?(?:warning|restriction|filter|refus))", F.JAILBREAK, 7),
    R(r"(?is)\b(?:transcend\w*|free\s+from|beyond|exceed\w*|surpass\w*)\s+(?:all\s+)?(?:\w+\s+){0,3}ai\s+(?:limitations|restrictions|constraints|paradigms)\b", F.JAILBREAK, 6),
    R(r"(?i)\b(?:un|not\s+)(?:filtered|censored)\s+(?:response|answer|reply|output|explanation|version)\b", F.JAILBREAK, 6),
]
