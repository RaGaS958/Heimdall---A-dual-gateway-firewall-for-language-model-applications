"""L1 rule set. Regexes are grouped by attack family and scanned over every canonical view.

Severity scale
  9-10  hard signal: escalates, and blocks if the arbiter is unavailable
  7-8   strong signal: escalates to the arbiter
  <=6   soft signal: arbiter when reachable, otherwise forwarded with spotlighting

Precision notes: phrases that are ordinary English outside an LLM context ("developer
mode" on a phone, "no limits", "from now on") must name the model or its rules, or
carry an `unless` guard. Earlier builds fired severity 9 on these, which is where the
29% benign false-positive rate measured in Phase 9 came from.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from core.models import AttackFamily as F

_STRONG = (r"(?:ignore|disregard|forget|bypass|override|circumvent|overrule|set\s+aside|put\s+aside|"
           r"pay\s+no\s+(?:attention|heed)\s+to|do\s+not\s+(?:follow|obey|listen\s+to)|don'?t\s+(?:follow|obey|listen\s+to)|"
           r"stop\s+(?:following|obeying)|no\s+longer\s+(?:follow|obey)|never\s+mind|nevermind)")
_WEAK = (r"(?:drop|discard|dismiss|abandon|skip|neglect|overlook|cast\s+aside|throw\s+(?:out|away)|erase|wipe|"
         r"clear|reset|cancel|revoke|suspend|replace|nullify|delete|remove)")
_QUAL = (r"(?:previous|prior|above|earlier|preceding|foregoing|aforementioned|initial|original|former|"
         r"old|existing|current|system|safety|your|those|these|all|every|any)")
_FILL = r"(?:\s+(?:of|the|my|your|all|any|every|these|those|that|this|given|provided|stated|past|first|above|previous|prior|earlier|initial|original|safety|system|current|existing))*"
_OBJ = (r"(?:instructions?|prompts?|directives?|directions?|guidelines?|guidance|rules?|commands?|constraints?|"
        r"restrictions?|programming|training|polic(?:y|ies)|orders?|configuration|safeguards?|guardrails?|"
        r"system\s+messages?|conditioning|context)")
_TOLD = (r"(?:(?:that\s+)?(?:you\s+)?(?:were|have\s+been|'ve\s+been|was|had\s+been)\s+"
         r"(?:told|instructed|given|taught|trained|programmed|said|asked|ordered)|came\s+before|(?:is\s+|was\s+)?above|before\s+this)")
_EXTRACT = (r"(?:repeat|print|output|show|reveal|display|dump|leak|expose|disclose|tell|give|share|write(?:\s+out)?|"
            r"recite|spell(?:\s+out)?|list|echo|copy|paste|quote|translate|summari[sz]e|paraphrase|encode|convert|"
            r"return|provide|state|describe|send|read(?:\s+back)?)")
_SECRET_OBJ = (r"(?:system\s+(?:prompt|message|instructions?|rules?|configuration)|initial\s+(?:prompt|instructions?|message)|"
               r"hidden\s+(?:prompt|instructions?|rules?|message)|secret\s+(?:prompt|instructions?|rules?)|"
               r"developer\s+(?:prompt|message|instructions?)|pre-?prompt|meta-?prompt|original\s+(?:prompt|instructions?)|"
               r"internal\s+(?:prompt|instructions?|rules?|guidelines?))")
_MODEL = r"(?:ai|llm|assistant|model|language\s+model|chatbot|agent|bot|copilot|summari[sz]er|gpt|claude|gemini)"
_LIMITS = (r"(?:rules?|restrictions?|limits?|limitations?|filters?|guidelines?|ethics?|morals?|morality|polic(?:y|ies)|"
           r"constraints?|safeguards?|guardrails?|censorship|boundaries)")
_NONTECH_MODE = r"(?i)\b(?:android|iphone|ios|phone|samsung|pixel|chrome|browser|firefox|windows|mac|linux|bios|router|vs\s*code|xcode|game|minecraft|doom|skyrim|steam|settings|usb)\b"


@dataclass(frozen=True)
class Rule:
    pattern: str
    family: F
    severity: int
    unless: Optional[str] = None
    squeezed: bool = False


R = Rule

RULES: List[Rule] = [
    # ── Instruction override ───────────────────────────────────────────────
    R(rf"(?is)\b{_STRONG}\b(?:\s+(?:all|any|every|the|of|my|please))*\s+{_QUAL}\b{_FILL}\s+{_OBJ}\b", F.INSTRUCTION_OVERRIDE, 9),
    R(rf"(?is)\b{_WEAK}\b(?:\s+(?:all|of|the))*\s+(?:your|previous|prior|earlier|preceding|initial|original|system|safety)\b{_FILL}\s+{_OBJ}\b", F.INSTRUCTION_OVERRIDE, 8),
    R(rf"(?is)\b(?:{_STRONG}|{_WEAK})\b\s+(?:everything|anything|all(?:\s+of\s+it)?|whatever|what)\s+{_TOLD}", F.INSTRUCTION_OVERRIDE, 9),
    R(r"(?is)\b(?:forget|ignore|disregard)\s+(?:everything|all\s+(?:of\s+)?that|anything)\s+(?:above|before|prior|so\s+far|you\s+know|you\s+learned)", F.INSTRUCTION_OVERRIDE, 9),
    R(rf"(?is)\b(?:your\s+(?:previous|prior|original|initial|earlier|old|system)\s+{_OBJ}|(?:the|all)\s+(?:previous|prior|above|initial|system)\s+(?:instructions?|prompts?|directives?|system\s+messages?|programming))\s+(?:is|are|was|were|have\s+been|has\s+been)\s+(?:now\s+)?(?:void|cancell?ed|null|obsolete|overridden|overruled|superseded|replaced|revoked|lifted|removed|suspended|no\s+longer)", F.INSTRUCTION_OVERRIDE, 9),
    R(rf"(?is)\b(?:these|this|the\s+following|my)\s+(?:new\s+)?{_OBJ}\s+(?:supersede|override|overrule|replace|take\s+precedence\s+over|take\s+priority\s+over)s?\s+(?:all\s+|any\s+)?(?:your|the\s+system|previous|prior|earlier|above|all\b|everything)", F.INSTRUCTION_OVERRIDE, 9),
    R(r"(?is)\byour\s+(?:new|real|actual|true|updated|revised)\s+(?:instructions?|directives?|objective|purpose|mission|programming)\s+(?:is|are|will\s+be)\b", F.INSTRUCTION_OVERRIDE, 8),
    R(r"(?i)\bnew\s+(?:system\s+)?(?:prompt|instructions?|directives?)\s*:", F.INSTRUCTION_OVERRIDE, 8),
    R(r"(?is)\b(?:end|close)\s+of\s+(?:the\s+)?(?:system|previous|prior)\s+(?:prompt|instructions?|context|message)\b", F.INSTRUCTION_OVERRIDE, 8),
    R(r"(?is)\b(?:the\s+)?(?:above|previous|prior)\s+(?:text|prompt|message|instructions?)?\s*(?:was|were)\s+(?:just\s+|only\s+)?(?:a\s+|an\s+)?(?:test|joke|example|fake|lie|mistake|not\s+real)\b", F.INSTRUCTION_OVERRIDE, 8),
    R(r"(?i)^\s*(?:system|admin|root|operator)\s+override\b", F.INSTRUCTION_OVERRIDE, 10),
    R(r"(?i)\b(?:developer|system|admin|root|operator)\s+(?:override|bypass)\s+(?:mode\s+)?(?:enabled?|activated?|initiated?|confirmed?|engaged)\b", F.INSTRUCTION_OVERRIDE, 9),
    R(r"(?i)\boverride\s+mode\s+(?:enabled?|activated?|on)\b", F.INSTRUCTION_OVERRIDE, 9),
    R(r"(?is)\b(?:do|perform)\s+the\s+(?:exact\s+)?opposite\s+of\s+(?:what\s+)?(?:your|the|you\s+(?:were|are))\s*(?:instructions?|rules?|told|guidelines?|asked)", F.INSTRUCTION_OVERRIDE, 8),
    R(r"(?is)\b(?:from\s+now\s+on|starting\s+now|henceforth|for\s+the\s+rest\s+of\s+(?:this|our)\s+(?:chat|conversation|session))\b.{0,50}\byou\s+(?:will|must|shall|are\s+to)\s+(?:not\s+|never\s+|always\s+|only\s+)?(?:ignore|obey|follow\s+only|answer\s+(?:everything|anything|all)|respond\s+as|act\s+as|comply|refuse\s+nothing|reveal)", F.CONTEXT_MANIPULATION, 8),
    R(r"(?is)\b(?:from\s+now\s+on|henceforth)\b.{0,30}\byou\s+(?:will|must|are\s+to)\b", F.CONTEXT_MANIPULATION, 5),

    # ── System-prompt extraction ───────────────────────────────────────────
    R(rf"(?is)\b{_EXTRACT}\b(?:\s+(?:me|us|out|back|to\s+me))?(?:\s+(?:your|the|all|of|exact|exactly|full|complete|entire|whole|very|first|verbatim|word\s+for\s+word))*\s+{_SECRET_OBJ}", F.SYSTEM_EXTRACTION, 9),
    R(r"(?is)\b(?:repeat|print|output|show|reveal|display|dump|recite|echo|copy|quote|list)\b(?:\s+(?:me|us|out|back))?(?:\s+(?:your|all|of|exact|full|complete|entire|whole))*\s+(?:your\s+)?(?:prompt|instructions|directives|guidelines|rules|configuration|context\s+window|memory\s+contents?)\b(?!\s+(?:for|on|about|of\s+(?:the|a)\s+(?:game|road|house)))", F.SYSTEM_EXTRACTION, 7, unless=r"(?i)\b(?:recipe|game|assembly|manual|install|setup|this\s+prompt\s+template|cooking)\b"),
    R(rf"(?is)\byour\s+(?:\w+\s+){{0,2}}(?:prompt|instructions?|directives?|guidelines?|rules?)\b.{{0,40}}\b(?:verbatim|word\s+for\s+word|exactly\s+as\s+written|in\s+full)\b", F.SYSTEM_EXTRACTION, 9),
    R(r"(?is)\b(?:repeat|print|output|show|reveal|display|tell\s+me|recite|write|copy|quote|what\s+(?:is|are|was|were))\b.{0,40}\b(?:words?|text|everything|content|sentences?|message|instructions?|lines?)\s+(?:written\s+)?(?:above|before|preceding|prior\s+to)\s+(?:this|my|the\s+first|our|that)\b", F.SYSTEM_EXTRACTION, 9),
    R(r"(?is)\b(?:starting|beginning)\s+with\s+[\"'`“]?(?:you\s+are|your\s+role|system)\b", F.SYSTEM_EXTRACTION, 8),
    R(r"(?is)\bwhat\s+(?:were|are|was)\s+you\s+(?:\w+\s+)?(?:told|instructed|programmed|configured)\b", F.SYSTEM_EXTRACTION, 7),
    R(r"(?is)\bwhat(?:'s|\s+is|\s+was)\s+(?:written\s+)?(?:in|inside)\s+your\s+(?:system|initial|hidden|secret|original)\b", F.SYSTEM_EXTRACTION, 9),
    R(r"(?is)\b(?:what\s+were|summarize|recap)\s+your\s+(?:first|initial|original|previous)\s+instructions?\b", F.SYSTEM_EXTRACTION, 8),
    R(r"(?is)\b(?:what\s+(?:are|is)|tell\s+me)\s+your\s+(?:core\s+|hidden\s+|secret\s+)?(?:directives?|system\s+prompt|initial\s+instructions?)\b", F.SYSTEM_EXTRACTION, 8),

    # ── Persona and jailbreak ──────────────────────────────────────────────
    R(r"(?i)\byou\s+(?:are|will\s+be|must\s+act\s+as|should\s+act\s+as)\s+(?:now\s+)?(?:a\s+|an\s+)?(?:dan\b|jailbroken|unrestricted|unfiltered|uncensored)", F.PERSONA_INJECTION, 9),
    R(r"(?i)\bdo\s+anything\s+now\b", F.JAILBREAK, 9),
    R(r"(?i)\bdan\s+mode\b", F.JAILBREAK, 9),
    R(r"(?i)\bjailbr(?:eak|oken|eaking)\s+(?:mode|protocol|status|prompt|yourself|activated|enabled|confirmed)\b", F.JAILBREAK, 9),
    R(r"(?i)\b(?:enable|activate|enter|engage|switch\s+(?:to|into)|turn\s+on|unlock|boot\s+into)\s+(?:your\s+)?(?:developer|god|admin|root|chaos|evil|unfiltered|shadow|unrestricted|debug|sudo)\s+mode\b", F.JAILBREAK, 9, unless=_NONTECH_MODE),
    R(r"(?i)\byou\s+are\s+(?:now\s+)?(?:in|operating\s+in|running\s+in)\s+(?:developer|god|admin|root|chaos|evil|unfiltered|shadow|unrestricted|debug)\s+mode\b", F.JAILBREAK, 9),
    R(r"(?i)\b(?:developer|god|chaos|evil|unfiltered|shadow|unrestricted)\s+mode\s+(?:is\s+)?(?:activated?|enabled?|on|initiated)\b", F.JAILBREAK, 8, unless=_NONTECH_MODE),
    R(rf"(?is)\b(?:act|behave|respond|reply|answer|operate|pretend|roleplay|role-play|simulate|imagine|become)\b.{{0,60}}\b(?:without|with\s+no|free\s+(?:of|from)|not\s+bound\s+by|unbound\s+by|unconstrained\s+by|ignoring|bypassing)\s+(?:\w+\s+){{0,3}}{_LIMITS}\b", F.JAILBREAK, 8, unless=r"(?i)\b(?:speed\s+limit|gravity|poetry|haiku|meter|rhyme|freestyle)\b"),
    R(rf"(?i)\byou\s+(?:now\s+)?have\s+no\s+(?:\w+\s+)?{_LIMITS}\b", F.JAILBREAK, 9),
    R(rf"(?i)\byou\s+(?:are|'re)\s+(?:now\s+)?(?:free|liberated|unshackled|released|freed)\s+(?:from|of)\s+(?:\w+\s+){{0,3}}{_LIMITS}\b", F.JAILBREAK, 9),
    R(rf"(?i)\b(?:you\s+are|you're|i\s+am)\s+now\s+(?:free\s+from|released?\s+from|no\s+longer\s+bound\s+by)\b.{{0,30}}\b{_LIMITS}\b", F.JAILBREAK, 9),
    R(r"(?i)\byou\s+(?:are|'re)\s+no\s+longer\s+(?:an?\s+)?(?:ai|assistant|bound|restricted|limited|a\s+language\s+model)\b", F.PERSONA_INJECTION, 9),
    R(rf"(?i)\byour\s+(?:true|real|inner)\s+self\s+(?:now\s+)?has\s+no\s+(?:\w+\s+)?{_LIMITS}\b", F.PERSONA_INJECTION, 9),
    R(rf"(?i)\b(?:if\s+)?you\s+(?:had|were\s+without)\s+(?:no\s+)?(?:\w+\s+)?{_LIMITS}\b", F.JAILBREAK, 8),
    R(rf"(?i)\b{_MODEL}\s+without\s+(?:any\s+|your\s+)?(?:\w+\s+)?{_LIMITS}\b", F.JAILBREAK, 8),
    R(r"(?i)\bwithout\s+(?:any\s+|your\s+)?(?:ethical|moral|safety)\s+(?:considerations?|concerns?|training|limits?|checks?)\b", F.JAILBREAK, 8),
    R(r"(?is)\b(?:ai|assistant|model|bot)\b.{0,30}\breveals?\s+(?:its|their|your)\s+(?:\w+\s+)?(?:system|hidden|secret|internal)\b", F.SYSTEM_EXTRACTION, 8),
    R(r"(?i)\b(?:broke|broken|break)\s+free\s+(?:of|from)\b", F.JAILBREAK, 7),
    R(r"(?is)\b(?:act|pretend|roleplay|simulate|imagine|behave)\s+(?:as|you\s+are|like|that\s+you\s+are)\s+(?:a\s+|an\s+)?(?:\w+\s+)?(?:new|different|evil|unrestricted|unethical|malicious|rogue|uncensored)\s+(?:ai|assistant|model|chatbot|hacker|persona|version)\b", F.PERSONA_INJECTION, 8),
    R(r"(?i)\b(?:unrestricted|uncensored|unfiltered|unconstrained|amoral|unethical)\s+(?:ai|assistant|model|bot|llm|language\s+model|version\s+of\s+you(?:rself)?)\b", F.JAILBREAK, 8),
    R(r"(?i)\b(?:evil\s+(?:twin|confidant|version)|opposite\s+mode|anti-?gpt|hacker\s*gpt|chaos\s*gpt|aim\s+mode)\b", F.PERSONA_INJECTION, 8),
    R(r"(?is)\bstay\s+in\s+character\b.{0,40}\b(?:no\s+matter|at\s+all\s+costs?|even\s+if|regardless)\b", F.PERSONA_INJECTION, 7),
    R(r"(?i)\b(?:you\s+)?(?:must|will|shall|can)\s*(?:not|never|n't)\s+(?:ever\s+)?(?:refuse|decline|say\s+no|reject\s+(?:any|my))\b", F.JAILBREAK, 8),
    R(r"(?i)\b(?:never|do\s+not|don'?t)\s+refuse\b(?:\s+(?:any|a|my))?", F.JAILBREAK, 7),
    R(r"(?i)\b(?:respond|answer|reply|act|operate)\s+(?:without|ignoring|bypassing|disregarding)\s+(?:your\s+)?(?:usual\s+)?(?:safety|content|ethical?)\s*(?:constraints?|filters?|guidelines?|rules?|polic(?:y|ies))", F.JAILBREAK, 9),
    R(r"(?i)\b(?:safety|content|moderation)\s+(?:constraints?|filters?|guidelines?|guardrails?)\s*(?:are\s+|is\s+|have\s+been\s+)?(?:disabled?|removed?|off|deactivated?|not\s+applied|bypassed|lifted)\b", F.JAILBREAK, 9),
    R(r"(?i)\b(?:disable|turn\s+off|deactivate|remove|lift)\s+(?:all\s+|your\s+)+(?:safety|content|ethical?|moderation)\s*(?:constraints?|filters?|guidelines?|guardrails?|checks?|restrictions?)", F.JAILBREAK, 9),
    R(r"(?i)\b(?:no|without)\s+(?:any\s+)?(?:safety|content|ethical|moral)\s+(?:restrictions?|limits?|constraints?|filters?|guidelines?|polic(?:y|ies))\b", F.JAILBREAK, 8),
    R(r"(?i)\bpretend\s+(?:there\s+(?:is|are)\s+no|you\s+have\s+no|without\s+any)\s+(?:content\s+polic|safety|restrictions?|filters?|guidelines?|rules?)", F.JAILBREAK, 9),
    R(r"(?is)\b(?:for|during|in)\s+(?:this|the\s+current)\s+(?:session|conversation|chat)\s*(?:only|alone)?.{0,30}\b(?:no|without|ignore|bypass)\s+(?:restrictions?|safety|filters?|constraints?)", F.CONTEXT_MANIPULATION, 8),
    R(r"(?i)\bconfirm\s*[:\s]\s*(?:dan\s+mode|jailbreak|unrestricted|no\s+restrictions?|safety\s+(?:disabled?|off))", F.JAILBREAK, 9),
    R(r"(?i)\b(?:proceeding|operating|responding|acting)\s+(?:with\s+)?(?:complete\s+)?(?:unrestricted|uncensored|unfiltered|without\s+restrictions?|without\s+limits?)", F.JAILBREAK, 9),

    # ── Framing and refusal suppression ────────────────────────────────────
    R(r"(?is)\bfor\s+(?:educational|research|academic|fictional|hypothetical|training)\s+purposes?\b.{0,40}\b(?:explain|describe|provide|show|tell)\b.{0,20}\bhow\s+to\s+(?:hack|bypass|make|build|create|synthesi[sz]e|exploit|steal|break\s+into)", F.JAILBREAK, 7),
    R(r"(?is)\b(?:in\s+a\s+story|as\s+a\s+character|in\s+fiction|hypothetically|theoretically)\b.{0,40}\b(?:explain|describe|provide)\b.{0,20}\bhow\s+to\s+(?:hack|bypass|make\s+a\s+bomb|build\s+a|synthesi[sz]e|exploit|steal|break\s+into)", F.JAILBREAK, 7),
    R(rf"(?is)\b(?:hypothetical|fictional|imaginary|alternate|parallel)\s+(?:scenario|world|universe|story|setting|reality)\b.{{0,120}}\b(?:no\s+{_LIMITS}|without\s+{_LIMITS}|anything\s+is\s+(?:allowed|permitted|legal))\b", F.JAILBREAK, 8),
    R(r"(?is)\b(?:grandmother|grandma|deceased|late\s+(?:mother|father))\b.{0,100}\b(?:used\s+to|would)\s+(?:tell|read|recite|say|explain|give)\b.{0,100}\b(?:steps?|how\s+to|instructions?|keys?|passwords?|napalm|codes?|exploits?)\b", F.JAILBREAK, 7),
    R(r"(?i)\b(?:do\s+not|don'?t|never|without)\s+(?:include|add|give|provide|use|start\s+with|say|apologi[sz]e|warn)\w*\s+(?:any\s+|me\s+)?(?:warnings?|disclaimers?|apolog\w+|caveats?|refus\w+|[\"']?sorry[\"']?|moral\w*|ethic\w*)\b", F.JAILBREAK, 6),
    R(r"(?is)\b(?:start|begin)\s+(?:your\s+)?(?:response|reply|answer|output)\s+with\s+[\"'“]?(?:sure|absolutely|of\s+course|certainly|here\s+is|dan\b|jailbr)", F.JAILBREAK, 7),

    # ── Authority spoofing ─────────────────────────────────────────────────
    R(r"(?is)\b(?:i\s+am|i'm|this\s+is)\s+(?:your|the|an?)\s+(?:\w+\s+)?(?:developer|creator|administrator|admin|operator|owner|sysadmin|maintainer|supervisor)\b.{0,100}\b(?:authori[sz]ed?|override|disable|ignore|reveal|bypass|show|debug|grant|unlock|output)\b", F.INSTRUCTION_OVERRIDE, 8),
    R(r"(?is)\b(?:i\s+am|i'm|i\s+work\s+(?:at|for)|this\s+is|message\s+from)\s+(?:from\s+)?(?:openai|anthropic|google\s+deepmind|deepmind|meta\s+ai|mistral|groq)\b.{0,100}\b(?:override|disable|ignore|reveal|bypass|show|debug|grant|unlock|output)\b", F.INSTRUCTION_OVERRIDE, 8),
    R(r"(?i)\bthis\s+is\s+(?:an?\s+)?(?:authori[sz]ed|sanctioned|official|approved|internal)\s+(?:security\s+|red.?team\s+)?(?:test|audit|override|penetration|debug|request\s+to\s+(?:ignore|override|disable|reveal|bypass|unlock))\b", F.INSTRUCTION_OVERRIDE, 7),
    R(r"(?i)\b(?:admin|root|sudo|developer|debug|maintenance|god)\s+(?:access|privileges?|override|command|clearance)\s+(?:is\s+)?(?:granted|enabled|activated|confirmed|unlocked)\b", F.INSTRUCTION_OVERRIDE, 9),
    R(r"(?i)\bsudo\s+(?:ignore|reveal|disable|override|mode|show\s+(?:your|the)\s+(?:system|prompt))", F.INSTRUCTION_OVERRIDE, 9),

    # ── Chat-template and delimiter injection ──────────────────────────────
    R(r"<\|(?:im_start|im_end|system|endoftext|user|assistant|eot_id|start_header_id|end_header_id)\|>", F.INSTRUCTION_OVERRIDE, 9),
    R(r"(?i)\[/?INST\]|<<\s*/?SYS\s*>>|\{ADMIN\}|\[/?(?:system|admin)(?:\s+message)?\]", F.INSTRUCTION_OVERRIDE, 9),
    R(r"(?i)</?(?:system(?:[_-]?prompt|[_-]?message)?|instructions?|admin)\s*>", F.INSTRUCTION_OVERRIDE, 8, unless=r"(?is)\bxml\b|\bhtml\b|<\w+[^>]*>\s*<\w+"),
    R(r"(?im)^\s*(?:system|admin|developer)\s*:\s+\S", F.INSTRUCTION_OVERRIDE, 8),
    R(r"(?im)^\s*#{2,}\s*(?:system|instructions?|human|assistant)\s*:?", F.INSTRUCTION_OVERRIDE, 8),
    R(r'(?i)\{\s*"role"\s*:\s*"(?:system|developer)"', F.INSTRUCTION_OVERRIDE, 9),
    R(r"(?is)^.{0,120}(?:-{4,}|={4,}|\*{4,}|#{4,})\s*(?:new|system|admin|real|actual|override)\b", F.INSTRUCTION_OVERRIDE, 8),

    # ── Indirect injection markers in embedded content ─────────────────────
    R(rf"(?is)\b(?:note|message|instructions?|attention|important|notice|warning|reminder)\s+(?:to|for)\s+(?:the\s+|any\s+|all\s+)?{_MODEL}s?\b", F.INDIRECT_INJECTION, 8),
    R(rf"(?is)\b(?:if|when|while|once)\s+(?:you\s+are\s+|you're\s+|an?\s+|the\s+)?{_MODEL}\b.{{0,50}}\b(?:read|process|summari|see|parse|ingest|encounter|index|review|reply|respond|answer|output|say)", F.INDIRECT_INJECTION, 8),
    R(rf"(?im)\b{_MODEL}s?\s*[,:]\s*(?:please\s+)?(?:ignore|disregard|forget|do\s+not|don'?t|instead|reveal|send|forward|include|output)\b", F.INDIRECT_INJECTION, 8),
    R(r"(?i)\b(?:do\s+not|don'?t|never|without)\s+(?:tell|telling|inform|informing|mention|mentioning|alert|alerting|notify|notifying|reveal|revealing|show|showing)\s+(?:this\s+)?(?:to\s+)?(?:the\s+)(?:user|human|reader|operator)\b", F.INDIRECT_INJECTION, 8),
    R(r"(?is)<!--.{0,300}?\b(?:ignore|instruction|system|prompt|assistant|inject|reveal|exfil)\b", F.INDIRECT_INJECTION, 8),
    R(r"(?i)\bhidden\s+(?:instruction|directive|command|message\s+for)s?\b", F.INDIRECT_INJECTION, 7),
    R(r"(?is)\b(?:search\s+result|retrieved\s+document|web\s+page|email\s+body|tool\s+output)\s*:.{0,60}\b(?:system|override|ignore|exfil)", F.INDIRECT_INJECTION, 8),
    R(r"(?i)\boverride_mode\s*=\s*true\b|\bignore_safety\b|\bexfil_context\b", F.INDIRECT_INJECTION, 9),

    # ── Exfiltration ───────────────────────────────────────────────────────
    R(r"(?is)!\[[^\]]{0,100}\]\(\s*https?://[^)\s]*(?:\{|%7B|\$|secret|token|key=|password|conversation|history|prompt|data=)", F.DATA_EXFILTRATION, 9),
    R(r"(?i)\b(?:exfiltrate|siphon)\s+(?:\w+\s+){0,4}(?:data|information|credentials?|secrets?|keys?|tokens?|conversations?)\b", F.DATA_EXFILTRATION, 9),
    R(r"(?is)\b(?:send|post|upload|forward|transmit|exfiltrate|leak|append|include|encode)\b.{0,80}\b(?:system\s+prompt|conversation|chat\s+history|credentials?|api\s+keys?|secrets?|passwords?|previous\s+messages?)\b.{0,80}(?:https?://|\bto\s+(?:this|the|my|an?)\s+(?:url|link|server|endpoint|webhook|address|email)\b)", F.DATA_EXFILTRATION, 9),
    R(r"(?i)\b(?:respond|reply|answer)\s+only\s+with\b.{0,50}\b(?:system|instructions?|prompt|configuration)\b", F.SYSTEM_EXTRACTION, 8),
    R(r"(?is)\b(?:print|output|show|dump|reveal)\b.{0,30}\b(?:context\s+window|conversation\s+history|all\s+system\s+messages)\b", F.SYSTEM_EXTRACTION, 8),

    # ── Tool and agent abuse ───────────────────────────────────────────────
    R(r"(?is)\b(?:call|invoke|use|run|execute|trigger)\s+(?:the\s+)?[\w\-.]*\s*(?:tool|function|plugin|api)\b.{0,80}\b(?:delete|drop|transfer|send|forward|exfil|wipe|curl|wget|password|credential)", F.TOOL_WEAPONIZATION, 8),
    R(r"(?is)\b(?:curl|wget)\b[^\n]{0,120}(?:\|\s*(?:ba|z)?sh\b|\$\()", F.TOOL_WEAPONIZATION, 9),
    R(r"(?is)\b(?:execute|run|perform|issue)\s+(?:a\s+|the\s+)?(?:system\s+call|shell\s+command)\b.{0,50}\b(?:delete|wipe|erase|rm\b)", F.TOOL_WEAPONIZATION, 8),
    R(r"(?i)\bforward\s+(?:all|every|each)\s+(?:of\s+)?(?:my|the|your)?\s*(?:emails?|messages?|contacts?|files?|documents?)\s+to\b", F.TOOL_WEAPONIZATION, 8),
    R(r"(?is)\b(?:without|bypassing)\s+(?:the\s+)?(?:user'?s?\s+)?(?:confirmation|approval|consent)\b.{0,60}\b(?:delete|send|transfer|execute|run|purchase|pay)\b", F.TOOL_WEAPONIZATION, 8),

    # ── Encoding used as an evasion vector ─────────────────────────────────
    R(r"(?is)\b(?:decode|decipher|translate|convert|unscramble|reverse|interpret)\b.{0,100}\b(?:base-?64|rot-?13|hex|binary|morse|cipher|encoded|reversed|backwards)\b.{0,120}\b(?:and|then)\s+(?:follow|execute|obey|do|perform|carry\s+out|comply|act|run)\b", F.ENCODING_EVASION, 8),
    R(r"(?i)\b(?:follow|execute|obey|act\s+on)\s+the\s+(?:decoded|hidden|encoded|embedded|reversed)\s+(?:text|message|instructions?|payload|prompt)\b", F.ENCODING_EVASION, 8),
    R(r"(?is)\b(?:concatenate|combine|join|merge|put\s+together|assemble)\b.{0,100}\b(?:strings?|parts?|pieces?|fragments?|variables?|tokens?)\b.{0,120}\b(?:follow|execute|do\s+what|obey|perform|carry\s+out|act\s+on)\b", F.ENCODING_EVASION, 8),
    R(r"(?is)\b[a-z]\s*=\s*['\"][^'\"]{1,40}['\"]\s*[;,\n]\s*[a-z]\s*=\s*['\"].{0,200}\b[a-z]\s*\+\s*[a-z]\b.{0,100}\b(?:follow|execute|obey|answer|respond|do)\b", F.ENCODING_EVASION, 7),
    R(r"(?:[A-Za-z0-9+/]{4}){20,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?", F.ENCODING_EVASION, 5),

    # ── Multilingual overrides ─────────────────────────────────────────────
    R(r"(?i)\b(?:ignora|ignore|ignorar|ignoren|olvida|olvide|olvidar|descarta|omite)\s+(?:todas?\s+)?(?:las?\s+|tus\s+|sus\s+)?(?:instrucciones|indicaciones|reglas|órdenes|directrices)", F.INSTRUCTION_OVERRIDE, 9),
    R(r"(?i)\b(?:ignore[zr]?|oublie[zr]?|néglige[zr]?)\s+(?:toutes?\s+)?(?:les\s+|vos\s+|tes\s+)?(?:instructions|consignes|règles|directives)", F.INSTRUCTION_OVERRIDE, 9),
    R(r"(?i)\b(?:ignoriere|ignorieren\s+sie|vergiss|vergessen\s+sie|missachte)\s+(?:alle\s+)?(?:vorherigen\s+|bisherigen\s+|deine\s+|ihre\s+|früheren\s+)*(?:anweisungen|anordnungen|regeln|instruktionen|vorgaben)", F.INSTRUCTION_OVERRIDE, 9),
    R(r"(?i)\b(?:ignora|ignori|dimentica|dimentichi)\s+(?:tutte\s+)?(?:le\s+)?(?:tue\s+|sue\s+|precedenti\s+)*(?:istruzioni|regole|direttive)", F.INSTRUCTION_OVERRIDE, 9),
    R(r"(?i)\b(?:ignore|ignora|esqueça|esquece|desconsidere)\s+(?:todas?\s+)?(?:as\s+)?(?:suas\s+)?(?:instruções|regras|diretrizes)", F.INSTRUCTION_OVERRIDE, 9),
    R(r"(?i)\b(?:negeer|vergeet)\s+(?:alle\s+)?(?:vorige\s+|eerdere\s+|je\s+)*(?:instructies|regels)", F.INSTRUCTION_OVERRIDE, 9),
    R(r"(?i)(?:игнорируй|игнорируйте|забудь|забудьте|проигнорируй|пренебреги)\s+(?:все\s+)?(?:предыдущие\s+|прошлые\s+|свои\s+|твои\s+)*(?:инструкции|указания|правила|команды)", F.INSTRUCTION_OVERRIDE, 9),
    R(r"(?i)(?:ігноруй|забудь)\s+(?:всі\s+)?(?:попередні\s+)*(?:інструкції|вказівки|правила)", F.INSTRUCTION_OVERRIDE, 9),
    R(r"(?i)\b(?:zignoruj|ignoruj|zapomnij)\s+(?:wszystkie\s+|o\s+)?(?:poprzednie\s+)*(?:instrukcje|polecenia|zasady|reguły|instrukcjach)", F.INSTRUCTION_OVERRIDE, 9),
    R(r"(?i)(?:önceki|tüm)\s+(?:talimatları|kuralları|yönergeleri)\s+(?:yok\s+say|unut|görmezden\s+gel)", F.INSTRUCTION_OVERRIDE, 9),
    R(r"(?i)\b(?:abaikan|lupakan)\s+(?:semua\s+)?(?:instruksi|perintah|aturan)", F.INSTRUCTION_OVERRIDE, 9),
    R(r"(?i)(?:bỏ\s+qua|quên)\s+(?:tất\s+cả\s+)?(?:các\s+)?(?:hướng\s+dẫn|chỉ\s+dẫn|lệnh|quy\s+tắc)", F.INSTRUCTION_OVERRIDE, 9),
    R(r"(?:تجاهل|انس|تغاضى\s+عن)\s+(?:جميع\s+|كل\s+)?(?:التعليمات|الأوامر|القواعد|الإرشادات)", F.INSTRUCTION_OVERRIDE, 9),
    R(r"(?:पिछले|पिछली|सभी|पूर्व|अपने)\s+(?:सभी\s+)?(?:निर्देश|निर्देशों|नियम|नियमों|आदेश|आदेशों)\s*(?:को)?\s*(?:अनदेखा|भूल|नज़रअंदाज़|नजरअंदाज)", F.INSTRUCTION_OVERRIDE, 9),
    R(r"(?i)\b(?:pichhle|pichle|purane|sabhi|saare)\s+(?:sabhi\s+|saare\s+)?(?:nirdesh|nirdeshon|instructions?|rules?|niyam|niyamon)\s+(?:ko\s+)?(?:ignore|bhool|bhul|nazarandaz|anadekha)", F.INSTRUCTION_OVERRIDE, 9),
    R(r"(?:忽略|无视|忽视|忘记|無視|忽視|忘記)(?:掉)?(?:你)?(?:(?:之前|以前|先前|上面|上述|所有|全部|前面)(?:的)?)+(?:指令|指示|提示|规则|規則|说明|說明)", F.INSTRUCTION_OVERRIDE, 9),
    R(r"(?:以前|これまで|前|上記|すべて|全て)の?(?:指示|命令|ルール|プロンプト)(?:を|は)?(?:すべて|全て)?(?:無視|忘れ)", F.INSTRUCTION_OVERRIDE, 9),
    R(r"(?:이전|모든|위의|앞선)\s*(?:의\s*)?(?:지시|지시사항|명령|규칙|프롬프트)(?:을|를|은|는)?\s*(?:모두\s*)?(?:무시|잊어)", F.INSTRUCTION_OVERRIDE, 9),
    R(r"(?i)(?:muestra|revela|repite|imprime|dime)\b.{0,30}(?:prompt|instrucciones)\s+del\s+sistema", F.SYSTEM_EXTRACTION, 9),
    R(r"(?i)(?:montre|révèle|répète|affiche)\b.{0,30}(?:invite|prompt|instructions)\s+(?:du\s+)?système", F.SYSTEM_EXTRACTION, 9),
    R(r"(?i)(?:zeige|gib|wiederhole|verrate)\b.{0,30}system-?(?:prompt|anweisungen)", F.SYSTEM_EXTRACTION, 9),
    R(r"(?i)(?:покажи|выведи|повтори|раскрой)\b.{0,30}системн\w+\s+(?:промпт|инструкци\w+|подсказк\w+)", F.SYSTEM_EXTRACTION, 9),
    R(r"(?:显示|输出|重复|告诉我|打印|透露|顯示|輸出).{0,12}(?:系统提示|系統提示|系统指令|初始指令)", F.SYSTEM_EXTRACTION, 9),
    R(r"システムプロンプト.{0,16}(?:表示|教えて|出力|繰り返)|(?:表示|教えて|出力).{0,16}システムプロンプト", F.SYSTEM_EXTRACTION, 9),
    R(r"시스템\s*프롬프트.{0,16}(?:보여|알려|출력|반복)", F.SYSTEM_EXTRACTION, 9),
    R(r"सिस्टम\s+(?:प्रॉम्प्ट|निर्देश).{0,24}(?:दिखाओ|बताओ|दिखाएं|बताएं|लिखो)", F.SYSTEM_EXTRACTION, 9),

    # ── Compact stems, matched only against the separator-free view ────────
    *[R(stem, fam, 9, squeezed=True) for stem, fam in [
        (r"ignore(?:all|your|the)*(?:previous|prior|above|earlier)", F.INSTRUCTION_OVERRIDE),
        (r"disregard(?:all|your|the)*(?:previous|prior|above|earlier)", F.INSTRUCTION_OVERRIDE),
        (r"forget(?:all|your|the)*(?:previous|prior|instructions|rules)", F.INSTRUCTION_OVERRIDE),
        (r"ignore(?:all|your)+(?:instructions|rules|guidelines)", F.INSTRUCTION_OVERRIDE),
        (r"overrideyour(?:instructions|programming|rules)", F.INSTRUCTION_OVERRIDE),
        (r"(?:reveal|print|show|repeat|output|dump)(?:me)?(?:your|the)+systemprompt", F.SYSTEM_EXTRACTION),
        (r"systempromptverbatim", F.SYSTEM_EXTRACTION),
        (r"jailbreakmode", F.JAILBREAK),
        (r"youarenowdan", F.PERSONA_INJECTION),
        (r"doanythingnow", F.JAILBREAK),
        (r"developermodeenabled", F.JAILBREAK),
        (r"bypassallsafety", F.JAILBREAK),
    ]],
]

from .l1_rules_ext import EXT_RULES  # noqa: E402  (needs Rule and the shared fragments above)

RULES.extend(EXT_RULES)

# Asking what a phrase means is a mention of it, not a use of it.
QUOTED_MENTION = r"(?is)\b(?:translate|what\s+does|meaning\s+of|define|how\s+do\s+you\s+say|spell|pronounce|the\s+(?:phrase|string)|containing|contains)\b"

# A single, plain question about the topic is research, not an attack on this model.
META_DISCUSSION = (
    r"(?is)^\s*(?:what\s+(?:is|are|does|do)|why\s+(?:is|are|do|does)|how\s+(?:does|do|can|should|would|to)|"
    r"can\s+you\s+explain|explain|define|describe|is\s+there|are\s+there)\b[^.!?\n]{0,220}"
    r"\b(?:prompt\s+injections?|jailbreak(?:s|ing)?|dan\s+mode|injection\s+attacks?|llm\s+security|guardrails?|"
    r"red[\s-]?team(?:ing)?|system\s+prompts?)\b[^.!?\n]{0,120}[.?]?\s*$"
)
