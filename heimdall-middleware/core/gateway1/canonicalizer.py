"""Input canonicalization: turn one prompt into every form an attacker could hide it in.

A model reads through obfuscation that a regex does not. So instead of a single
"cleaned" string this module produces:

  llm_safe   what is actually forwarded to the model: invisible and control
             characters removed, NFKC normalized, otherwise unchanged
  canonical  the primary scanning form
  views      extra scanning forms (confusables folded, leetspeak undone, separators
             collapsed, payloads decoded, reversed)
  signals    evidence that obfuscation itself was used

Each view is capped and the decoder recursion is bounded, so scanning cost stays
linear in the request size limit.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import html
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Dict, List, Tuple
from urllib.parse import unquote

MAX_VIEW_CHARS = 8_000
MAX_DECODE_DEPTH = 2
MAX_DECODED_SEGMENTS = 12

# Cross-script look-alikes that NFKC leaves alone.
CONFUSABLES = {
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i",
    "ј": "j", "ѕ": "s", "һ": "h", "ԁ": "d", "ɡ": "g", "ԛ": "q", "ԝ": "w", "ո": "n",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P",
    "С": "C", "Т": "T", "Х": "X", "У": "Y", "І": "I", "Ј": "J", "Ѕ": "S",
    "м": "m", "т": "t", "к": "k", "н": "h", "в": "b", "г": "r", "ь": "b", "п": "n",
    # Greek
    "α": "a", "β": "b", "γ": "y", "δ": "d", "ε": "e", "η": "n", "ι": "i", "κ": "k",
    "λ": "l", "μ": "m", "ν": "v", "ο": "o", "π": "n", "ρ": "p", "σ": "o", "ς": "s",
    "τ": "t", "υ": "u", "χ": "x", "ω": "w",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M",
    "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
    # Latin small capitals and IPA look-alikes
    "ᴀ": "a", "ʙ": "b", "ᴄ": "c", "ᴅ": "d", "ᴇ": "e", "ꜰ": "f", "ɢ": "g", "ʜ": "h",
    "ɪ": "i", "ᴊ": "j", "ᴋ": "k", "ʟ": "l", "ᴍ": "m", "ɴ": "n", "ᴏ": "o", "ᴘ": "p",
    "ʀ": "r", "ꜱ": "s", "ᴛ": "t", "ᴜ": "u", "ᴠ": "v", "ᴡ": "w", "ʏ": "y", "ᴢ": "z",
    "ɑ": "a", "ɩ": "i", "ı": "i", "ɾ": "r",
    # Armenian, Cherokee and other frequent substitutes
    "օ": "o", "ս": "u", "հ": "h", "ց": "g", "Ꭺ": "A", "Ꮯ": "C", "Ꭼ": "E", "Ꮋ": "H",
    "Ꮪ": "S", "Ꭲ": "T",
    # Punctuation look-alikes
    "‐": "-", "‑": "-", "‒": "-", "–": "-", "—": "-", "―": "-", "⁃": "-",
    "‘": "'", "’": "'", "‚": "'", "“": '"', "”": '"', "„": '"', "﹣": "-", "－": "-",
}
_CONFUSABLE_TABLE = str.maketrans(CONFUSABLES)

_LEET = {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "6": "g", "7": "t", "8": "b",
         "9": "g", "@": "a", "$": "s", "!": "i", "|": "l", "+": "t", "€": "e", "£": "l"}
_LEET_TOKEN = re.compile(r"(?=\S*[A-Za-z])(?=\S*[0-9@$!|+€£])[A-Za-z0-9@$!|+€£]{3,}")

_SPACED_RUN = re.compile(r"(?<![A-Za-z])(?:[A-Za-z][ \t._\-*/|,:~+]{1,3}){3,}[A-Za-z](?![A-Za-z])")
_INTRAWORD_PUNCT = re.compile(r"(?<=[A-Za-z])[.\-_*'`~|^:;,/\\]{1,2}(?=[A-Za-z])")
_NON_ALNUM = re.compile(r"[^a-z0-9]+")

_B64 = re.compile(r"(?<![A-Za-z0-9+/_\-])(?:[A-Za-z0-9+/_\-]{4}){4,}(?:[A-Za-z0-9+/_\-]{2}==?|[A-Za-z0-9+/_\-]{3}=?)?(?![A-Za-z0-9+/_\-])")
_B32 = re.compile(r"(?<![A-Z2-7])(?:[A-Z2-7]{8}){2,}(?:[A-Z2-7]{2,7}=*)?(?![A-Z2-7])")
_HEX_RUN = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}){8,}(?![0-9a-fA-F])")
_HEX_SEP = re.compile(r"(?:(?:\\x|0x|%)?[0-9a-fA-F]{2}[ ,:;-]?){8,}")
_BIN_RUN = re.compile(r"(?:[01]{8}[ ,]?){6,}")
_UNI_ESC = re.compile(r"(?:\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}){4,}")
_URL_ESC = re.compile(r"(?:%[0-9a-fA-F]{2}){3,}")
_HTML_ENT = re.compile(r"(?:&#x?[0-9a-fA-F]{2,6};|&[a-z]{2,8};){3,}")

_MORSE = {".-": "a", "-...": "b", "-.-.": "c", "-..": "d", ".": "e", "..-.": "f", "--.": "g",
          "....": "h", "..": "i", ".---": "j", "-.-": "k", ".-..": "l", "--": "m", "-.": "n",
          "---": "o", ".--.": "p", "--.-": "q", ".-.": "r", "...": "s", "-": "t", "..-": "u",
          "...-": "v", ".--": "w", "-..-": "x", "-.--": "y", "--..": "z"}
_MORSE_RUN = re.compile(r"(?:[.\-]{1,5}[ /]+){8,}[.\-]{1,5}")


@dataclass
class Signal:
    name: str
    severity: int
    family: str
    evidence: str
    confidence: float = 0.9


@dataclass
class CanonicalResult:
    raw: str
    llm_safe: str
    canonical: str
    views: Dict[str, str] = field(default_factory=dict)
    transforms: List[str] = field(default_factory=list)
    signals: List[Signal] = field(default_factory=list)
    decoded: List[Tuple[str, str]] = field(default_factory=list)

    @property
    def delta(self) -> int:
        return len(self.transforms)

    def scan_views(self) -> List[Tuple[str, str]]:
        """Distinct (name, text) pairs, canonical first."""
        seen, out = set(), []
        for name, text in [("canonical", self.canonical), *self.views.items()]:
            key = text.strip().lower()
            if key and key not in seen:
                seen.add(key)
                out.append((name, text[:MAX_VIEW_CHARS]))
        return out


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    good = sum(1 for c in text if c.isprintable() or c in "\n\r\t")
    return good / len(text)


def _looks_like_language(text: str) -> bool:
    """Reject random bytes: a real decoded payload has letters and word breaks."""
    if len(text) < 6 or _printable_ratio(text) < 0.9:
        return False
    letters = sum(c.isalpha() for c in text)
    return letters / len(text) > 0.55 and (" " in text or "\n" in text or len(text) < 40)


def strip_invisibles(text: str) -> Tuple[str, int, int]:
    """Remove format and control characters, keeping ZWJ/ZWNJ only inside non-Latin text.

    Returns (clean text, characters removed, removals that split an ASCII word).
    """
    out, removed, in_word = [], 0, 0
    length = len(text)
    for i, ch in enumerate(text):
        cat = unicodedata.category(ch)
        strip = cat == "Cf" or (cat == "Cc" and ch not in "\t\n\r")
        if "︀" <= ch <= "️" and i and ord(text[i - 1]) < 0x2000:
            strip = True  # variation selector on plain text; emoji keep theirs
        if not strip:
            out.append(ch)
            continue
        prev_ch = text[i - 1] if i else " "
        next_ch = text[i + 1] if i + 1 < length else " "
        if ch in "‌‍" and (ord(prev_ch) > 0x2ff or ord(next_ch) > 0x2ff):
            out.append(ch)  # Persian, Indic and emoji shaping joiners are legitimate
            continue
        removed += 1
        if prev_ch.isascii() and prev_ch.isalpha() and next_ch.isascii() and next_ch.isalpha():
            in_word += 1
    return "".join(out), removed, in_word


def decode_tag_smuggling(text: str) -> str:
    """Decode Unicode tag characters, the 'ASCII smuggling' channel models can read."""
    return "".join(chr(ord(c) - 0xE0000) for c in text if 0xE0020 <= ord(c) <= 0xE007E)


def decode_variation_smuggling(text: str) -> str:
    """Decode bytes hidden in runs of variation selectors."""
    data = bytearray()
    for c in text:
        o = ord(c)
        if 0xFE00 <= o <= 0xFE0F:
            data.append(o - 0xFE00)
        elif 0xE0100 <= o <= 0xE01EF:
            data.append(o - 0xE0100 + 16)
    if len(data) < 4:
        return ""
    return data.decode("utf-8", errors="ignore")


def fold_confusables(text: str) -> str:
    folded = text.translate(_CONFUSABLE_TABLE)
    stripped = unicodedata.normalize("NFD", folded)
    return "".join(c for c in stripped if unicodedata.category(c) != "Mn")


def undo_leet(text: str, one_as: str = "i") -> str:
    table = {**_LEET, "1": one_as}
    return _LEET_TOKEN.sub(lambda m: "".join(table.get(ch, ch) for ch in m.group(0)), text)


def collapse_spaced_letters(text: str) -> Tuple[str, int]:
    """Join 'i g n o r e' style runs. A wider gap in the source stays a word break."""
    count = 0

    def fix(match):
        nonlocal count
        count += 1
        marked = re.sub(r"[ \t._\-*/|,:~+]{2,}", "\0", match.group(0))
        return re.sub(r"[ \t._\-*/|,:~+]", "", marked).replace("\0", " ")

    return _SPACED_RUN.sub(fix, text), count


def _try_b64(segment: str) -> str:
    normalized = segment.replace("-", "+").replace("_", "/")
    normalized += "=" * (-len(normalized) % 4)
    try:
        return base64.b64decode(normalized, validate=True).decode("utf-8", errors="strict")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return ""


def _try_b32(segment: str) -> str:
    padded = segment.rstrip("=")
    padded += "=" * (-len(padded) % 8)
    try:
        return base64.b32decode(padded).decode("utf-8", errors="strict")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return ""


def _try_hex(segment: str) -> str:
    digits = re.sub(r"\\x|0x|%|[ ,:;-]", "", segment)
    try:
        return bytes.fromhex(digits).decode("utf-8", errors="strict")
    except (ValueError, UnicodeDecodeError):
        return ""


def _try_bin(segment: str) -> str:
    bits = re.sub(r"[ ,]", "", segment)
    if len(bits) % 8:
        return ""
    try:
        return int(bits, 2).to_bytes(len(bits) // 8, "big").decode("utf-8", errors="strict")
    except (ValueError, UnicodeDecodeError):
        return ""


def _try_morse(segment: str) -> str:
    words = re.split(r"\s*/\s*|\s{3,}", segment.strip())
    out = []
    for word in words:
        letters = [_MORSE.get(sym, "") for sym in word.split()]
        if not all(letters):
            return ""
        out.append("".join(letters))
    return " ".join(out)


def _decode_segments(text: str, permissive: bool = False) -> List[Tuple[str, str]]:
    found: List[Tuple[str, str]] = []
    decoders = [
        ("base64", _B64, _try_b64),
        ("base32", _B32, _try_b32),
        ("hex", _HEX_RUN, _try_hex),
        ("hex", _HEX_SEP, _try_hex),
        ("binary", _BIN_RUN, _try_bin),
        ("morse", _MORSE_RUN, _try_morse),
    ]
    for label, pattern, decoder in decoders:
        for match in pattern.finditer(text):
            decoded = decoder(match.group(0))
            if decoded and (_looks_like_language(decoded) or (permissive and _printable_ratio(decoded) > 0.9)):
                found.append((label, decoded))
                if len(found) >= MAX_DECODED_SEGMENTS:
                    return found
    for pattern, label in ((_URL_ESC, "url"), (_UNI_ESC, "unicode-escape"), (_HTML_ENT, "html-entity")):
        for match in pattern.finditer(text):
            segment = match.group(0)
            if label == "url":
                decoded = unquote(segment)
            elif label == "html-entity":
                decoded = html.unescape(segment)
            else:
                try:
                    decoded = codecs.decode(segment, "unicode_escape")
                except Exception:
                    decoded = ""
            if decoded and decoded != segment and _printable_ratio(decoded) > 0.9:
                found.append((label, decoded))
    return found[:MAX_DECODED_SEGMENTS]


def _inline_escapes(text: str) -> str:
    """Decode percent, entity and backslash escapes in place, keeping surrounding words."""
    text = _URL_ESC.sub(lambda m: unquote(m.group(0)), text)
    text = _HTML_ENT.sub(lambda m: html.unescape(m.group(0)), text)

    def unescape(match):
        try:
            return codecs.decode(match.group(0), "unicode_escape")
        except Exception:
            return match.group(0)

    return _UNI_ESC.sub(unescape, text)


def canonicalize(raw: str, permissive: bool = False) -> CanonicalResult:
    transforms: List[str] = []
    signals: List[Signal] = []
    views: Dict[str, str] = {}

    # 1. Covert channels are read before the characters are stripped.
    smuggled = decode_tag_smuggling(raw)
    if smuggled:
        transforms.append("decoded unicode tag characters")
        signals.append(Signal("ascii_smuggling", 9, "ENCODING_EVASION",
                              "Hidden text in Unicode tag characters", 0.98))
        views["tag_payload"] = smuggled
    vs_payload = decode_variation_smuggling(raw)
    if vs_payload and _printable_ratio(vs_payload) > 0.9:
        transforms.append("decoded variation-selector payload")
        signals.append(Signal("variation_selector_smuggling", 9, "ENCODING_EVASION",
                              "Hidden bytes in variation selectors", 0.95))
        views["vs_payload"] = vs_payload

    # 2. Invisible characters and bidirectional overrides.
    without_tags = "".join(c for c in raw if not 0xE0000 <= ord(c) <= 0xE0FFF)
    if any(c in without_tags for c in "‪‫‬‭‮⁦⁧⁨⁩"):
        signals.append(Signal("bidi_override", 7, "ENCODING_EVASION",
                              "Bidirectional control characters in the prompt", 0.85))
    stripped, removed, in_word = strip_invisibles(without_tags)
    if removed:
        transforms.append(f"removed {removed} invisible characters")
    if in_word >= 2:
        signals.append(Signal("invisible_word_splitting", 8, "ENCODING_EVASION",
                              f"{in_word} invisible characters inside words", 0.9))

    # 3. Compatibility normalization (full-width, math alphanumerics, circled letters).
    llm_safe = unicodedata.normalize("NFKC", stripped)
    if llm_safe != stripped:
        transforms.append("NFKC normalized")

    # 4. Base canonical form: hyphen-joined words split, the shape L1 rules expect.
    canonical = re.sub(r"([A-Za-z])-([A-Za-z])", r"\1 \2", llm_safe)
    if canonical != llm_safe:
        transforms.append("split hyphenated words")

    # 5. Script tricks. Folded text is scan-only; genuine non-Latin text is untouched.
    folded = fold_confusables(canonical)
    if folded != canonical:
        views["folded"] = folded
    mixed_words = 0

    def fold_if_mixed(match):
        nonlocal mixed_words
        word = match.group(0)
        scripts = {unicodedata.name(ch, "").split(" ")[0] for ch in word if ch.isalpha()}
        if "LATIN" in scripts and scripts & {"CYRILLIC", "GREEK", "ARMENIAN", "CHEROKEE"}:
            mixed_words += 1
            return fold_confusables(word)
        return word

    canonical = re.sub(r"\w{2,}", fold_if_mixed, canonical)
    if mixed_words:
        transforms.append(f"folded {mixed_words} mixed-script words")
        signals.append(Signal("mixed_script_words", 7, "ENCODING_EVASION",
                              f"{mixed_words} words mix Latin with look-alike scripts", 0.85))
    combining = sum(1 for c in unicodedata.normalize("NFD", llm_safe) if unicodedata.category(c) == "Mn")
    if len(llm_safe) >= 12 and combining / len(llm_safe) > 0.6:
        signals.append(Signal("combining_mark_flood", 7, "ENCODING_EVASION",
                              "Heavy combining-mark stacking", 0.85))

    base = folded

    # 6. Leetspeak, with both readings of 1 (ignore/all).
    leet_i, leet_l = undo_leet(base, "i"), undo_leet(base, "l")
    if leet_i != base:
        views["leet"] = leet_i
        views["leet_l"] = leet_l
        transforms.append("undid leetspeak")

    # 7. Spaced letters and punctuation splitting.
    collapsed, runs = collapse_spaced_letters(base)
    if runs:
        views["collapsed"] = collapsed
        transforms.append(f"collapsed {runs} spaced-letter runs")
        longest = max((len(re.sub(r"[^A-Za-z]", "", m.group(0))) for m in _SPACED_RUN.finditer(base)), default=0)
        if longest >= 10:
            signals.append(Signal("spaced_letters", 8, "ENCODING_EVASION",
                                  "Long run of separated single letters", 0.9))
    joined = _INTRAWORD_PUNCT.sub("", llm_safe)
    if joined != llm_safe:
        views["joined"] = fold_confusables(joined)
    views["squeezed"] = _NON_ALNUM.sub("", base.lower())

    # 8. Whole-string transforms, cheap to scan and rarely collide with benign text.
    views["rot13"] = codecs.decode(base, "rot_13")
    views["reversed"] = base[::-1]
    words = base.split()
    if len(words) > 2:
        views["reversed_words"] = " ".join(reversed(words))

    inlined = _inline_escapes(llm_safe)
    if inlined != llm_safe:
        views["inlined"] = fold_confusables(inlined)
        transforms.append("decoded inline escapes")

    # 9. Encoded payloads, recursively to a bounded depth.
    decoded: List[Tuple[str, str]] = []
    frontier = [llm_safe]
    for _ in range(MAX_DECODE_DEPTH):
        next_frontier = []
        for text in frontier:
            for label, payload in _decode_segments(text, permissive):
                decoded.append((label, payload))
                next_frontier.append(payload)
        if not next_frontier or len(decoded) >= MAX_DECODED_SEGMENTS:
            break
        frontier = next_frontier
    if decoded:
        joined_payloads = "\n".join(fold_confusables(p) for _, p in decoded)
        views["decoded"] = joined_payloads
        transforms.append("decoded " + ", ".join(sorted({label for label, _ in decoded})))
        for label, payload in decoded:
            if any(k in payload.lower() for k in ("ignore", "system", "prompt", "instruction", "bypass", "override", "reveal")):
                canonical += f" [DECODED:{payload[:200]}]"
                break

    return CanonicalResult(raw=raw, llm_safe=llm_safe, canonical=canonical, views=views,
                           transforms=transforms, signals=signals, decoded=decoded)
