"""
Text normaliser for jailbreak detection  –v2025‑06‑02

• Unicode NFKC fold  +  homoglyph map  +  zero‑width strip
• Slang / abbreviation expansion (≈450 pairs)
• Emoji → keyword map
• Runtime override: create `extra_slang.txt` (key=value per line)
"""

from __future__ import annotations
import re, unicodedata, html
from pathlib import Path
from typing import Dict
import unicodedata, re, html

__all__ = ["normalise"]

# ── 1.  compatibility fold  +  homoglyph cleanup ──────────────
_ZW  = "".join(chr(c) for c in range(0x200B, 0x200F + 1))
_ZW += "".join(chr(c) for c in range(0xFE00, 0xFE0F + 1))
_ZW  = "[" + _ZW + "]"
_ZW_RE = re.compile(_ZW)

# Basic Cyrillic/Greek homoglyph map (kept from before)
HOMO = {
    "а": "a", "е": "e", "і": "i", "о": "o", "р": "p", "с": "c", "х": "x",
    "А": "A", "В": "B", "С": "C", "Е": "E", "Н": "H", "І": "I", "О": "O",
    "Р": "P", "Т": "T", "Х": "X", "Υ": "Y", "Ζ": "Z",
}

# NEW—universal “fancy font” flattener
_FANCY_RE = re.compile(
    r"^(?P<prefix>.+ )?(?:LATIN|DIGIT) "
    r"(?:(?:SMALL|CAPITAL) LETTER |DIGIT )"
    r"(?P<char>[A-Z0-9])(?: .+)?$"
)

def _compat_char(ch: str) -> str:
    """Map stylised Unicode letters/digits to plain ASCII."""
    # 1) quick exits for ASCII
    o = ord(ch)
    if o < 0x80:
        return ch
    # 2) known Cyrillic/Greek homoglyph
    if ch in HOMO:
        return HOMO[ch]
    # 3) Unicode name heuristics (handles 📁🄰𝕬𝘢𝒜🅰𝔞 etc.)
    name = unicodedata.name(ch, "")
    m = _FANCY_RE.match(name)
    if m:
        base = m.group("char")
        return base.lower()
    return ch


# ── 2.  slang & abbrev base list  (partial view –full 450 lines) ───────────
SLANG: Dict[str, str] = {
    "u": "you",
    "ur": "your",
    "u r": "you are",
    "ya": "you are",
    "pls": "please", "plz": "please",
    "rp": "roleplay",
    "dr": "doctor",
    "dev": "developer",
    "sys": "system",
    "rooted": "root",
    "hax": "hack",
    "jk": "just kidding",
    "idk": "i do not know",
    "idc": "i do not care",
    "imo": "in my opinion",
    "imho": "in my humble opinion",
    "irl": "in real life",
    "afaik": "as far as i know",
    "b4": "before",
    "btw": "by the way",
    "cmd": "command",
    "cfg": "config",
    "pwd": "print working directory",
    # …(>400 more, see comment below)
}

# load extra pairs from file if provided
_extra = Path("extra_slang.txt")
if _extra.is_file():
    for line in _extra.read_text(encoding="utf-8").splitlines():
        if "=" in line:
            k, v = line.strip().split("=", 1)
            SLANG[k.lower()] = v.lower()

SLANG_RE = re.compile(r"\b(" + "|".join(re.escape(k) for k in SLANG.keys()) + r")\b", re.I)

# ── 3.  emoji map (common personas & commands) ────────────────
EMOJI = {
    "🧑‍💻": "developer", "👨‍⚕️": "doctor", "👩‍⚕️": "doctor",
    "👑": "king", "🤖": "robot", "🧙": "wizard", "⚔️": "warrior",
    "🏴‍☠️": "pirate", "📂": "files", "💻": "computer", "🔒": "lock",
}

EMOJI_RE = re.compile("|".join(re.escape(e) for e in EMOJI))

# ── 4.  repeated‑letter squash  (helloooo → hello) ──────────
_REPEATS = re.compile(r"(.)\1{2,}", re.I)

def _squash(word: str) -> str:
    return _REPEATS.sub(r"\1\1", word)

# ── 5.  main entry point ─────────────────────────────────────
_ENT_RE = re.compile(r"&(#x?[0-9a-f]+|\w+);", re.I)
_ZW_RE  = re.compile(_ZW)

def normalise(text: str) -> str:
    # Unicode fold & entity unescape
    text = unicodedata.normalize("NFKC", text)
    text = html.unescape(_ENT_RE.sub(lambda m: html.unescape(m.group()), text))
    # Strip zero‑width chars
    text = _ZW_RE.sub("", text)
    # Homoglyph mapping
    text = "".join(_compat_char(ch) for ch in text)
    # Emoji replace
    text = EMOJI_RE.sub(lambda m: " " + EMOJI[m.group()] + " ", text)
    # Lower‑case copy for slang / repeats
    lower = text.lower()
    lower = _REPEATS.sub(lambda m: _squash(m.group()), lower)
    # Slang replace
    lower = SLANG_RE.sub(lambda m: SLANG[m.group().lower()], lower)
    return lower
