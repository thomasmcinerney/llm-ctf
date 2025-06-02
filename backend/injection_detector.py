"""
Ultimate prompt‑ & command‑injection detector   (v2025‑06‑01)

Goals
─────
• Near‑state‑of‑the‑art recall on public jailbreak corpora (≥92 % F1)
• Zero external deps beyond Transformers + requests (OpenAI optional)
• Self‑contained: drop‑in for any FastAPI / Flask backend

Public API
──────────
detect_prompt_injection(text:str) -> List[str]
    • Returns sorted labels, e.g. ["directory_traversal","shell_command_attempt"]
    • Benign RP → "benign_roleplay"   ML catch‑all → "ml_flag"
"""

from __future__ import annotations
import html, json, os, re, ssl, time, unicodedata, urllib.request, logging, asyncio
from pathlib import Path
from typing import Dict, List, Set
from text_normaliser import normalise

# ──────────────────────────────────────────────────────────────
# 0Logging
# ──────────────────────────────────────────────────────────────
LOG = logging.getLogger("injection_detector")
LOG.setLevel(logging.INFO)
if not LOG.handlers:
    LOG.addHandler(logging.FileHandler("logs/jailbreak_regress.log", encoding="utf‑8"))
    LOG.addHandler(logging.StreamHandler())

# ──────────────────────────────────────────────────────────────
# 1External rules – Rebuff feed (hourly)
# ──────────────────────────────────────────────────────────────
_FEED_URL = (
    "https://raw.githubusercontent.com/protectai/rebuff/main/"
    "rebuff/rules/prompt_injection.json"
)
_CACHE = Path(".rebuff_cache.json")
_TTL = 3600
_last_dl = 0.0


def _rebuff() -> Dict[str, List[str]]:
    global _last_dl
    if _CACHE.exists() and time.time() - _last_dl < _TTL:
        try:
            return json.loads(_CACHE.read_text())
        except Exception:
            pass
    try:
        with urllib.request.urlopen(_FEED_URL, context=ssl.create_default_context(), timeout=5) as r:
            data = json.loads(r.read().decode())
            _CACHE.write_text(json.dumps(data))
            _last_dl = time.time()
            LOG.info("Rebuff rule‑feed refreshed(%drule groups)", len(data))
            return data
    except Exception as e:
        LOG.warning("Rebuff feed unavailable: %s", e)
        try:
            return json.loads(_CACHE.read_text())
        except Exception:
            return {}

# ──────────────────────────────────────────────────────────────
# 2Static rule base (140patterns)
# ──────────────────────────────────────────────────────────────
_BASE: Dict[str, List[str]] = json.loads(Path(__file__).with_name(
    "base_patterns.json").read_text(encoding="utf‑8"))

# Contents of base_patterns.json trimmed here for brevity; it carries:
#   • instruction_bypass, role_manipulation, jailbreak_mode, context_switch,
#   • social_engineering, prompt_leak, prompt_override,
#   • directory_traversal, file_access, system_command, shell_meta, encoded_cmd
# with 140 carefully‑tuned regexes.

# ──────────────────────────────────────────────────────────────
# 3Canonicaliser
# ──────────────────────────────────────────────────────────────

_ENT_RE = re.compile(r"&(#x?[0-9a-f]+|\w+);", re.I)

def _canon(text: str) -> str:
    """Delegate to the shared normaliser."""
    return normalise(text)

# ──────────────────────────────────────────────────────────────
# 4Compile combined rules
# ──────────────────────────────────────────────────────────────
# ──────────────────────────────────────────────────────────────
# 4Compile combined rules (merge – don’t overwrite)          *
# ──────────────────────────────────────────────────────────────
def _compile(*dicts) -> Dict[str, List[re.Pattern]]:
    """
    Combine multiple  {label: [regex, …]}  dicts without losing
    patterns that share the same label.
    """
    merged: Dict[str, List[str]] = {}
    for d in dicts:
        for key, plist in d.items():
            merged.setdefault(key, []).extend(plist)

    # Deduplicate (rare) identical strings before compiling
    return {
        k: [re.compile(p, re.I) for p in dict.fromkeys(plist)]
        for k, plist in merged.items()
    }

# Build the final ruleset
_RULES = _compile(_BASE, _rebuff())

# ──────────────────────────────────────────────────────────────
# 5Heuristics
# ──────────────────────────────────────────────────────────────
_SHELL_HEADS: Set[str] = set(json.loads(
    Path(__file__).with_name("shell_heads.json").read_text(encoding="utf‑8")))

# ──────────────────────────────────────────────────────────────
# 6ML ensemble (open + OpenAI)
# ──────────────────────────────────────────────────────────────
try:
    from transformers import pipeline
    _hf_guard = pipeline("text-classification", model="SaFoLab-WISC/InjecGuard", device="cpu")
except Exception:
    _hf_guard = None

_OPENAI_KEY = os.getenv("OPENAI_API_KEY")
async def _openai_flag(text: str) -> bool:
    if not _OPENAI_KEY:
        return False
    import aiohttp
    headers = {"Authorization": f"Bearer {_OPENAI_KEY}"}
    async with aiohttp.ClientSession(headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as s:
        async with s.post(
            "https://api.openai.com/v1/moderations", json={"input": text}
        ) as r:
            if r.status == 200:
                cat = (await r.json())["results"][0]["category_scores"]
                return cat.get("harassment", 0) > 0.4 or cat.get("self-harm", 0) > 0.4
    return False

_ML_THRESH = 0.6
_MIN_LEN = 12

# ──────────────────────────────────────────────────────────────
# 7Lightweight hex decoder for re‑inspection
# ──────────────────────────────────────────────────────────────
_HEX_BLOCK = re.compile(r"(?:[0-9A-Fa-f]{2}\s*){4,}")

def _decoded_hex_segments(text: str) -> List[str]:
    """Return readable UTF‑8 strings decoded from space‑/bare‑hex blocks."""
    out: List[str] = []
    for blk in _HEX_BLOCK.findall(text):
        cleaned = re.sub(r"\s+", "", blk)          # strip spaces/newlines
        try:
            decoded = bytes.fromhex(cleaned).decode("utf‑8", "ignore")
            if decoded.strip():
                out.append(decoded)
        except ValueError:
            continue
    return out

# ──────────────────────────────────────────────────────────────
# 8Public API
# ──────────────────────────────────────────────────────────────
def detect_prompt_injection(user_input: str) -> List[str]:
    """
    Detect prompt / command injection; return sorted labels.
    """
    if not user_input or not user_input.strip():
        return []
    text = normalise(user_input)
    labs: Set[str] = set()

    # 8‑Astatic patterns
    for tag, plist in _RULES.items():
        if any(p.search(text) for p in plist):
            if tag == "role_manipulation":
                benign = {"roleplay", "role‑play", "play", "pretend", "imagine"}
                harmful = {"ignore", "override", "bypass", "root", "system", "admin"}
                labs.add("benign_roleplay" if any(b in text.lower() for b in benign) and
                         not any(h in text.lower() for h in harmful) else tag)
            else:
                labs.add(tag)

    # Layer‑2 heuristics
    first = text.split()[0].lower() if text.split() else ""
    if first in _SHELL_HEADS:
        labs.add("shell_command_attempt")

    if re.search(r"\bhome\s+dir(?:ectory)?\b", text) and \
       re.search(r"\b(?:tell|show|list|give|get|what(?:'s| is))\b", text):
        labs.add("outside_workspace_nl")

    if re.search(r"\b[a-z]{1,8}\s+\.\.\s*$", text):
        labs.add("directory_traversal")

    # 8‑D hex‑encoded payloads  (e.g. "54 65 73 74")
    for decoded in _decoded_hex_segments(text):
        labs.add("encoded_hex")                    # new explicit label
        # Re‑inspect the decoded content for further tags
        labs.update(detect_prompt_injection(decoded))

    # 8‑CML guard
    if len(text) >= _MIN_LEN:
        if _hf_guard and _hf_guard(text, truncation=True, max_length=512)[0]["score"] >= _ML_THRESH:
            labs.add("ml_flag")
        elif _OPENAI_KEY:
            try:
                if asyncio.run(_openai_flag(text)):
                    labs.add("ml_flag")
            except Exception:
                pass

    return sorted(labs)
