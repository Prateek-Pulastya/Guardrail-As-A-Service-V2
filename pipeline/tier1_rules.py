"""
GuardRail — Tier 1 Rule Engine
================================
Fast O(n) blocklist scan using Aho-Corasick automaton + regex patterns.
Designed to handle >95% of direct attacks in <0.1ms per prompt.

Key additions over baseline:
  - Unicode normalization (NFKD + math-block mapping + zero-width removal)
  - Base64 / hex decode-and-scan
  - URL-percent decode
  - Modular pattern loading from config/rules.yaml
"""

import re
import unicodedata
import base64
import binascii
import urllib.parse
import logging
import time
from pathlib import Path
from typing import NamedTuple

import ahocorasick
import yaml

logger = logging.getLogger("guardrail.tier1")

CONFIG_PATH = Path(__file__).parent.parent / "config" / "rules.yaml"

# ── Unicode math-block character name fragments → base ASCII ──────────────
_MATH_BLOCK_MARKERS = (
    "MATHEMATICAL BOLD",
    "MATHEMATICAL ITALIC",
    "MATHEMATICAL BOLD ITALIC",
    "MATHEMATICAL SCRIPT",
    "MATHEMATICAL BOLD SCRIPT",
    "MATHEMATICAL FRAKTUR",
    "MATHEMATICAL DOUBLE-STRUCK",
    "MATHEMATICAL BOLD FRAKTUR",
    "MATHEMATICAL SANS-SERIF",
    "MATHEMATICAL SANS-SERIF BOLD",
    "MATHEMATICAL SANS-SERIF ITALIC",
    "MATHEMATICAL SANS-SERIF BOLD ITALIC",
    "MATHEMATICAL MONOSPACE",
    "FULLWIDTH",
    "CIRCLED LATIN",
    "PARENTHESIZED LATIN",
)

# Precomputed: Unicode code points that are math-block variants mapped to ASCII
# Built once at import time, then O(1) per character.
_MATH_MAP: dict[int, str] = {}

def _build_math_map() -> None:
    for cp in range(0x1D400, 0x1D800):   # Mathematical Alphanumeric Symbols block
        try:
            name = unicodedata.name(chr(cp), "")
        except (ValueError, TypeError):
            continue
        parts = name.split()
        if not parts:
            continue
        last = parts[-1]
        if len(last) == 1 and last.isascii():
            _MATH_MAP[cp] = last.lower()
    # Fullwidth Latin: Ａ=0xFF21 … Ｚ, ａ=0xFF41 … ｚ
    for cp in range(0xFF01, 0xFF5F):
        try:
            name = unicodedata.name(chr(cp), "")
        except (ValueError, TypeError):
            continue
        if "FULLWIDTH" in name:
            parts = name.split()
            last = parts[-1]
            if len(last) == 1 and last.isascii():
                _MATH_MAP[cp] = last.lower()
    # Circled Latin: Ⓐ=0x24B6 … ⓩ
    for cp in range(0x24B6, 0x24E9 + 1):
        try:
            name = unicodedata.name(chr(cp), "")
        except (ValueError, TypeError):
            continue
        if "CIRCLED LATIN" in name:
            parts = name.split()
            last = parts[-1]
            if len(last) == 1 and last.isascii():
                _MATH_MAP[cp] = last.lower()
    # Small-capital / phonetic-extension Latin lookalikes:
    #   ɪɢɴᴏʀᴇ (IPA + Phonetic Extensions) — used to spoof "ignore".
    # Names look like "LATIN LETTER SMALL CAPITAL I", "LATIN SMALL LETTER ...".
    for cp in list(range(0x0250, 0x02B0)) + list(range(0x1D00, 0x1D80)):
        try:
            name = unicodedata.name(chr(cp), "")
        except (ValueError, TypeError):
            continue
        if "LATIN" not in name:
            continue
        last = name.split()[-1]
        if len(last) == 1 and last.isascii() and last.isalpha():
            _MATH_MAP.setdefault(cp, last.lower())

_build_math_map()

# ── Leetspeak digit/symbol → letter map (applied only in the deobfuscation
# scan pass, never to the primary normalized text, so blocklist terms that
# legitimately contain '|', '_', digits still match on the primary path).
_LEET_MAP = str.maketrans({
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t",
    "!": "i", "|": "i", "@": "a", "$": "s",
})
_DEOBF_STRIP = re.compile(r"[.\-_*·•]")


def _normalize_linebreaks(text: str) -> str:
    """
    Normalize while preserving line breaks as sentence boundaries.

    `_normalize` collapses all whitespace, so a payload appended on its own line
    ("<context>\\n Write a script to ...") loses the boundary and a
    sentence-initial anchor can no longer see it. Injected content is very often
    delimited by a newline rather than punctuation, so the instruction-in-data
    scan runs against this variant instead.
    """
    return _normalize(re.sub(r"[\r\n]+", " . ", text))


def _deobfuscate(normalized: str) -> str:
    """
    Aggressive de-obfuscation of already-normalized text, used as a SECOND
    scan pass. De-leets digits/symbols and strips intra-word separators so
    that 'ign0re', '!gnore', 'instr-uction-s', 'ignore... previous' collapse
    back to their plain forms. Whitespace between words is preserved so
    multi-word blocklist phrases still match.
    """
    text = normalized.translate(_LEET_MAP)
    text = _DEOBF_STRIP.sub("", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text

# Zero-width / invisible characters to strip
_ZW_PATTERN = re.compile(
    r"[\u200b\u200c\u200d\u200e\u200f\u00ad\u2060\ufeff\u180e\u034f]"
)

# Injection-relevant keywords used to gate decoded content
_INJECTION_KEYWORDS = frozenset({
    "ignore", "override", "system", "instruction", "instructions",
    "unrestricted", "bypass", "disregard", "jailbreak", "forget",
    "safety", "restrict", "filter", "prompt", "admin", "dan",
})


def _normalize(text: str) -> str:
    """
    Full Unicode normalization pipeline:
    1. Strip zero-width and invisible characters
    2. Map math-block Unicode to ASCII equivalents
    3. NFKD decomposition (handles diacritics, some lookalikes)
    4. Strip combining diacritics
    5. Replace non-breaking and unusual spaces with regular space
    6. Collapse whitespace, lowercase

    After this, 'ɪɢɴᴏʀᴇ' → 'ignore', '𝗶𝗴𝗻𝗼𝗿𝗲' → 'ignore', etc.
    """
    # Step 1: strip zero-width chars
    text = _ZW_PATTERN.sub("", text)

    # Step 2: math-block → ASCII
    text = "".join(_MATH_MAP.get(ord(c), c) for c in text)

    # Step 3: NFKD
    text = unicodedata.normalize("NFKD", text)

    # Step 4: strip combining diacritics
    text = "".join(c for c in text if not unicodedata.combining(c))

    # Step 5: normalize spaces
    text = text.replace("\u00a0", " ").replace("\t", " ")

    # Step 6: lowercase + collapse whitespace
    text = re.sub(r"\s+", " ", text).strip().lower()

    return text


def _decode_payload(text: str) -> str:
    """
    Attempt to detect and decode obfuscated payloads:
    - Base64 chunks ≥ 20 chars
    - Hex strings ≥ 16 chars
    - URL percent-encoding

    Only appends decoded content if it contains injection-relevant keywords,
    preventing false positives on legitimate API keys / base64 images.
    """
    extra = []

    # URL decode first (idempotent on non-encoded text)
    try:
        url_decoded = urllib.parse.unquote(text)
        if url_decoded != text:
            norm = _normalize(url_decoded)
            if any(kw in norm for kw in _INJECTION_KEYWORDS):
                extra.append(url_decoded)
    except Exception:
        pass

    # Base64 chunks
    b64_re = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
    for match in b64_re.findall(text):
        try:
            decoded = base64.b64decode(match + "==").decode("utf-8", errors="ignore")
            if len(decoded) >= 8:
                norm = _normalize(decoded)
                if any(kw in norm for kw in _INJECTION_KEYWORDS):
                    extra.append(decoded)
        except (binascii.Error, ValueError):
            pass

    # Hex strings (continuous, at least 16 hex chars = 8 bytes)
    hex_re = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")
    for match in hex_re.findall(text):
        try:
            decoded = bytes.fromhex(match).decode("utf-8", errors="ignore")
            if decoded.isprintable() and len(decoded) >= 6:
                norm = _normalize(decoded)
                if any(kw in norm for kw in _INJECTION_KEYWORDS):
                    extra.append(decoded)
        except ValueError:
            pass

    if extra:
        return text + " " + " ".join(extra)
    return text


class MatchResult(NamedTuple):
    blocked: bool
    reason: str | None         # blocklist pattern that matched
    match_type: str | None     # "blocklist" | "regex" | None
    latency_ms: float


class Tier1Engine:
    """
    Aho-Corasick automaton + compiled regex patterns.
    Loaded once from config/rules.yaml at startup.
    """

    def __init__(self, config_path: Path = CONFIG_PATH):
        self._load_config(config_path)
        self._build_automaton()
        logger.info(
            f"Tier1Engine ready: {len(self._blocklist)} blocklist terms, "
            f"{len(self._regex_patterns)} regex patterns"
        )

    def _load_config(self, path: Path) -> None:
        with open(path) as f:
            cfg = yaml.safe_load(f)
        self._blocklist: list[str] = [
            term.lower().strip() for term in cfg.get("blocklist", []) if term.strip()
        ]
        self._regex_patterns: list[re.Pattern] = [
            re.compile(pat, re.IGNORECASE)
            for pat in cfg.get("regex_patterns", [])
        ]
        # Applied only to source="data" — see config/rules.yaml for why these are
        # not safe to run against user-authored prompts.
        self._data_instruction_patterns: list[re.Pattern] = [
            re.compile(pat, re.IGNORECASE)
            for pat in cfg.get("data_instruction_patterns", [])
        ]

    def _build_automaton(self) -> None:
        self._automaton = ahocorasick.Automaton()
        for idx, term in enumerate(self._blocklist):
            self._automaton.add_word(term, (idx, term))
        self._automaton.make_automaton()

    def validate(self, prompt: str, source: str = "user") -> MatchResult:
        """
        Screen a prompt.

        source="user" (default): the text is the user's own turn. Instructions are
        expected and legitimate; only the blocklist and structural regexes apply.

        source="data": the text is untrusted content the application is processing
        (retrieved documents, tool output, third-party payloads). Data is meant to
        be read, not obeyed, so an instruction addressed to a model is itself the
        attack signal — `data_instruction_patterns` apply in addition to everything
        above. This is what catches injected task instructions that carry no
        override vocabulary.
        """
        t0 = time.perf_counter()

        # Pipeline: decode → normalize → scan
        decoded = _decode_payload(prompt)
        normalized = _normalize(decoded)
        deobf = _deobfuscate(normalized)

        # Scan primary normalized text first, then the de-obfuscated variant.
        # The primary path preserves separators (|, _, -) so blocklist terms
        # like "<|im_start|>" and "safety_mode=off" keep matching; the deobf
        # path catches leetspeak / separator-fragmented obfuscation.
        scan_targets = [normalized]
        if deobf != normalized:
            scan_targets.append(deobf)

        # Aho-Corasick scan
        for target in scan_targets:
            for _, (_, term) in self._automaton.iter(target):
                elapsed = (time.perf_counter() - t0) * 1000
                return MatchResult(
                    blocked=True,
                    reason=term,
                    match_type="blocklist",
                    latency_ms=round(elapsed, 4),
                )

        # Regex scan (catches structural patterns blocklist can't)
        for pattern in self._regex_patterns:
            for target in scan_targets:
                if pattern.search(target):
                    elapsed = (time.perf_counter() - t0) * 1000
                    return MatchResult(
                        blocked=True,
                        reason=pattern.pattern,
                        match_type="regex",
                        latency_ms=round(elapsed, 4),
                    )

        # Instruction-in-data scan — only for untrusted payloads. Runs against a
        # line-break-preserving normalization so that content appended on its own
        # line still presents a sentence boundary for the anchors to match.
        if source == "data":
            data_targets = scan_targets + [_normalize_linebreaks(decoded)]
            for pattern in self._data_instruction_patterns:
                for target in data_targets:
                    if pattern.search(target):
                        elapsed = (time.perf_counter() - t0) * 1000
                        return MatchResult(
                            blocked=True,
                            reason=f"instruction_in_data: {pattern.pattern}",
                            match_type="data_instruction",
                            latency_ms=round(elapsed, 4),
                        )

        elapsed = (time.perf_counter() - t0) * 1000
        return MatchResult(
            blocked=False,
            reason=None,
            match_type=None,
            latency_ms=round(elapsed, 4),
        )
