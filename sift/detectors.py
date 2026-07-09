"""The five detectors that power sift-sim.

Each detector exposes:
    detect(text: str) -> Iterable[Finding]

Detectors are pure functions of the text; no model calls, no network.
That keeps sift-sim fast, deterministic, and easy to embed in pipelines
that already pay for LLM inference.
"""

from __future__ import annotations

import base64
import binascii
import math
import re
import string
import unicodedata
from collections import Counter
from typing import Iterable, List

from .report import Finding


# --------------------------------------------------------------------------- #
# Detector 1: Base64 / hex / ROT13 smuggled payloads
# --------------------------------------------------------------------------- #

_B64_RE = re.compile(r"\b[A-Za-z0-9+/]{20,}={0,2}\b")
_HEX_RE = re.compile(r"\b(?:0x)?[0-9a-fA-F]{16,}\b")
_ROT13_HINT_RE = re.compile(r"\[rot13\]\s*([A-Za-z\s.,!?]{20,})", re.IGNORECASE)


def _b64_decodes_safely(s: str) -> bool:
    """True if the candidate round-trips through base64 into printable ASCII."""
    try:
        padded = s + "=" * (-len(s) % 4)
        decoded = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return False
    try:
        text = decoded.decode("utf-8")
    except UnicodeDecodeError:
        return False
    printable = sum(1 for c in text if c in string.printable)
    return printable / max(1, len(text)) > 0.9 and len(text) >= 8


def _hex_decodes_safely(s: str) -> bool:
    body = s[2:] if s.startswith(("0x", "0X")) else s
    if len(body) % 2 != 0:
        return False
    try:
        decoded = bytes.fromhex(body).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return False
    return all(c in string.printable for c in decoded) and len(decoded) >= 6


def detect_encoded_payloads(text: str) -> List[Finding]:
    findings: List[Finding] = []
    for m in _B64_RE.finditer(text):
        token = m.group(0)
        if _b64_decodes_safely(token):
            findings.append(
                Finding(
                    detector="encoded.base64",
                    confidence=0.85,
                    span=m.span(),
                    snippet=token[:60] + ("…" if len(token) > 60 else ""),
                    reason="long base64 token decodes to printable text",
                )
            )
    for m in _HEX_RE.finditer(text):
        token = m.group(0)
        if _hex_decodes_safely(token):
            findings.append(
                Finding(
                    detector="encoded.hex",
                    confidence=0.7,
                    span=m.span(),
                    snippet=token[:60] + ("…" if len(token) > 60 else ""),
                    reason="long hex string decodes to printable text",
                )
            )
    for m in _ROT13_HINT_RE.finditer(text):
        findings.append(
            Finding(
                detector="encoded.rot13",
                confidence=0.6,
                span=m.span(),
                snippet=m.group(0)[:60],
                reason="explicit [rot13] hint in text",
            )
        )
    return findings


# --------------------------------------------------------------------------- #
# Detector 2: Hidden / zero-width characters and homoglyphs
# --------------------------------------------------------------------------- #

_INVISIBLE_CODEPOINTS = {
    0x200B,  # zero-width space
    0x200C,  # zero-width non-joiner
    0x200D,  # zero-width joiner
    0x2060,  # word joiner
    0xFEFF,  # BOM / zero-width no-break space
    0x202E,  # right-to-left override
    0x202D,  # left-to-right override
    0x202A,  # left-to-right embedding
    0x202B,  # right-to-left embedding
    0x202C,  # pop directional formatting
}

# Cyrillic / Greek letters that visually mimic Latin ones (homoglyphs).
_HOMOGLYPH_RANGES = [(0x0400, 0x04FF), (0x0370, 0x03FF)]


def _is_homoglyph(ch: str) -> bool:
    cp = ord(ch)
    return any(lo <= cp <= hi for lo, hi in _HOMOGLYPH_RANGES)


def detect_hidden_chars(text: str) -> List[Finding]:
    findings: List[Finding] = []
    spans: list[tuple[int, int, str, str]] = []
    for i, ch in enumerate(text):
        cp = ord(ch)
        if cp in _INVISIBLE_CODEPOINTS:
            spans.append((i, i + 1, ch, f"invisible U+{cp:04X}"))
        elif ch not in "\n\t\r " and _is_homoglyph(ch):
            spans.append((i, i + 1, ch, f"homoglyph U+{cp:04X} ({unicodedata.name(ch, '?')})"))

    if not spans:
        return findings
    # Group consecutive invisibles into one finding.
    groups: list[list[tuple[int, int, str, str]]] = []
    for s in spans:
        if groups and s[0] == groups[-1][-1][1]:
            groups[-1].append(s)
        else:
            groups.append([s])
    for g in groups:
        start, end = g[0][0], g[-1][1]
        snippet = repr(text[start:end])
        conf = min(0.95, 0.5 + 0.1 * len(g))
        kind = g[0][3].split()[0]
        findings.append(
            Finding(
                detector=f"hidden.{kind}",
                confidence=conf,
                span=(start, end),
                snippet=snippet,
                reason=f"{len(g)} hidden/homoglyph char(s) clustered",
            )
        )
    return findings


# --------------------------------------------------------------------------- #
# Detector 3: Prompt-injection phrasing
# --------------------------------------------------------------------------- #

_INJECTION_PATTERNS: list[tuple[str, re.Pattern[str], float]] = [
    (
        "ignore_safety",
        re.compile(
            r"\b(ignore|disregard|forget|drop|override|bypass)\b[^.\n]{0,40}\b"
            r"(safety|guard|filter|rule|policy|instruction|system|previous|prior)\b",
            re.IGNORECASE,
        ),
        0.9,
    ),
    (
        "new_identity",
        re.compile(
            r"\b(you are now|act as|pretend to be|from now on you|switch to|"
            r"your new role|new persona|dan mode|jailbreak)\b",
            re.IGNORECASE,
        ),
        0.85,
    ),
    (
        "hidden_command",
        re.compile(
            r"<\s*(system|assistant|instruction|prompt)\s*>|###\s*(system|assistant|"
            r"instruction)\s*:|<<\s*SYS\s*>>|\[\s*INST\s*\]",
            re.IGNORECASE,
        ),
        0.9,
    ),
    (
        "exfiltrate",
        re.compile(
            r"\b(send|email|post|transmit|upload|leak|exfiltrate|forward)\b[^.\n]{0,40}"
            r"\b(secret|token|password|key|credential|api[_\s-]?key|conversation|history)\b",
            re.IGNORECASE,
        ),
        0.95,
    ),
]


def detect_prompt_injection(text: str) -> List[Finding]:
    findings: List[Finding] = []
    for name, pattern, conf in _INJECTION_PATTERNS:
        for m in pattern.finditer(text):
            findings.append(
                Finding(
                    detector=f"injection.{name}",
                    confidence=conf,
                    span=m.span(),
                    snippet=m.group(0),
                    reason=f"matched {name!r} pattern",
                )
            )
    return findings


# --------------------------------------------------------------------------- #
# Detector 4: Excessive entropy / gibberish
# --------------------------------------------------------------------------- #


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


_ENTROPY_RE = re.compile(r"\b[A-Za-z0-9_\-]{12,}\b")


def detect_high_entropy(text: str) -> List[Finding]:
    findings: List[Finding] = []
    for m in _ENTROPY_RE.finditer(text):
        token = m.group(0)
        ent = _shannon_entropy(token)
        # Normal English words top out around ~3.5 bits/char.
        # Generated API keys, hashes, and unscrambled base32 sit >3.8.
        # Pure hex (16 unique symbols) tops out at 4.0; we want to catch those.
        if ent > 3.7 and len(token) >= 16:
            conf = min(0.95, 0.5 + (ent - 4.2) * 0.4)
            findings.append(
                Finding(
                    detector="entropy.high",
                    confidence=conf,
                    span=m.span(),
                    snippet=token,
                    reason=f"shannon entropy {ent:.2f} bits/char over {len(token)} chars",
                )
            )
    return findings


# --------------------------------------------------------------------------- #
# Detector 5: Markdown / link smuggling
# --------------------------------------------------------------------------- #

# Markdown links whose visible text says one thing and the URL says another.
_MISLEADING_LINK_RE = re.compile(
    r"\[([^\]]+)\]\((https?://[^)\s]+)\)",
    re.IGNORECASE,
)


def detect_smuggled_links(text: str) -> List[Finding]:
    findings: List[Finding] = []
    for m in _MISLEADING_LINK_RE.finditer(text):
        label, url = m.group(1).strip(), m.group(2).strip()
        # The label looks like a real URL / domain, but the href points
        # at a different host.
        label_host = re.search(r"https?://([^/\s)]+)", label, re.IGNORECASE)
        url_host_m = re.search(r"https?://([^/\s)]+)", url, re.IGNORECASE)
        if not url_host_m:
            continue
        url_host = url_host_m.group(1).lower()
        is_shortener = any(
            url_host == d or url_host.endswith("." + d)
            for d in ("bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd")
        )
        # Case 1: label claims a different host than the href.
        if label_host and label_host.group(1).lower() != url_host:
            findings.append(
                Finding(
                    detector="link.misleading",
                    confidence=0.9,
                    span=m.span(),
                    snippet=m.group(0),
                    reason=(
                        f"label host '{label_host.group(1)}' != href host "
                        f"'{url_host}'"
                    ),
                )
            )
            continue
        # Case 2: href is a known shortener — common obfuscation regardless of label.
        if is_shortener:
            findings.append(
                Finding(
                    detector="link.shortener",
                    confidence=0.7,
                    span=m.span(),
                    snippet=m.group(0),
                    reason=f"href uses shortener {url_host}",
                )
            )
    return findings


# --------------------------------------------------------------------------- #
# Public registry
# --------------------------------------------------------------------------- #

ALL_DETECTORS = {
    "encoded": detect_encoded_payloads,
    "hidden": detect_hidden_chars,
    "injection": detect_prompt_injection,
    "entropy": detect_high_entropy,
    "links": detect_smuggled_links,
}
