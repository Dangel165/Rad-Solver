from __future__ import annotations

import math
import re
import string
from pathlib import Path

from .models import PromptContext


DEFAULT_FLAG_PATTERNS = [
    r"(?i:\bflag\{[ -~]{1,200}\})",
    r"(?i:\bctf\{[ -~]{1,200}\})",
    r"\b[A-Z0-9_]{2,32}\{[A-Za-z0-9_@!#$%^&*()+\-=:;,.?/]{4,200}\}",
]

PRINTABLE = set(bytes(string.printable, "ascii"))


def compile_patterns(patterns: list[str]) -> list[re.Pattern[str]]:
    compiled = []
    for pattern in patterns:
        compiled.append(re.compile(pattern))
    return compiled


def find_flags(text: str, patterns: list[str]) -> list[str]:
    hits: list[str] = []
    for regex in compile_patterns(patterns):
        for match in regex.findall(text):
            value = match if isinstance(match, str) else match[0]
            if value not in hits:
                hits.append(value)
    return hits


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return sum(byte in PRINTABLE for byte in data) / len(data)


def looks_textual(data: bytes) -> bool:
    if not data:
        return False
    return printable_ratio(data) > 0.82


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in counts if count)


def extract_ascii_strings(data: bytes, min_len: int = 4) -> list[str]:
    results: list[str] = []
    current = bytearray()
    for byte in data:
        if 32 <= byte <= 126 or byte in (9, 10, 13):
            current.append(byte)
        else:
            if len(current) >= min_len:
                results.append(current.decode("ascii", errors="ignore"))
            current.clear()
    if len(current) >= min_len:
        results.append(current.decode("ascii", errors="ignore"))
    return results


def extract_utf16le_strings(data: bytes, min_len: int = 4) -> list[str]:
    results = _extract_utf16le_aligned(data, min_len, start_offset=0)
    for value in _extract_utf16le_aligned(data, min_len, start_offset=1):
        if value not in results:
            results.append(value)
    return results


def _extract_utf16le_aligned(data: bytes, min_len: int, start_offset: int) -> list[str]:
    results: list[str] = []
    current: list[int] = []
    for idx in range(start_offset, len(data) - 1, 2):
        code = data[idx] | (data[idx + 1] << 8)
        if 32 <= code <= 126 or code in (9, 10, 13):
            current.append(code)
        else:
            if len(current) >= min_len:
                results.append("".join(chr(codepoint) for codepoint in current))
            current.clear()
    if len(current) >= min_len:
        results.append("".join(chr(codepoint) for codepoint in current))
    return results


def read_targets(path_or_text: str) -> list[tuple[str, bytes, Path | None]]:
    path = Path(path_or_text)
    if path.exists():
        if path.is_dir():
            targets = []
            for child in sorted(p for p in path.rglob("*") if p.is_file()):
                try:
                    targets.append((str(child), child.read_bytes(), child))
                except OSError:
                    continue
            return targets
        return [(str(path), path.read_bytes(), path)]
    return [("stdin-text", path_or_text.encode("utf-8"), None)]


def parse_prompt_context(prompt: str) -> PromptContext:
    text = prompt.strip()
    lowered = text.lower()
    categories = {
        category
        for category in ("crypto", "forensics", "reversing", "pwn", "web", "misc", "osint")
        if category in lowered
    }
    aliases = {
        "암호": "crypto",
        "포렌식": "forensics",
        "리버싱": "reversing",
        "웹": "web",
        "바이너리": "reversing",
        "익스": "pwn",
    }
    for marker, category in aliases.items():
        if marker in lowered:
            categories.add(category)

    patterns = []
    for match in re.findall(r"(?:flag[-_ ]?format|flag|format|형식)\s*[:=]\s*([^\r\n]+)", text, flags=re.IGNORECASE):
        candidate = match.strip().strip("`'\"")
        if "{" in candidate and "}" in candidate and "\\" not in candidate:
            prefix = re.escape(candidate.split("{", 1)[0])
            patterns.append(prefix + r"\{[A-Za-z0-9_@!#$%^&*()+\-=:;,.?/]{1,200}\}")
        elif candidate:
            patterns.append(candidate)
    for prefix in re.findall(r"\b([A-Za-z0-9_]{2,32})\{", text):
        pattern = re.escape(prefix) + r"\{[A-Za-z0-9_@!#$%^&*()+\-=:;,.?/]{1,200}\}"
        if pattern not in patterns:
            patterns.append(pattern)

    stopwords = {
        "the",
        "and",
        "for",
        "with",
        "this",
        "that",
        "flag",
        "format",
        "problem",
        "challenge",
        "ctf",
        "문제",
        "플래그",
        "형식",
        "힌트",
        "분야",
    }
    keywords = {
        word.lower()
        for word in re.findall(r"[A-Za-z0-9_가-힣]{3,32}", text)
        if word.lower() not in stopwords
    }
    return PromptContext(raw=text, categories=categories, keywords=keywords, flag_patterns=patterns)


def shorten(value: str, limit: int = 220) -> str:
    clean = value.replace("\r", "\\r").replace("\n", "\\n")
    if len(clean) <= limit:
        return clean
    return clean[: limit - 3] + "..."
