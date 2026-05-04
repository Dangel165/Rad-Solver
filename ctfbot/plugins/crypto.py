from __future__ import annotations

import base64
import binascii
import hashlib
import math
import re
import urllib.parse

from ..models import Finding, Plugin, Target
from ..utils import find_flags, looks_textual, printable_ratio, shorten


GENERIC_PREFIX_RE = re.compile(r"^[A-Z0-9_]{2,32}\{")


def is_high_confidence_flag(value: str, flag_patterns: list[str]) -> bool:
    lowered = value.lower()
    if lowered.startswith(("flag{", "ctf{")):
        return True
    prefix = value.split("{", 1)[0]
    if not prefix or GENERIC_PREFIX_RE.fullmatch(prefix + "{"):
        escaped_prefix = re.escape(prefix)
        return any(escaped_prefix in pattern and "[A-Z0-9_]" not in pattern for pattern in flag_patterns)
    return True


class CryptoPlugin(Plugin):
    name = "crypto-codec"
    category = "crypto"

    def analyze(self, target: Target, flag_patterns: list[str]) -> list[Finding]:
        text = target.text.strip()
        findings: list[Finding] = []
        if not text:
            return findings
        binary_like = bool(target.path and not looks_textual(target.data[:8192]))
        if binary_like:
            return self._xor_candidates(target.data, flag_patterns, target.label)
            return findings

        candidates = self._decode_candidates(text)
        for label, decoded in candidates:
            decoded_text = decoded.decode("utf-8", errors="ignore")
            flags = find_flags(decoded_text, flag_patterns)
            textual = looks_textual(decoded)
            if not flags and not textual:
                continue
            score = 45.0 if textual else 20.0
            if flags:
                score += 45.0
            findings.append(
                Finding(
                    score=score,
                    title=f"{label} decode",
                    category=self.category,
                    detail=shorten(decoded_text),
                    source=target.label,
                    value=flags[0] if flags else None,
                    metadata={"flags": flags},
                )
            )

        findings.extend(self._rot_candidates(text, flag_patterns, target.label))
        findings.extend(self._xor_candidates(target.data, flag_patterns, target.label))
        findings.extend(self._recursive_decode_findings(text, flag_patterns, target.label))
        findings.extend(self._rsa_toy_findings(text, flag_patterns, target.label))
        findings.extend(self._hash_hints(text, target.label))
        return findings

    def _decode_candidates(self, text: str) -> list[tuple[str, bytes]]:
        compact = re.sub(r"\s+", "", text)
        results: list[tuple[str, bytes]] = []
        attempts = [
            ("hex", compact, lambda s: bytes.fromhex(s)),
            ("base64", compact, lambda s: base64.b64decode(s + "=" * (-len(s) % 4), validate=False)),
            ("base32", compact, lambda s: base64.b32decode(s + "=" * (-len(s) % 8), casefold=True)),
            ("base85", compact, lambda s: base64.b85decode(s)),
            ("ascii85", compact, lambda s: base64.a85decode(s)),
            ("url", text, lambda s: urllib.parse.unquote_to_bytes(s)),
        ]
        for label, candidate, fn in attempts:
            try:
                decoded = fn(candidate)
            except (ValueError, binascii.Error, UnicodeEncodeError):
                continue
            if decoded and decoded != text.encode("utf-8", errors="ignore"):
                if len(decoded) > 8 and printable_ratio(decoded) < 0.45:
                    continue
                results.append((label, decoded))
        return results

    def _recursive_decode_findings(self, text: str, flag_patterns: list[str], source: str) -> list[Finding]:
        findings: list[Finding] = []
        queue: list[tuple[str, str, list[str]]] = [(text, text, [])]
        seen = {text}
        while queue and len(seen) < 80:
            current_text, _original, chain = queue.pop(0)
            if len(chain) >= 4:
                continue
            for label, decoded in self._decode_candidates(current_text):
                decoded_text = decoded.decode("utf-8", errors="ignore").strip()
                if not decoded_text or decoded_text in seen:
                    continue
                seen.add(decoded_text)
                next_chain = chain + [label]
                flags = find_flags(decoded_text, flag_patterns)
                if flags:
                    findings.append(
                        Finding(
                            score=104.0 - len(next_chain),
                            title="recursive decode flag",
                            category=self.category,
                            detail=f"{' -> '.join(next_chain)}: {shorten(decoded_text)}",
                            source=source,
                            value=flags[0],
                            metadata={"chain": next_chain, "flags": flags},
                        )
                    )
                if looks_textual(decoded) and len(decoded_text) <= 5000:
                    queue.append((decoded_text, text, next_chain))
        return findings

    def _rsa_toy_findings(self, text: str, flag_patterns: list[str], source: str) -> list[Finding]:
        values = {
            key.lower(): int(value)
            for key, value in re.findall(r"\b([nec])\s*=\s*(\d+)\b", text, flags=re.IGNORECASE)
        }
        if not {"n", "e", "c"} <= set(values):
            return []
        n, e, c = values["n"], values["e"], values["c"]
        if n <= 1 or n > 10**14:
            return [
                Finding(
                    score=24.0,
                    title="RSA parameters",
                    category=self.category,
                    detail="Found n/e/c, but n is too large for the built-in toy RSA factorer.",
                    source=source,
                    metadata={"n_digits": len(str(n)), "e": e},
                )
            ]
        factor = self._small_factor(n)
        if not factor:
            return [
                Finding(
                    score=28.0,
                    title="RSA parameters",
                    category=self.category,
                    detail="Found n/e/c, but no small factor was found.",
                    source=source,
                    metadata={"n": n, "e": e},
                )
            ]
        p, q = factor, n // factor
        phi = (p - 1) * (q - 1)
        try:
            d = pow(e, -1, phi)
        except ValueError:
            return []
        m = pow(c, d, n)
        decoded = m.to_bytes(max(1, (m.bit_length() + 7) // 8), "big")
        decoded_text = decoded.decode("utf-8", errors="ignore")
        flags = find_flags(decoded_text, flag_patterns)
        return [
            Finding(
                score=108.0 if flags else 76.0,
                title="toy RSA decrypt",
                category=self.category,
                detail=shorten(decoded_text),
                source=source,
                value=flags[0] if flags else decoded_text,
                metadata={"p": p, "q": q, "e": e, "flags": flags},
            )
        ]

    def _small_factor(self, n: int) -> int | None:
        if n % 2 == 0:
            return 2
        limit = min(math.isqrt(n), 10_000_000)
        factor = 3
        while factor <= limit:
            if n % factor == 0:
                return factor
            factor += 2
        return None

    def _rot_candidates(self, text: str, flag_patterns: list[str], source: str) -> list[Finding]:
        if len(text) > 5000:
            return []
        out: list[Finding] = []
        alphabet = "abcdefghijklmnopqrstuvwxyz"
        for shift in range(1, 26):
            trans = str.maketrans(
                alphabet + alphabet.upper(),
                alphabet[shift:] + alphabet[:shift] + alphabet[shift:].upper() + alphabet[:shift].upper(),
            )
            decoded = text.translate(trans)
            flags = find_flags(decoded, flag_patterns)
            common = any(word in decoded.lower() for word in ("flag", "ctf", "password", "secret"))
            strong_flag = any(is_high_confidence_flag(flag, flag_patterns) for flag in flags)
            if strong_flag or common:
                value = next((flag for flag in flags if is_high_confidence_flag(flag, flag_patterns)), None)
                out.append(
                    Finding(
                        score=70.0 if strong_flag else 30.0,
                        title=f"ROT{shift} candidate",
                        category=self.category,
                        detail=shorten(decoded),
                        source=source,
                        value=value,
                        metadata={"shift": shift, "flags": flags},
                    )
                )
        return out

    def _xor_candidates(self, data: bytes, flag_patterns: list[str], source: str) -> list[Finding]:
        if not data or len(data) > 20000:
            return []
        out: list[Finding] = []
        chunks = [(0, data)]
        chunks.extend((offset, chunk) for offset, chunk in self._nonzero_chunks(data) if chunk != data)
        seen: set[tuple[int, str]] = set()
        for offset, chunk in chunks:
            out.extend(self._xor_chunk_candidates(chunk, flag_patterns, source, offset, seen))
        return out[:20]

    def _nonzero_chunks(self, data: bytes) -> list[tuple[int, bytes]]:
        chunks: list[tuple[int, bytes]] = []
        start: int | None = None
        for idx, byte in enumerate(data):
            if byte != 0:
                if start is None:
                    start = idx
            elif start is not None:
                if idx - start >= 6:
                    chunks.append((start, data[start:idx]))
                start = None
        if start is not None and len(data) - start >= 6:
            chunks.append((start, data[start:]))
        return chunks

    def _xor_chunk_candidates(
        self,
        data: bytes,
        flag_patterns: list[str],
        source: str,
        offset: int,
        seen: set[tuple[int, str]],
    ) -> list[Finding]:
        out: list[Finding] = []
        for key in range(1, 256):
            decoded = bytes(byte ^ key for byte in data)
            if not looks_textual(decoded):
                continue
            text = decoded.decode("utf-8", errors="ignore")
            flags = find_flags(text, flag_patterns)
            strong_flag = any(is_high_confidence_flag(flag, flag_patterns) for flag in flags)
            if strong_flag or "flag{" in text.lower() or "ctf{" in text.lower():
                value = next((flag for flag in flags if is_high_confidence_flag(flag, flag_patterns)), None)
                identity = (key, value or text)
                if identity in seen:
                    continue
                seen.add(identity)
                out.append(
                    Finding(
                        score=82.0 if strong_flag else 42.0,
                        title="single-byte XOR candidate",
                        category=self.category,
                        detail=shorten(text),
                        source=source,
                        value=value,
                        metadata={"key_hex": hex(key), "offset": offset, "flags": flags},
                    )
                )
        return out

    def _hash_hints(self, text: str, source: str) -> list[Finding]:
        stripped = text.strip().lower()
        lengths = {32: "MD5/NTLM-like", 40: "SHA1-like", 64: "SHA256-like", 96: "SHA384-like", 128: "SHA512-like"}
        if len(stripped) in lengths and re.fullmatch(r"[0-9a-f]+", stripped):
            digest = hashlib.sha256(stripped.encode()).hexdigest()[:12]
            return [
                Finding(
                    score=18.0,
                    title="hash-shaped value",
                    category=self.category,
                    detail=f"Looks like {lengths[len(stripped)]}. Offline cracking/dictionary lookup may be needed.",
                    source=source,
                    metadata={"fingerprint": digest},
                )
            ]
        return []
