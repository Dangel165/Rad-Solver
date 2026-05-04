from __future__ import annotations

import base64
import binascii
import json
import re

from ..models import Finding, Plugin, Target
from ..utils import find_flags, printable_ratio, shorten


class WebPlugin(Plugin):
    name = "web-static"
    category = "web"

    def analyze(self, target: Target, flag_patterns: list[str]) -> list[Finding]:
        text = target.text
        if not text:
            return []
        web_suffixes = {".html", ".htm", ".js", ".css", ".json", ".xml", ".txt", ".md", ".http"}
        is_webish = target.path and target.path.suffix.lower() in web_suffixes
        if not is_webish and printable_ratio(target.data[:8192]) < 0.85:
            return []
        findings: list[Finding] = []
        flags = find_flags(text, flag_patterns)
        for flag in flags:
            findings.append(
                Finding(
                    score=98.0,
                    title="flag in web/text content",
                    category=self.category,
                    detail=flag,
                    source=target.label,
                    value=flag,
                )
            )

        comments = re.findall(r"<!--(.*?)-->|/\*(.*?)\*/|//\s*(.+)", text, flags=re.DOTALL)
        flat_comments = ["".join(group).strip() for group in comments if "".join(group).strip()]
        if flat_comments:
            findings.append(
                Finding(
                    score=32.0,
                    title="comments",
                    category=self.category,
                    detail=shorten(" | ".join(flat_comments[:8])),
                    source=target.label,
                )
            )

        paths = sorted(set(re.findall(r"""["']((?:/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+)+)["']""", text)))
        if paths:
            findings.append(
                Finding(
                    score=24.0,
                    title="interesting paths",
                    category=self.category,
                    detail=shorten(", ".join(paths[:20])),
                    source=target.label,
                    metadata={"count": len(paths)},
                )
            )

        findings.extend(self._jwt_findings(text, target.label, flag_patterns))
        findings.extend(self._web_artifact_findings(text, target.label))
        findings.extend(self._encoded_string_findings(text, target.label, flag_patterns))
        findings.extend(self._payload_candidate_findings(text, target.label))

        for keyword in ("debug", "admin", "jwt", "session", "csrf", "sqli", "xss", "prototype", "deserialize", "union select", "or 1=1"):
            if keyword in text.lower() or (keyword == "xss" and "<script" in text.lower()):
                findings.append(
                    Finding(
                        score=18.0,
                        title=f"web keyword: {keyword}",
                        category=self.category,
                        detail=f"Keyword '{keyword}' appears in the content.",
                        source=target.label,
                    )
                )
        return findings

    def _payload_candidate_findings(self, text: str, source: str) -> list[Finding]:
        lowered = text.lower()
        findings: list[Finding] = []
        candidates: list[tuple[str, str, str]] = []
        if "union select" in lowered or "sqli" in lowered or "sql" in lowered:
            candidates.extend(
                [
                    ("SQLi payload candidate", "' OR '1'='1' -- ", "Login/auth bypass probe for CTF forms."),
                    ("SQLi payload candidate", "' UNION SELECT NULL,NULL-- ", "Column-count probing starter payload."),
                ]
            )
        if "<script" in lowered or "xss" in lowered:
            candidates.append(("XSS payload candidate", "<script>alert(1)</script>", "Basic reflected/stored XSS probe."))
        if "{{" in text or "ssti" in lowered or "template" in lowered:
            candidates.append(("SSTI payload candidate", "{{7*7}}", "Template injection arithmetic probe."))
        if "deserialize" in lowered or "pickle" in lowered or "unserialize" in lowered:
            candidates.append(("deserialization check candidate", "tamper serialized object / signed cookie", "Inspect serializer/signing boundary."))
        if "admin" in lowered and ("role" in lowered or "jwt" in lowered or "cookie" in lowered):
            candidates.append(("auth bypass candidate", "role=admin", "Try role/cookie/JWT claim tampering in authorized CTF lab."))

        seen = set()
        for title, value, detail in candidates:
            identity = (title, value)
            if identity in seen:
                continue
            seen.add(identity)
            findings.append(
                Finding(
                    score=50.0,
                    title=title,
                    category=self.category,
                    detail=detail,
                    source=source,
                    value=value,
                )
            )
        return findings

    def _encoded_string_findings(self, text: str, source: str, flag_patterns: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        string_values = re.findall(r"""["']([A-Za-z0-9+/=_-]{12,300})["']""", text)
        seen: set[str] = set()
        for value in string_values[:80]:
            if value in seen:
                continue
            seen.add(value)
            attempts = [
                ("base64 string", lambda s: base64.b64decode(s + "=" * (-len(s) % 4), validate=False)),
                ("urlsafe base64 string", lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))),
                ("hex string", lambda s: bytes.fromhex(s)),
            ]
            for title, decode in attempts:
                try:
                    decoded = decode(value)
                except (ValueError, binascii.Error):
                    continue
                decoded_text = decoded.decode("utf-8", errors="ignore")
                for flag in find_flags(decoded_text, flag_patterns):
                    findings.append(
                        Finding(
                            score=92.0,
                            title=f"decoded {title}",
                            category=self.category,
                            detail=flag,
                            source=source,
                            value=flag,
                            metadata={"encoded_prefix": value[:32]},
                        )
                    )
        return findings

    def _jwt_findings(self, text: str, source: str, flag_patterns: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        tokens = sorted(set(re.findall(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*(?=$|[^A-Za-z0-9_-])", text)))
        for token in tokens[:10]:
            parts = token.split(".")
            decoded_parts = []
            for part in parts[:2]:
                try:
                    raw = base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))
                    decoded_parts.append(json.loads(raw.decode("utf-8", errors="ignore")))
                except (ValueError, json.JSONDecodeError):
                    decoded_parts.append(raw.decode("utf-8", errors="ignore") if "raw" in locals() else "")
            findings.append(
                Finding(
                    score=40.0,
                    title="JWT token",
                    category=self.category,
                    detail=shorten(json.dumps(decoded_parts, ensure_ascii=False)),
                    source=source,
                    metadata={"token_prefix": token[:32]},
                )
            )
            decoded_text = json.dumps(decoded_parts, ensure_ascii=False)
            for flag in find_flags(decoded_text, flag_patterns):
                findings.append(
                    Finding(
                        score=96.0,
                        title="flag inside JWT",
                        category=self.category,
                        detail=flag,
                        source=source,
                        value=flag,
                    )
                )
            if any(isinstance(part, dict) and str(part.get("alg", "")).lower() == "none" for part in decoded_parts):
                findings.append(
                    Finding(
                        score=55.0,
                        title="JWT alg none hint",
                        category=self.category,
                        detail="JWT header uses alg=none.",
                        source=source,
                    )
                )
        return findings

    def _web_artifact_findings(self, text: str, source: str) -> list[Finding]:
        findings: list[Finding] = []
        lowered = text.lower()
        artifacts = {
            "robots.txt hint": ("user-agent:", "disallow:"),
            "source map hint": ("sourcemappingurl=", ".map"),
            "backup file hint": (".bak", ".old", "~", "backup"),
            "graphql hint": ("graphql", "__schema", "introspection"),
            "ssti hint": ("{{", "jinja", "template"),
        }
        for title, markers in artifacts.items():
            if any(marker in lowered for marker in markers):
                findings.append(
                    Finding(
                        score=30.0,
                        title=title,
                        category=self.category,
                        detail=f"Detected markers: {', '.join(marker for marker in markers if marker in lowered)}",
                        source=source,
                    )
                )
        return findings
