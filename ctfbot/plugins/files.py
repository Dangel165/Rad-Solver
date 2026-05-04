from __future__ import annotations

import io
import struct
import zipfile
import zlib

from ..models import Finding, Plugin, Target
from ..utils import entropy, extract_ascii_strings, extract_utf16le_strings, find_flags, looks_textual, shorten


MAGICS = [
    (b"\x7fELF", "ELF executable"),
    (b"MZ", "PE executable"),
    (b"PK\x03\x04", "ZIP archive"),
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"%PDF", "PDF document"),
    (b"GIF8", "GIF image"),
    (b"7z\xbc\xaf\x27\x1c", "7z archive"),
    (b"Rar!\x1a\x07", "RAR archive"),
]


class FilePlugin(Plugin):
    name = "file-forensics"
    category = "forensics"

    def analyze(self, target: Target, flag_patterns: list[str]) -> list[Finding]:
        data = target.data
        findings: list[Finding] = []
        for magic, label in MAGICS:
            if data.startswith(magic):
                findings.append(
                    Finding(
                        score=25.0,
                        title="file type",
                        category=self.category,
                        detail=label,
                        source=target.label,
                    )
                )
                break

        findings.extend(self._embedded_signatures(target))

        ent = entropy(data)
        findings.append(
            Finding(
                score=8.0,
                title="entropy",
                category=self.category,
                detail=f"Shannon entropy: {ent:.2f} bits/byte",
                source=target.label,
                metadata={"entropy": round(ent, 3), "size": len(data)},
            )
        )

        strings = extract_ascii_strings(data) + extract_utf16le_strings(data)
        joined = "\n".join(strings)
        flags = find_flags(joined, flag_patterns)
        for flag in flags:
            findings.append(
                Finding(
                    score=96.0,
                    title="flag in strings",
                    category=self.category,
                    detail=flag,
                    source=target.label,
                    value=flag,
                )
                )

        if looks_textual(data[:8192]):
            findings.extend(self._text_file_findings(target, joined, flag_patterns))

        for marker in ("password", "passwd", "secret", "key=", "token", "hidden", "stego", "admin"):
            hits = [s for s in strings if marker in s.lower()]
            if hits:
                findings.append(
                    Finding(
                        score=35.0,
                        title=f"interesting string: {marker}",
                        category=self.category,
                        detail=shorten(" | ".join(hits[:5])),
                        source=target.label,
                    )
                )

        if data.startswith(b"\x89PNG\r\n\x1a\n"):
            findings.extend(self._png_chunk_findings(target, flag_patterns))

        if target.path and target.path.suffix.lower() in {".zip", ".png", ".jpg", ".jpeg", ".pdf"}:
            findings.append(
                Finding(
                    score=20.0,
                    title="forensics next step",
                    category=self.category,
                    detail="Try binwalk/exiftool/foremost/stegsolve equivalents if installed; embedded data or metadata may be present.",
                    source=target.label,
                )
            )
        zip_offsets = [offset for offset in self._magic_offsets(data, b"PK\x03\x04") if offset >= 0]
        for offset in zip_offsets[:5]:
            findings.extend(self._zip_findings(target, flag_patterns, offset=offset))
        return findings

    def _text_file_findings(self, target: Target, text: str, flag_patterns: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if lines and lines[0].startswith("#!"):
            findings.append(
                Finding(
                    score=30.0,
                    title="script/shebang file",
                    category=self.category,
                    detail=shorten(lines[0]),
                    source=target.label,
                    metadata={"interpreter": lines[0][2:]},
                )
            )
        for line in lines[:300]:
            lowered = line.lower()
            if any(marker in lowered for marker in ("flag", "secret", "token", "password", "api_key", "apikey")):
                for flag in find_flags(line, flag_patterns):
                    findings.append(
                        Finding(
                            score=98.0,
                            title="flag in text line",
                            category=self.category,
                            detail=shorten(line),
                            source=target.label,
                            value=flag,
                        )
                    )
                if "=" in line and len(line) <= 240:
                    key, value = line.split("=", 1)
                    clean_value = value.strip().strip("'\"")
                    if clean_value:
                        findings.append(
                            Finding(
                                score=42.0,
                                title="interesting key-value",
                                category=self.category,
                                detail=shorten(line),
                                source=target.label,
                                value=clean_value if any(marker in key.lower() for marker in ("flag", "secret", "token", "password")) else None,
                                metadata={"key": key.strip()},
                            )
                        )
        return findings

    def _png_chunk_findings(self, target: Target, flag_patterns: list[str]) -> list[Finding]:
        data = target.data
        findings: list[Finding] = []
        offset = 8
        while offset + 12 <= len(data):
            try:
                length = struct.unpack_from(">I", data, offset)[0]
            except struct.error:
                break
            chunk_type = data[offset + 4 : offset + 8]
            chunk_data = data[offset + 8 : offset + 8 + length]
            if offset + 12 + length > len(data):
                break
            name = chunk_type.decode("ascii", errors="ignore")
            if name in {"tEXt", "iTXt", "zTXt"}:
                text = self._decode_png_text(name, chunk_data)
                if text:
                    findings.append(
                        Finding(
                            score=44.0,
                            title="PNG text chunk",
                            category=self.category,
                            detail=shorten(text),
                            source=target.label,
                            metadata={"chunk": name, "offset": offset},
                        )
                    )
                    for flag in find_flags(text, flag_patterns):
                        findings.append(
                            Finding(
                                score=101.0,
                                title="flag inside PNG text chunk",
                                category=self.category,
                                detail=flag,
                                source=target.label,
                                value=flag,
                                metadata={"chunk": name, "offset": offset},
                            )
                        )
            offset += 12 + length
        if offset < len(data):
            tail = data[offset:]
            if tail.strip(b"\x00"):
                findings.append(
                    Finding(
                        score=34.0,
                        title="PNG trailing data",
                        category=self.category,
                        detail=f"{len(tail)} bytes after parsed PNG chunks.",
                        source=target.label,
                        metadata={"offset": offset, "length": len(tail)},
                    )
                )
        return findings

    def _decode_png_text(self, chunk_type: str, data: bytes) -> str:
        try:
            if chunk_type == "tEXt":
                return data.replace(b"\x00", b"=").decode("latin-1", errors="ignore")
            if chunk_type == "zTXt":
                key, rest = data.split(b"\x00", 1)
                if rest and rest[0] == 0:
                    return key.decode("latin-1", errors="ignore") + "=" + zlib.decompress(rest[1:]).decode("utf-8", errors="ignore")
            if chunk_type == "iTXt":
                parts = data.split(b"\x00", 5)
                if len(parts) == 6:
                    key, compression_flag, _compression_method, _lang, _translated, payload = parts
                    if compression_flag == b"\x01":
                        payload = zlib.decompress(payload)
                    return key.decode("utf-8", errors="ignore") + "=" + payload.decode("utf-8", errors="ignore")
        except (ValueError, OSError, zlib.error):
            return ""
        return ""

    def _embedded_signatures(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        for magic, label in MAGICS:
            offset = target.data.find(magic, 1)
            if offset > 0:
                findings.append(
                    Finding(
                        score=38.0,
                        title="embedded file signature",
                        category=self.category,
                        detail=f"{label} signature at offset {offset}",
                        source=target.label,
                        metadata={"offset": offset, "type": label},
                    )
                )
        return findings

    def _magic_offsets(self, data: bytes, magic: bytes) -> list[int]:
        offsets: list[int] = []
        start = 0
        while True:
            offset = data.find(magic, start)
            if offset < 0:
                return offsets
            offsets.append(offset)
            start = offset + 1

    def _zip_findings(self, target: Target, flag_patterns: list[str], offset: int = 0) -> list[Finding]:
        findings: list[Finding] = []
        try:
            with zipfile.ZipFile(io.BytesIO(target.data[offset:])) as archive:
                names = archive.namelist()
                findings.append(
                    Finding(
                        score=36.0 if offset else 32.0,
                        title="embedded zip entries" if offset else "zip entries",
                        category=self.category,
                        detail=shorten(", ".join(names[:20])),
                        source=target.label,
                        metadata={"count": len(names), "offset": offset},
                    )
                )
                for info in archive.infolist()[:50]:
                    if info.file_size > 1024 * 1024:
                        continue
                    content = archive.read(info)
                    text = "\n".join(extract_ascii_strings(content) + extract_utf16le_strings(content))
                    for flag in find_flags(text, flag_patterns):
                        findings.append(
                            Finding(
                                score=99.0,
                                title="flag inside embedded zip entry" if offset else "flag inside zip entry",
                                category=self.category,
                                detail=f"{info.filename}: {flag}",
                                source=target.label,
                                value=flag,
                                metadata={"entry": info.filename, "offset": offset},
                            )
                        )
                    if content.startswith(b"PK\x03\x04"):
                        nested_target = Target(f"{target.label}!{info.filename}", content, None)
                        for nested in self._zip_findings(nested_target, flag_patterns, offset=0):
                            nested.score += 4.0
                            nested.metadata["container_entry"] = info.filename
                            findings.append(nested)
        except (OSError, ValueError, zipfile.BadZipFile, RuntimeError):
            findings.append(
                Finding(
                    score=18.0,
                    title="zip parse failed",
                    category=self.category,
                    detail=f"ZIP header at offset {offset} exists but archive could not be read. It may be encrypted, damaged, or intentionally malformed.",
                    source=target.label,
                    metadata={"offset": offset},
                )
            )
        return findings
