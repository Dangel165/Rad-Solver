from __future__ import annotations

import hashlib
import math
import struct

from ..models import Finding, Plugin, Target
from ..utils import extract_ascii_strings, extract_utf16le_strings, find_flags, looks_textual, shorten


DANGEROUS_FUNCS = [
    "gets",
    "strcpy",
    "strcat",
    "sprintf",
    "scanf",
    "system",
    "execve",
    "WinExec",
    "CreateProcess",
]

PACKER_HINTS = ["UPX!", "UPX0", "UPX1", ".packed", "Themida", "VMProtect"]
PWN_MARKERS = ["ret2win", "ROP", "pop rdi", "/bin/sh", "setuid", "mprotect", "mmap"]
FORMAT_MARKERS = ["%p", "%x", "%n", "%s%s", "printf(user", "printf(buf"]


class ReversingPlugin(Plugin):
    name = "reversing-hints"
    category = "reversing"

    def analyze(self, target: Target, flag_patterns: list[str]) -> list[Finding]:
        strings = extract_ascii_strings(target.data) + extract_utf16le_strings(target.data)
        blob = "\n".join(strings)
        findings: list[Finding] = []

        for hint in PACKER_HINTS:
            if hint.lower() in blob.lower():
                findings.append(
                    Finding(
                        score=40.0,
                        title="packer hint",
                        category=self.category,
                        detail=f"Found {hint}; unpacking may be required.",
                        source=target.label,
                    )
                )

        found_funcs = [func for func in DANGEROUS_FUNCS if func.lower() in blob.lower()]
        if found_funcs:
            findings.append(
                Finding(
                    score=34.0,
                    title="pwn/reversing API hints",
                    category=self.category,
                    detail=", ".join(found_funcs),
                    source=target.label,
                    metadata={"functions": found_funcs},
                )
            )
            if target.data.startswith(b"\x7fELF") or any(func in found_funcs for func in ("gets", "strcpy", "scanf", "system")):
                findings.append(
                    Finding(
                        score=46.0,
                        title="pwn dangerous functions",
                        category="pwn",
                        detail=", ".join(found_funcs),
                        source=target.label,
                        metadata={"functions": found_funcs},
                    )
                )

        pwn_hits = [marker for marker in PWN_MARKERS if marker.lower() in blob.lower()]
        if pwn_hits:
            findings.append(
                Finding(
                    score=42.0,
                    title="pwn exploitation hints",
                    category="pwn",
                    detail=", ".join(pwn_hits),
                    source=target.label,
                    metadata={"markers": pwn_hits},
                )
            )
            for marker in pwn_hits:
                value = marker
                if marker == "/bin/sh" and "system" in blob:
                    value = "system('/bin/sh')"
                findings.append(
                    Finding(
                        score=58.0,
                        title="pwn target candidate",
                        category="pwn",
                        detail=f"Potential exploit target: {value}",
                        source=target.label,
                        value=value,
                        metadata={"marker": marker},
                    )
                )

        fmt_hits = [marker for marker in FORMAT_MARKERS if marker.lower() in blob.lower()]
        if fmt_hits:
            findings.append(
                Finding(
                    score=44.0,
                    title="format string hints",
                    category="pwn",
                    detail=", ".join(fmt_hits),
                    source=target.label,
                    metadata={"markers": fmt_hits},
                )
            )
            findings.append(
                Finding(
                    score=56.0,
                    title="format string payload candidate",
                    category="pwn",
                    detail="Starter payload to leak stack values in a CTF service.",
                    source=target.label,
                    value="%p.%p.%p.%p.%p",
                    metadata={"markers": fmt_hits},
                )
            )

        prompts = [s for s in strings if any(word in s.lower() for word in ("enter", "correct", "wrong", "license", "serial", "password"))]
        if prompts:
            findings.append(
                Finding(
                    score=28.0,
                    title="program prompt strings",
                    category=self.category,
                    detail=shorten(" | ".join(prompts[:8])),
                    source=target.label,
                )
            )
        findings.extend(self._credential_string_findings(strings, target.label))

        if target.data.startswith(b"\x7fELF"):
            findings.append(
                Finding(
                    score=22.0,
                    title="ELF binary",
                    category="pwn",
                    detail="Run checksec/gdb/radare2 locally for NX/PIE/RELRO/canary and control-flow analysis.",
                    source=target.label,
                )
            )
            findings.extend(self._elf_static_findings(target, flag_patterns, blob))
            findings.extend(self._hex_generated_flag_findings(target, flag_patterns))
            findings.extend(self._stack_printf_transform_findings(target))
            findings.extend(self._cyclic_bit_inverse_findings(target))
            findings.extend(self._indexed_xor_affine_table_findings(target, flag_patterns, blob))
            findings.extend(self._nibble_swap_table_findings(target, flag_patterns, blob))
        elif target.data.startswith(b"MZ"):
            findings.append(
                Finding(
                    score=22.0,
                    title="PE binary",
                    category="reversing",
                    detail="Windows PE detected; inspect imports, resources, and strings in a disassembler.",
                    source=target.label,
                )
            )
            findings.extend(self._pe_static_findings(target, flag_patterns, blob))
            findings.extend(self._hex_generated_flag_findings(target, flag_patterns))
            findings.extend(self._cyclic_bit_inverse_findings(target))
            findings.extend(self._indexed_xor_affine_table_findings(target, flag_patterns, blob))
            findings.extend(self._nibble_swap_table_findings(target, flag_patterns, blob))
        return findings

    def _nibble_swap_table_findings(
        self,
        target: Target,
        flag_patterns: list[str],
        string_blob: str,
    ) -> list[Finding]:
        if "%256s" not in string_blob and "Correct" not in string_blob:
            return []
        data = target.data
        code_has_pattern = b"\xc1\xf8\x04" in data and b"\xc1\xe1\x04" in data and b"\x81\xe1\xf0\x00\x00\x00" in data
        if not code_has_pattern:
            return []
        prefixes = self._flag_prefixes_from_patterns(flag_patterns)
        referenced_offsets = self._rip_relative_raw_targets(data)
        findings: list[Finding] = []
        seen: set[str] = set()
        for offset, run in self._nonzero_runs(data, min_len=8, max_len=96):
            if referenced_offsets and offset not in referenced_offsets:
                continue
            for length in range(min(64, len(run)), 7, -1):
                encoded = run[:length]
                decoded = bytes(((byte & 0x0F) << 4) | (byte >> 4) for byte in encoded)
                text_bytes = decoded[:-1] if decoded.endswith(b"\x00") else decoded
                if not self._looks_ctf_plaintext(text_bytes):
                    continue
                text = text_bytes.decode("ascii", errors="ignore")
                for prefix in prefixes:
                    value = f"{prefix}{{{text}}}"
                    if value in seen:
                        continue
                    seen.add(value)
                    findings.append(
                        Finding(
                            score=140.0,
                            title="nibble-swap table flag candidate",
                            category=self.category,
                            detail=f"Decoded nibble-swap comparison table at raw offset 0x{offset:x}.",
                            source=target.label,
                            value=value,
                            metadata={"table_offset": offset, "length": length, "decoded": text},
                        )
                    )
                break
        return sorted(findings, reverse=True)[:6]

    def _indexed_xor_affine_table_findings(
        self,
        target: Target,
        flag_patterns: list[str],
        string_blob: str,
    ) -> list[Finding]:
        if "%256s" not in string_blob and "Correct" not in string_blob:
            return []
        data = target.data
        prefixes = self._flag_prefixes_from_patterns(flag_patterns)
        findings: list[Finding] = []
        seen: set[str] = set()
        referenced_offsets = self._rip_relative_raw_targets(data)
        for offset, run in self._nonzero_runs(data, min_len=8, max_len=96):
            if referenced_offsets and offset not in referenced_offsets:
                continue
            for length in range(min(64, len(run)), 7, -1):
                encoded = run[:length]
                for add_mul in range(0, 5):
                    for xor_mul in range(0, 5):
                        if add_mul == 0 and xor_mul == 0:
                            continue
                        decoded = bytes(((byte - add_mul * idx) & 0xFF) ^ ((xor_mul * idx) & 0xFF) for idx, byte in enumerate(encoded))
                        text_bytes = decoded[:-1] if decoded.endswith(b"\x00") else decoded
                        if not self._looks_ctf_plaintext(text_bytes):
                            continue
                        text = text_bytes.decode("ascii", errors="ignore")
                        for prefix in prefixes:
                            value = f"{prefix}{{{text}}}"
                            if value in seen:
                                continue
                            seen.add(value)
                            findings.append(
                                Finding(
                                    score=136.0,
                                    title="indexed xor/add table flag candidate",
                                    category=self.category,
                                    detail=(
                                        f"Decoded byte table at raw offset 0x{offset:x}: "
                                        f"plain[i] = (table[i] - {add_mul}*i) ^ ({xor_mul}*i)."
                                    ),
                                    source=target.label,
                                    value=value,
                                    metadata={
                                        "table_offset": offset,
                                        "length": length,
                                        "add_multiplier": add_mul,
                                        "xor_multiplier": xor_mul,
                                        "decoded": text,
                                    },
                                )
                            )
                        if findings:
                            break
                    if findings:
                        break
                if findings:
                    break
        return sorted(findings, reverse=True)[:8]

    def _rip_relative_raw_targets(self, data: bytes) -> set[int]:
        if data.startswith(b"MZ"):
            return self._pe_rip_relative_raw_targets(data)
        return self._rip_relative_targets(data)

    def _pe_rip_relative_raw_targets(self, data: bytes) -> set[int]:
        sections = self._pe_sections(data)
        text = next((section for section in sections if section["name"] == ".text"), None)
        if not text or len(data) < 0x40:
            return set()
        try:
            pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
            image_base = struct.unpack_from("<Q", data, pe_offset + 24 + 24)[0]
        except (struct.error, ValueError):
            return set()
        raw = data[int(text["raw_ptr"]) : int(text["raw_ptr"]) + int(text["raw_size"])]
        va_base = image_base + int(text["virtual_address"])
        targets: set[int] = set()
        for idx in range(len(raw) - 7):
            if raw[idx : idx + 3] not in (b"\x48\x8d\x05", b"\x48\x8d\x0d", b"\x48\x8d\x15"):
                continue
            disp = struct.unpack_from("<i", raw, idx + 3)[0]
            target_va = va_base + idx + 7 + disp
            target_raw = self._pe_va_to_raw(data, sections, image_base, target_va)
            if target_raw is not None:
                targets.add(target_raw)
        return targets

    def _pe_va_to_raw(self, data: bytes, sections: list[dict[str, int | str]], image_base: int, va: int) -> int | None:
        rva = va - image_base
        for section in sections:
            start = int(section["virtual_address"])
            size = max(int(section["virtual_size"]), int(section["raw_size"]))
            if start <= rva < start + size:
                raw = int(section["raw_ptr"]) + (rva - start)
                if 0 <= raw < len(data):
                    return raw
        return None

    def _nonzero_runs(self, data: bytes, min_len: int, max_len: int) -> list[tuple[int, bytes]]:
        runs = []
        idx = 0
        while idx < len(data):
            while idx < len(data) and data[idx] == 0:
                idx += 1
            start = idx
            while idx < len(data) and data[idx] != 0 and idx - start < max_len:
                idx += 1
            run = data[start:idx]
            if len(run) >= min_len:
                runs.append((start, run))
            while idx < len(data) and data[idx] != 0:
                idx += 1
        return runs

    def _looks_ctf_plaintext(self, value: bytes) -> bool:
        if not (8 <= len(value) <= 64):
            return False
        if not all(32 <= byte <= 126 for byte in value):
            return False
        text = value.decode("ascii", errors="ignore")
        if " " in text or "This program" in text:
            return False
        useful = sum(char.isalnum() or char == "_" for char in text)
        return useful / len(text) > 0.85 and ("_" in text or any(char.isdigit() for char in text))

    def _cyclic_bit_inverse_findings(self, target: Target) -> list[Finding]:
        data = target.data
        if b"%64s" not in data and b"Correct! Flag is" not in data:
            return []
        wrappers = []
        for fmt_offset in self._find_all(data, b"%s"):
            prefix = self._nearby_flag_prefix(data, fmt_offset)
            suffix = self._nearby_suffix(data, fmt_offset)
            if prefix:
                wrappers.append((fmt_offset, prefix, suffix))
        if not wrappers:
            return []

        modulus = (1 << 256) - 1
        findings: list[Finding] = []
        seen_values: set[str] = set()
        referenced_offsets = self._rip_relative_targets(data)
        for table_offset, words in self._binary_u32_tables(data, 256):
            constant = sum((word & 1) << idx for idx, word in enumerate(words))
            if constant in (0, 1) or math.gcd(constant, modulus) != 1:
                continue
            inverse = pow(constant, -1, modulus)
            candidate_hex = "".join(f"{(inverse >> (4 * idx)) & 0xF:x}" for idx in range(64))
            for fmt_offset, prefix, suffix in wrappers:
                value = prefix + candidate_hex + suffix
                if value in seen_values:
                    continue
                seen_values.add(value)
                findings.append(
                    Finding(
                        score=176.0 if table_offset in referenced_offsets else 146.0,
                        title="cyclic bit inverse flag candidate",
                        category=self.category,
                        detail=(
                            f"Solved 256-bit cyclic bit convolution table at raw offset 0x{table_offset:x} "
                            "as modular inverse modulo 2^256-1."
                        ),
                        source=target.label,
                        value=value,
                        metadata={
                            "format_offset": fmt_offset,
                            "table_offset": table_offset,
                            "rip_relative_reference": table_offset in referenced_offsets,
                            "modulus": "2^256-1",
                            "constant_hex_big": f"{constant:064x}",
                            "inverse_hex_little_nibbles": candidate_hex,
                        },
                    )
                )
        return sorted(findings, reverse=True)[:5]

    def _rip_relative_targets(self, data: bytes) -> set[int]:
        targets: set[int] = set()
        for idx in range(len(data) - 7):
            if data[idx : idx + 3] not in (b"\x48\x8d\x05", b"\x48\x8d\x15", b"\x48\x8d\x0d"):
                continue
            disp = struct.unpack_from("<i", data, idx + 3)[0]
            target = idx + 7 + disp
            if 0 <= target < len(data):
                targets.add(target)
        return targets

    def _binary_u32_tables(self, data: bytes, count: int) -> list[tuple[int, list[int]]]:
        tables: list[tuple[int, list[int]]] = []
        table_size = count * 4
        idx = 0
        while idx + table_size <= len(data):
            words = []
            for word_idx in range(count):
                value = struct.unpack_from("<I", data, idx + word_idx * 4)[0]
                if value not in (0, 1):
                    break
                words.append(value)
            if len(words) == count:
                ones = sum(words)
                if 8 <= ones <= count - 8:
                    tables.append((idx, words))
                    idx += 4
                    continue
            idx += 4
        return tables

    def _stack_printf_transform_findings(self, target: Target) -> list[Finding]:
        data = target.data
        fmt_offsets = self._find_all(data, b"%s")
        wrappers = []
        for fmt_offset in fmt_offsets:
            prefix = self._nearby_flag_prefix(data, fmt_offset)
            suffix = self._nearby_suffix(data, fmt_offset)
            if prefix:
                wrappers.append((fmt_offset, prefix, suffix))
        if not wrappers:
            return []

        sections = self._elf_sections(data) if data.startswith(b"\x7fELF") else self._pe_sections(data)
        text = next((section for section in sections if section["name"] == ".text"), None)
        if not text:
            return []
        if "offset" in text:
            raw_base = int(text["offset"])
            raw = data[raw_base : raw_base + int(text["size"])]
        else:
            raw_base = int(text["raw_ptr"])
            raw = data[raw_base : raw_base + int(text["raw_size"])]

        groups = self._stack_immediate_groups(raw, raw_base)
        findings: list[Finding] = []
        seen: set[str] = set()
        for fmt_offset, prefix, suffix in wrappers:
            for idx in range(len(groups)):
                first_offset, first_encoded = groups[idx]
                first_decoded = self._digit_rotate_decodes(first_encoded)
                for key, decoded in first_decoded:
                    if 24 <= len(decoded) <= 96 and self._looks_hex_bytes(decoded):
                        value = prefix + decoded.decode("ascii") + suffix
                        if value not in seen:
                            seen.add(value)
                            findings.append(
                                Finding(
                                    score=104.0,
                                    title="stack transform printf flag candidate",
                                    category=self.category,
                                    detail=f"Decoded stack immediate block at raw offset 0x{first_offset:x} with rotate key {key}.",
                                    source=target.label,
                                    value=value,
                                    metadata={"format_offset": fmt_offset, "block_offset": first_offset, "rotate_key": key},
                                )
                            )
                if idx + 1 >= len(groups):
                    continue
                second_offset, second_encoded = groups[idx + 1]
                for first_key, first_plain in first_decoded:
                    for second_key, second_plain in self._digit_rotate_decodes(second_encoded):
                        decoded = first_plain + second_plain
                        if not (32 <= len(decoded) <= 128 and self._looks_hex_bytes(decoded)):
                            continue
                        value = prefix + decoded.decode("ascii") + suffix
                        if value in seen:
                            continue
                        seen.add(value)
                        findings.append(
                            Finding(
                                score=132.0,
                                title="stack transform printf flag candidate (combined blocks)",
                                category=self.category,
                                detail=(
                                    f"Decoded adjacent stack immediate blocks at raw offsets "
                                    f"0x{first_offset:x} and 0x{second_offset:x} with rotate keys {first_key}, {second_key}."
                                ),
                                source=target.label,
                                value=value,
                                metadata={
                                    "format_offset": fmt_offset,
                                    "block_offsets": [first_offset, second_offset],
                                    "rotate_keys": [first_key, second_key],
                                },
                            )
                        )
        return sorted(findings, reverse=True)[:8]

    def _stack_immediate_groups(self, code: bytes, raw_base: int) -> list[tuple[int, bytes]]:
        events: list[tuple[int, bytes]] = []
        idx = 0
        while idx < len(code):
            if idx + 10 <= len(code) and code[idx : idx + 2] in (b"\x48\xb8", b"\x48\xba"):
                events.append((raw_base + idx, code[idx + 2 : idx + 10]))
                idx += 10
                continue
            if code[idx : idx + 2] == b"\xc7\x45" and idx + 7 <= len(code):
                stack_disp = struct.unpack("b", code[idx + 2 : idx + 3])[0]
                if stack_disp <= -0x10:
                    events.append((raw_base + idx, code[idx + 3 : idx + 7]))
                idx += 7
                continue
            idx += 1

        groups: list[tuple[int, bytes]] = []
        current_offset: int | None = None
        current = bytearray()
        last_offset: int | None = None
        for offset, value in events:
            if current and last_offset is not None and offset - last_offset > 40:
                if len(current) >= 16:
                    groups.append((int(current_offset), bytes(current)))
                current = bytearray()
                current_offset = None
            if current_offset is None:
                current_offset = offset
            current.extend(value)
            last_offset = offset
        if current and len(current) >= 16 and current_offset is not None:
            groups.append((current_offset, bytes(current)))
        return groups

    def _digit_rotate_decodes(self, encoded: bytes) -> list[tuple[int, bytes]]:
        decodes = []
        for key in range(1, 8):
            decoded = bytes(self._digit_rotate_byte(byte, key) for byte in encoded)
            printable = sum(32 <= byte <= 126 for byte in decoded)
            if printable / max(1, len(decoded)) >= 0.75:
                decodes.append((key, decoded))
        return decodes

    def _digit_rotate_byte(self, byte: int, key: int) -> int:
        if 0x30 <= byte <= 0x39:
            value = (byte * 8) % 10
            if 7 < value <= 9:
                value += 0x28
            else:
                value += 0x32
            return value & 0xFF
        signed = byte if byte < 0x80 else byte - 0x100
        value = signed & 0xFFFFFFFF
        rotated = ((value >> key) | (value << (8 - key))) & 0xFFFFFFFF
        if rotated & 0x80000000:
            rotated = (rotated + 0x68) & 0xFFFFFFFF
        return rotated & 0xFF

    def _looks_hex_bytes(self, value: bytes) -> bool:
        return bool(value) and all(byte in b"0123456789abcdefABCDEF" for byte in value)

    def _hex_generated_flag_findings(self, target: Target, flag_patterns: list[str]) -> list[Finding]:
        data = target.data
        findings: list[Finding] = []
        for fmt_offset in self._find_all(data, b"%02x"):
            prefix = self._nearby_flag_prefix(data, fmt_offset)
            suffix = self._nearby_suffix(data, fmt_offset)
            if not prefix:
                continue
            table_start = self._guess_hex_table_start(data, fmt_offset)
            if table_start is None:
                findings.append(
                    Finding(
                        score=62.0,
                        title="hex-generated flag pattern",
                        category=self.category,
                        detail=f"Found {prefix}%02x... pattern near raw offset 0x{fmt_offset:x}; inspect nearby byte table.",
                        source=target.label,
                        metadata={"format_offset": fmt_offset, "prefix": prefix},
                    )
                )
                continue
            findings.extend(self._sha256_hex_output_findings(data, target.label, fmt_offset, table_start, prefix, suffix))
            likely_length = self._guess_hex_loop_length(data, fmt_offset)
            lengths = [likely_length] if likely_length else []
            lengths.extend(length for length in (16, 24, 32, 48, 64) if length not in lengths)
            for length in lengths:
                table = data[table_start : table_start + length]
                if len(table) < length:
                    continue
                candidate = prefix + table.hex() + suffix
                findings.append(
                    Finding(
                        score=72.0 if likely_length == length else (60.0 if length == 32 else 48.0),
                        title="hex-generated flag candidate" if likely_length != length else "hex-generated flag candidate (loop length)",
                        category=self.category,
                        detail=f"{length} bytes from raw offset 0x{table_start:x}; may be a lookup/hash constant table, not final output.",
                        source=target.label,
                        value=candidate,
                        metadata={"format_offset": fmt_offset, "table_offset": table_start, "length": length},
                    )
                )
        return findings[:10]

    def _sha256_hex_output_findings(
        self,
        data: bytes,
        source: str,
        fmt_offset: int,
        table_start: int,
        prefix: str,
        suffix: str,
    ) -> list[Finding]:
        if table_start + 256 > len(data) or not self._has_sha256_iv(data):
            return []
        messages = self._candidate_hash_messages(data, fmt_offset, table_start)
        if not messages:
            return []
        k_words = [struct.unpack_from("<I", data, table_start + idx * 4)[0] for idx in range(64)]
        findings: list[Finding] = []
        seen: set[tuple[str, bytes]] = set()
        for message_offset, message in messages[:3]:
            if (message_offset, message) in seen:
                continue
            seen.add((message_offset, message))
            variant_digest = self._sha256_variant(message, k_words).hex()
            findings.append(
                Finding(
                    score=128.0,
                    title="custom SHA-256 generated flag candidate",
                    category=self.category,
                    detail=f"Hashes printable message at raw offset 0x{message_offset:x} with the binary's 64 round constants.",
                    source=source,
                    value=prefix + variant_digest + suffix,
                    metadata={
                        "format_offset": fmt_offset,
                        "message_offset": message_offset,
                        "message": message.decode("utf-8", errors="replace"),
                        "constants_offset": table_start,
                        "digest": variant_digest,
                    },
                )
            )
            standard_digest = hashlib.sha256(message).hexdigest()
            if standard_digest != variant_digest:
                findings.append(
                    Finding(
                        score=106.0,
                        title="standard SHA-256 generated flag candidate",
                        category=self.category,
                        detail=f"Hashes printable message at raw offset 0x{message_offset:x} with standard SHA-256.",
                        source=source,
                        value=prefix + standard_digest + suffix,
                        metadata={
                            "format_offset": fmt_offset,
                            "message_offset": message_offset,
                            "message": message.decode("utf-8", errors="replace"),
                            "digest": standard_digest,
                        },
                    )
                )
        return findings

    def _has_sha256_iv(self, data: bytes) -> bool:
        iv = (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A)
        little_hits = sum(1 for value in iv if struct.pack("<I", value) in data)
        big_hits = sum(1 for value in iv if struct.pack(">I", value) in data)
        return max(little_hits, big_hits) >= 3

    def _candidate_hash_messages(self, data: bytes, fmt_offset: int, table_start: int) -> list[tuple[int, bytes]]:
        start = fmt_offset + len(b"%02x")
        end = min(table_start, fmt_offset + 1024)
        messages: list[tuple[int, bytes]] = []
        idx = start
        while idx < end:
            while idx < end and data[idx] == 0:
                idx += 1
            run_start = idx
            while idx < end and data[idx] != 0:
                idx += 1
            run = data[run_start:idx]
            if 8 <= len(run) <= 128 and all(byte in (9, 10, 13) or 32 <= byte <= 126 for byte in run):
                if b"%" not in run and b"{" not in run and b"}" not in run:
                    messages.append((run_start, run))
            idx += 1
        return list(reversed(messages))

    def _sha256_variant(self, message: bytes, k_words: list[int]) -> bytes:
        mask = 0xFFFFFFFF

        def rotr(value: int, shift: int) -> int:
            return ((value >> shift) | (value << (32 - shift))) & mask

        h_words = [
            0x6A09E667,
            0xBB67AE85,
            0x3C6EF372,
            0xA54FF53A,
            0x510E527F,
            0x9B05688C,
            0x1F83D9AB,
            0x5BE0CD19,
        ]
        padded = bytearray(message)
        bit_length = len(padded) * 8
        padded.append(0x80)
        while len(padded) % 64 != 56:
            padded.append(0)
        padded.extend(bit_length.to_bytes(8, "big"))

        for block_start in range(0, len(padded), 64):
            block = padded[block_start : block_start + 64]
            words = [int.from_bytes(block[idx : idx + 4], "big") for idx in range(0, 64, 4)]
            for idx in range(16, 64):
                s0 = rotr(words[idx - 15], 7) ^ rotr(words[idx - 15], 18) ^ (words[idx - 15] >> 3)
                s1 = rotr(words[idx - 2], 17) ^ rotr(words[idx - 2], 19) ^ (words[idx - 2] >> 10)
                words.append((words[idx - 16] + s0 + words[idx - 7] + s1) & mask)

            a, b, c, d, e, f, g, h = h_words
            for idx in range(64):
                sum1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
                ch = (e & f) ^ ((~e) & g)
                temp1 = (h + sum1 + ch + k_words[idx] + words[idx]) & mask
                sum0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
                maj = (a & b) ^ (a & c) ^ (b & c)
                temp2 = (sum0 + maj) & mask
                h, g, f, e, d, c, b, a = g, f, e, (d + temp1) & mask, c, b, a, (temp1 + temp2) & mask

            h_words = [(old + new) & mask for old, new in zip(h_words, (a, b, c, d, e, f, g, h))]
        return b"".join(value.to_bytes(4, "big") for value in h_words)

    def _find_all(self, data: bytes, needle: bytes) -> list[int]:
        offsets = []
        start = 0
        while True:
            offset = data.find(needle, start)
            if offset < 0:
                return offsets
            offsets.append(offset)
            start = offset + 1

    def _nearby_flag_prefix(self, data: bytes, offset: int) -> str | None:
        window_start = max(0, offset - 128)
        window = data[window_start:offset]
        candidates = []
        for marker in (b"flag{", b"ctf{", b"FLAG{", b"CTF{", b"DH{"):
            idx = window.rfind(marker)
            if idx >= 0:
                candidates.append((idx, marker))
        generic = list(__import__("re").finditer(rb"\b[A-Z0-9_]{2,32}\{", window))
        for match in generic:
            candidates.append((match.start(), match.group(0)))
        if not candidates:
            return None
        _idx, marker = max(candidates, key=lambda item: item[0])
        return marker.decode("ascii", errors="ignore")

    def _nearby_suffix(self, data: bytes, offset: int) -> str:
        window = data[offset : offset + 32]
        if b"}" in window:
            return "}"
        return "}"

    def _guess_hex_table_start(self, data: bytes, fmt_offset: int) -> int | None:
        start = fmt_offset + 4
        end = min(len(data), fmt_offset + 512)
        idx = start
        while idx < end:
            while idx < end and data[idx] == 0:
                idx += 1
            run_start = idx
            while idx < end and data[idx] != 0:
                idx += 1
            run = data[run_start:idx]
            if len(run) >= 16 and sum(32 <= byte <= 126 for byte in run) / len(run) < 0.75:
                return run_start
            idx += 1
        return None

    def _guess_hex_loop_length(self, data: bytes, fmt_offset: int) -> int | None:
        start = max(0, fmt_offset - 256)
        end = min(len(data), fmt_offset + 256)
        window = data[start:end]
        candidates = []
        for idx in range(len(window) - 4):
            if window[idx] == 0x83 and window[idx + 1] in {0x7D, 0xBD}:
                value = window[idx + (3 if window[idx + 1] == 0x7D else 6)]
                if 0 < value <= 255:
                    candidates.append(value + 1)
        for preferred in (32, 16, 24, 48, 64):
            if preferred in candidates:
                return preferred
        return candidates[0] if candidates else None

    def _elf_static_findings(self, target: Target, flag_patterns: list[str], string_blob: str) -> list[Finding]:
        sections = self._elf_sections(target.data)
        text = next((section for section in sections if section["name"] == ".text"), None)
        if not text:
            text = {"offset": 0, "size": min(len(target.data), 0x20000)}
        raw = target.data[int(text["offset"]) : int(text["offset"]) + int(text["size"])]
        findings: list[Finding] = []
        stack_findings = self._stack_xor_string_findings(raw, int(text["offset"]), target.label, flag_patterns)
        focus_offsets = [
            int(finding.metadata["offset"])
            for finding in stack_findings
            if isinstance(finding.metadata.get("offset"), int)
        ]
        findings.extend(stack_findings)
        findings.extend(self._magic_number_findings(raw, int(text["offset"]), target.label, string_blob, focus_offsets))
        findings.extend(self._indexed_char_compare_findings(raw, int(text["offset"]), target.label, flag_patterns))
        return findings

    def _elf_sections(self, data: bytes) -> list[dict[str, int | str]]:
        if not data.startswith(b"\x7fELF") or len(data) < 0x40:
            return []
        try:
            elf_class = data[4]
            endian = "<" if data[5] == 1 else ">"
            if elf_class == 2:
                e_shoff = struct.unpack_from(endian + "Q", data, 0x28)[0]
                e_shentsize = struct.unpack_from(endian + "H", data, 0x3A)[0]
                e_shnum = struct.unpack_from(endian + "H", data, 0x3C)[0]
                e_shstrndx = struct.unpack_from(endian + "H", data, 0x3E)[0]
                section_fmt = endian + "IIQQQQIIQQ"
            elif elf_class == 1:
                e_shoff = struct.unpack_from(endian + "I", data, 0x20)[0]
                e_shentsize = struct.unpack_from(endian + "H", data, 0x2E)[0]
                e_shnum = struct.unpack_from(endian + "H", data, 0x30)[0]
                e_shstrndx = struct.unpack_from(endian + "H", data, 0x32)[0]
                section_fmt = endian + "IIIIIIIIII"
            else:
                return []
            if not e_shoff or not e_shnum or e_shoff >= len(data):
                return []
            headers = []
            for idx in range(e_shnum):
                offset = e_shoff + idx * e_shentsize
                if offset + e_shentsize > len(data):
                    return []
                values = struct.unpack_from(section_fmt, data, offset)
                headers.append(values)
            if e_shstrndx >= len(headers):
                return []
            str_header = headers[e_shstrndx]
            str_offset = int(str_header[4])
            str_size = int(str_header[5])
            names = data[str_offset : str_offset + str_size]
            sections = []
            for values in headers:
                name_offset = int(values[0])
                name = self._read_c_string(names, name_offset)
                sections.append({"name": name, "offset": int(values[4]), "size": int(values[5])})
            return sections
        except (struct.error, ValueError, IndexError):
            return []

    def _read_c_string(self, data: bytes, offset: int) -> str:
        if offset < 0 or offset >= len(data):
            return ""
        end = data.find(b"\x00", offset)
        if end < 0:
            end = len(data)
        return data[offset:end].decode("ascii", errors="ignore")

    def _pe_static_findings(self, target: Target, flag_patterns: list[str], string_blob: str) -> list[Finding]:
        sections = self._pe_sections(target.data)
        text = next((section for section in sections if section["name"] == ".text"), None)
        if not text:
            return []
        raw = target.data[text["raw_ptr"] : text["raw_ptr"] + text["raw_size"]]
        findings: list[Finding] = []
        stack_findings = self._stack_xor_string_findings(raw, text["raw_ptr"], target.label, flag_patterns)
        focus_offsets = [
            int(finding.metadata["offset"])
            for finding in stack_findings
            if isinstance(finding.metadata.get("offset"), int)
        ]
        findings.extend(stack_findings)
        findings.extend(self._magic_number_findings(raw, text["raw_ptr"], target.label, string_blob, focus_offsets))
        findings.extend(self._indexed_char_compare_findings(raw, text["raw_ptr"], target.label, flag_patterns))
        return findings

    def _indexed_char_compare_findings(
        self,
        code: bytes,
        raw_base: int,
        source: str,
        flag_patterns: list[str],
    ) -> list[Finding]:
        compares: dict[int, int] = {}
        idx = 0
        while idx < len(code) - 16:
            if code[idx : idx + 3] == b"\x48\x6b\xc0":
                char_index = code[idx + 3]
                window = code[idx : idx + 40]
                load_at = window.find(b"\x0f\xb6\x04\x01")
                cmp_at = window.find(b"\x83\xf8")
                if 0 <= load_at < cmp_at and cmp_at + 2 < len(window):
                    compares[char_index] = window[cmp_at + 2]
                    idx += 4
                    continue
            idx += 1
        if len(compares) < 6 or 0 not in compares:
            return []
        ordered = []
        for char_index in range(max(compares) + 1):
            if char_index not in compares:
                break
            value = compares[char_index]
            if value == 0:
                break
            ordered.append(value)
        if len(ordered) < 6 or not looks_textual(bytes(ordered)):
            return []
        decoded = bytes(ordered).decode("ascii", errors="ignore")
        values = [decoded]
        for prefix in self._flag_prefixes_from_patterns(flag_patterns):
            wrapped = f"{prefix}{{{decoded}}}"
            if wrapped not in values:
                values.append(wrapped)
        findings = []
        for value in values[:4]:
            findings.append(
                Finding(
                    score=118.0 if value != decoded else 92.0,
                    title="indexed char compare flag candidate" if value != decoded else "indexed char compare string",
                    category=self.category,
                    detail=f"Recovered sequential input[index] == char comparisons: {decoded}",
                    source=source,
                    value=value,
                    metadata={"decoded": decoded, "length": len(decoded), "offset": raw_base},
                )
            )
        return findings

    def _flag_prefixes_from_patterns(self, flag_patterns: list[str]) -> list[str]:
        prefixes = []
        for pattern in flag_patterns:
            cleaned = pattern.replace("\\", "")
            match = __import__("re").search(r"\b([A-Za-z0-9_]{2,32})\{", cleaned)
            if match:
                prefix = match.group(1)
                if prefix.lower() in {"bflag", "bctf"}:
                    prefix = prefix[1:]
                if prefix not in prefixes and not any(char in prefix for char in "[]().?+*|"):
                    if prefix.lower() not in {"flag", "ctf"}:
                        prefixes.insert(0, prefix)
                    else:
                        prefixes.append(prefix)
        return prefixes or ["FLAG"]

    def _pe_sections(self, data: bytes) -> list[dict[str, int | str]]:
        if not data.startswith(b"MZ"):
            return []
        try:
            pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
            if data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
                return []
            section_count = struct.unpack_from("<H", data, pe_offset + 6)[0]
            optional_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
            section_offset = pe_offset + 24 + optional_size
            sections = []
            for idx in range(section_count):
                offset = section_offset + idx * 40
                name = data[offset : offset + 8].split(b"\x00")[0].decode("ascii", errors="ignore")
                virtual_size, virtual_address, raw_size, raw_ptr = struct.unpack_from("<IIII", data, offset + 8)
                sections.append(
                    {
                        "name": name,
                        "virtual_size": virtual_size,
                        "virtual_address": virtual_address,
                        "raw_size": raw_size,
                        "raw_ptr": raw_ptr,
                    }
                )
            return sections
        except (struct.error, ValueError):
            return []

    def _magic_number_findings(
        self,
        code: bytes,
        raw_base: int,
        source: str,
        string_blob: str,
        focus_offsets: list[int],
    ) -> list[Finding]:
        findings: list[Finding] = []
        lowered_blob = string_blob.lower()
        wants_number = any(
            word in lowered_blob
            for word in ("magic number", "enter number", "enter the number", "pin:", "serial:")
        )
        if not wants_number:
            return findings
        seen: set[int] = set()
        for idx in range(len(code) - 7):
            value: int | None = None
            opcode = code[idx : idx + 3]
            if opcode[:2] == b"\x81\x7d":
                value = struct.unpack_from("<I", code, idx + 3)[0]
            elif opcode[:2] == b"\x83\x7d":
                value = code[idx + 3]
            elif code[idx] == 0x3D:
                value = struct.unpack_from("<I", code, idx + 1)[0]
            if value is None or value in seen or value > 10_000_000:
                continue
            seen.add(value)
            raw_offset = raw_base + idx
            near_focus = any(abs(raw_offset - focus) <= 768 for focus in focus_offsets)
            score = 34.0
            if value <= 999_999:
                score = 48.0
            if value <= 9999:
                score = 58.0
            if near_focus:
                score += 28.0
            findings.append(
                Finding(
                    score=score,
                    title="magic number candidate",
                    category=self.category,
                    detail=f"Possible comparison immediate: {value} (0x{value:x}) at raw offset 0x{raw_offset:x}",
                    source=source,
                    value=str(value),
                    metadata={"offset": raw_offset, "integer": value, "hex": hex(value), "near_decoded_flag": near_focus},
                )
            )
        return sorted(findings, reverse=True)[:8]

    def _stack_xor_string_findings(self, code: bytes, raw_base: int, source: str, flag_patterns: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        seen_flags: set[str] = set()
        for start in range(0, len(code), 128):
            window = code[start : start + 512]
            stack_bytes: dict[int, int] = {}
            idx = 0
            while idx < len(window) - 3:
                if idx + 7 <= len(window) and window[idx : idx + 2] == b"\xc7\x45":
                    stack_offset = struct.unpack("b", window[idx + 2 : idx + 3])[0]
                    imm = window[idx + 3 : idx + 7]
                    for byte_idx, byte in enumerate(imm):
                        stack_bytes[stack_offset + byte_idx] = byte
                    idx += 7
                    continue
                if idx + 8 <= len(window) and window[idx : idx + 3] == b"\xc7\x44\x24":
                    stack_offset = window[idx + 3]
                    imm = window[idx + 4 : idx + 8]
                    for byte_idx, byte in enumerate(imm):
                        stack_bytes[stack_offset + byte_idx] = byte
                    idx += 8
                    continue
                if idx + 7 <= len(window) and window[idx : idx + 3] == b"\xc7\x45":
                    stack_offset = struct.unpack("b", window[idx + 2 : idx + 3])[0]
                    imm = window[idx + 3 : idx + 7]
                    for byte_idx, byte in enumerate(imm):
                        stack_bytes[stack_offset + byte_idx] = byte
                    idx += 7
                    continue
                if idx + 6 <= len(window) and window[idx : idx + 3] == b"\x66\xc7\x45":
                    stack_offset = struct.unpack("b", window[idx + 3 : idx + 4])[0]
                    imm = window[idx + 4 : idx + 6]
                    for byte_idx, byte in enumerate(imm):
                        stack_bytes[stack_offset + byte_idx] = byte
                    idx += 6
                    continue
                if idx + 7 <= len(window) and window[idx : idx + 4] == b"\x66\xc7\x44\x24":
                    stack_offset = window[idx + 4]
                    imm = window[idx + 5 : idx + 7]
                    for byte_idx, byte in enumerate(imm):
                        stack_bytes[stack_offset + byte_idx] = byte
                    idx += 7
                    continue
                if idx + 4 <= len(window) and window[idx : idx + 2] == b"\xc6\x45":
                    stack_offset = struct.unpack("b", window[idx + 2 : idx + 3])[0]
                    stack_bytes[stack_offset] = window[idx + 3]
                    idx += 4
                    continue
                if idx + 5 <= len(window) and window[idx : idx + 3] == b"\xc6\x44\x24":
                    stack_offset = window[idx + 3]
                    stack_bytes[stack_offset] = window[idx + 4]
                    idx += 5
                    continue
                idx += 1
            if len(stack_bytes) < 8:
                continue

            encoded = bytes(stack_bytes[key] for key in sorted(stack_bytes))
            keys = set(reversed([window[i + 1] for i in range(len(window) - 1) if window[i] == 0x34]))
            keys.update(range(1, 256))
            for key in keys:
                decoded = bytes(byte ^ key for byte in encoded)
                if not looks_textual(decoded):
                    continue
                text = decoded.decode("utf-8", errors="ignore").rstrip("\x00")
                flags = find_flags(text, flag_patterns)
                if not flags:
                    continue
                for flag in flags:
                    if flag in seen_flags:
                        continue
                    seen_flags.add(flag)
                    findings.append(
                        Finding(
                            score=94.0,
                            title="stack XOR string flag",
                            category=self.category,
                            detail=f"{flag} (xor key 0x{key:02x})",
                            source=source,
                            value=flag,
                            metadata={"offset": raw_base + start, "key_hex": hex(key)},
                        )
                    )
                break
        return findings

    def _credential_string_findings(self, strings: list[str], source: str) -> list[Finding]:
        findings: list[Finding] = []
        indicators = ("password", "serial", "key", "pin", "username", "admin")
        api_suffixes = ("W", "A")
        for idx, value in enumerate(strings):
            lowered = value.lower().strip()
            if lowered in {"password", "enter password:", "wrong!", "correct! %s"}:
                continue
            if any(word in lowered for word in ("invalid", "wrong", "correct", "flag{")):
                continue
            if "%" in value or len(value) < 4:
                continue
            if value.strip().endswith(":"):
                continue
            if value.startswith(("Get", "Set", "Create", "Enter", "Exit", "Initialize", "UnhandledException")):
                continue
            if value.endswith(api_suffixes) and any(char.isupper() for char in value[1:]):
                continue
            score = 0.0
            title = ""
            if any(marker in lowered for marker in indicators) and 4 <= len(value) <= 80:
                score = 52.0
                title = "credential candidate"
            if idx > 0 and "enter password" in strings[idx - 1].lower() and 3 <= len(value) <= 80:
                score = 74.0
                title = "password candidate"
            if value == "admin":
                score = max(score, 58.0)
                title = title or "credential candidate"
            if not score:
                continue
            findings.append(
                Finding(
                    score=score,
                    title=title,
                    category=self.category,
                    detail=f"Possible input/credential string: {value}",
                    source=source,
                    value=value,
                )
            )
        return findings[:8]
