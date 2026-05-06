"""Forensics plugin for CTF analysis."""

import struct
import re
from ..models import Finding, Target


class ForensicsPlugin:
    """Analyzes files for forensic artifacts and hidden data."""
    name = "forensics"
    category = "forensics"

    def analyze(self, target: Target, flag_patterns: list[str]) -> list[Finding]:
        """Analyze target for forensic artifacts."""
        findings = []

        data = target.data
        findings.extend(self._file_signature_findings(data, flag_patterns))
        findings.extend(self._metadata_findings(data, flag_patterns))
        findings.extend(self._steganography_hints(data, flag_patterns))
        findings.extend(self._hidden_data_findings(data, flag_patterns))
        findings.extend(self._string_extraction(data, flag_patterns))
        findings.extend(self._compression_analysis(data, flag_patterns))

        return findings

    def _file_signature_findings(self, data: bytes, flag_patterns: list[str]) -> list[Finding]:
        """Detect file signatures (magic bytes)."""
        findings = []
        signatures = {
            b'\x89PNG': ('PNG Image', 18),
            b'\xff\xd8\xff': ('JPEG Image', 18),
            b'%PDF': ('PDF Document', 20),
            b'PK\x03\x04': ('ZIP Archive', 22),
            b'\x7fELF': ('ELF Binary', 20),
            b'MZ': ('PE Binary (Windows)', 20),
            b'GIF8': ('GIF Image', 18),
            b'\x1f\x8b': ('GZIP Compressed', 16),
            b'BM': ('BMP Image', 16),
            b'\xff\xfb': ('MP3 Audio', 14),
        }

        for sig, (desc, score) in signatures.items():
            if data.startswith(sig):
                findings.append(Finding(
                    score=score,
                    title='File Signature',
                    category=self.category,
                    detail=f'File identified as {desc}',
                    value=desc
                ))
                break

        return findings

    def _metadata_findings(self, data: bytes, flag_patterns: list[str]) -> list[Finding]:
        """Extract metadata from files."""
        findings = []

        # JPEG EXIF metadata
        if data.startswith(b'\xff\xd8\xff'):
            exif_data = self._extract_exif(data)
            for key, value in exif_data.items():
                value_str = str(value).lower()
                if any(pattern in value_str for pattern in ['flag', 'key', 'secret', 'password', 'ctf']):
                    findings.append(Finding(
                        score=28,
                        title='EXIF Metadata',
                        category=self.category,
                        detail=f'EXIF metadata contains suspicious keyword: {key}',
                        value=str(value)
                    ))
                else:
                    findings.append(Finding(
                        score=12,
                        title='EXIF Metadata',
                        category=self.category,
                        detail=f'EXIF metadata: {key}',
                        value=str(value)
                    ))

        # PNG metadata chunks
        if data.startswith(b'\x89PNG'):
            png_meta = self._extract_png_metadata(data)
            for key, value in png_meta.items():
                value_str = str(value).lower()
                if any(pattern in value_str for pattern in ['flag', 'key', 'secret', 'password', 'ctf']):
                    findings.append(Finding(
                        score=28,
                        title='PNG Metadata',
                        category=self.category,
                        detail=f'PNG metadata contains suspicious keyword: {key}',
                        value=str(value)
                    ))
                else:
                    findings.append(Finding(
                        score=12,
                        title='PNG Metadata',
                        category=self.category,
                        detail=f'PNG metadata: {key}',
                        value=str(value)
                    ))

        return findings

    def _steganography_hints(self, data: bytes, flag_patterns: list[str]) -> list[Finding]:
        """Detect potential steganography."""
        findings = []

        # High entropy detection (potential encryption/compression)
        entropy = self._calculate_entropy(data)
        if entropy > 7.8:
            findings.append(Finding(
                score=22,
                title='High Entropy',
                category=self.category,
                detail='Very high entropy - likely encrypted or compressed data',
                value=f'Entropy: {entropy:.2f}'
            ))
        elif entropy > 7.5:
            findings.append(Finding(
                score=16,
                title='High Entropy',
                category=self.category,
                detail='High entropy detected - possible encryption or compression',
                value=f'Entropy: {entropy:.2f}'
            ))

        # Null byte patterns (potential hidden data)
        null_count = data.count(b'\x00')
        if null_count > len(data) * 0.2:
            findings.append(Finding(
                score=18,
                title='Null Bytes',
                category=self.category,
                detail='Unusual null byte density - likely hidden data or padding',
                value=f'Null bytes: {null_count}'
            ))
        elif null_count > len(data) * 0.1:
            findings.append(Finding(
                score=12,
                title='Null Bytes',
                category=self.category,
                detail='Unusual null byte density - possible hidden data',
                value=f'Null bytes: {null_count}'
            ))

        return findings

    def _hidden_data_findings(self, data: bytes, flag_patterns: list[str]) -> list[Finding]:
        """Detect hidden data patterns."""
        findings = []

        # Control characters (potential hidden text)
        control_chars = sum(1 for b in data if b < 32 and b not in (9, 10, 13))
        if control_chars > len(data) * 0.1:
            findings.append(Finding(
                score=16,
                title='Control Characters',
                category=self.category,
                detail='High control character density - likely hidden or obfuscated data',
                value=f'Control chars: {control_chars}'
            ))
        elif control_chars > len(data) * 0.05:
            findings.append(Finding(
                score=10,
                title='Control Characters',
                category=self.category,
                detail='Unusual control character density',
                value=f'Control chars: {control_chars}'
            ))

        # Look for common flag patterns in raw data
        for pattern in flag_patterns:
            if pattern.encode() in data:
                findings.append(Finding(
                    score=30,
                    title='Pattern Match',
                    category=self.category,
                    detail='Flag pattern found in raw data',
                    value=pattern
                ))

        return findings

    def _string_extraction(self, data: bytes, flag_patterns: list[str]) -> list[Finding]:
        """Extract readable strings from binary data."""
        findings = []
        
        # Extract ASCII strings (min 4 chars)
        strings = []
        current = b''
        for byte in data:
            if 32 <= byte <= 126:
                current += bytes([byte])
            else:
                if len(current) >= 4:
                    strings.append(current.decode('ascii', errors='ignore'))
                current = b''
        
        if current and len(current) >= 4:
            strings.append(current.decode('ascii', errors='ignore'))
        
        # Check for suspicious strings
        suspicious_keywords = ['flag', 'password', 'secret', 'key', 'ctf', 'admin', 'root', 'token']
        for s in strings[:20]:  # Check first 20 strings
            s_lower = s.lower()
            if any(kw in s_lower for kw in suspicious_keywords):
                findings.append(Finding(
                    score=24,
                    title='Suspicious String',
                    category=self.category,
                    detail=f'Suspicious string found: {s}',
                    value=s
                ))
            elif len(s) > 8 and any(c.isupper() for c in s) and any(c.isdigit() for c in s):
                # Looks like a potential flag or hash
                findings.append(Finding(
                    score=18,
                    title='Potential Flag',
                    category=self.category,
                    detail=f'Potential flag/hash: {s}',
                    value=s
                ))
        
        return findings

    def _compression_analysis(self, data: bytes, flag_patterns: list[str]) -> list[Finding]:
        """Analyze compression and encoding patterns."""
        findings = []
        
        # Check for repeated byte patterns (compression indicator)
        if len(data) > 100:
            byte_freq = {}
            for byte in data[:1000]:
                byte_freq[byte] = byte_freq.get(byte, 0) + 1
            
            max_freq = max(byte_freq.values()) if byte_freq else 0
            if max_freq > 100:
                findings.append(Finding(
                    score=14,
                    title='Compression',
                    category=self.category,
                    detail='High byte repetition - likely compressed or encoded data',
                    value=f'Byte frequency: {max_freq}/1000'
                ))
        
        return findings

    def _extract_exif(self, data: bytes) -> dict:
        """Extract EXIF metadata from JPEG."""
        metadata = {}
        try:
            # Simple EXIF extraction - look for common markers
            if b'Exif\x00\x00' in data:
                idx = data.find(b'Exif\x00\x00')
                exif_data = data[idx+6:idx+256]
                # Extract ASCII strings from EXIF
                strings = []
                current = b''
                for byte in exif_data:
                    if 32 <= byte <= 126:
                        current += bytes([byte])
                    else:
                        if len(current) > 3:
                            strings.append(current.decode('ascii', errors='ignore'))
                        current = b''
                for s in strings[:5]:
                    metadata[f'exif_{len(metadata)}'] = s
        except Exception:
            pass
        return metadata

    def _extract_png_metadata(self, data: bytes) -> dict:
        """Extract metadata chunks from PNG."""
        metadata = {}
        try:
            # PNG chunks start after 8-byte signature
            pos = 8
            while pos < len(data) - 8:
                chunk_len = struct.unpack('>I', data[pos:pos+4])[0]
                chunk_type = data[pos+4:pos+8]
                chunk_data = data[pos+8:pos+8+chunk_len]

                if chunk_type == b'tEXt':
                    # Text chunk
                    null_idx = chunk_data.find(b'\x00')
                    if null_idx > 0:
                        key = chunk_data[:null_idx].decode('ascii', errors='ignore')
                        value = chunk_data[null_idx+1:].decode('ascii', errors='ignore')
                        metadata[key] = value

                pos += 12 + chunk_len
        except Exception:
            pass
        return metadata

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        import math
        if not data:
            return 0.0
        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1
        entropy = 0.0
        for count in freq.values():
            p = count / len(data)
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy
