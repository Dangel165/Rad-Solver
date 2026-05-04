import base64
import struct
import unittest
import zlib

from ctfbot.engine import SolverEngine
from ctfbot.models import Target


def png_with_text(keyword: str, text: str) -> bytes:
    def chunk(name: bytes, payload: bytes) -> bytes:
        crc = zlib.crc32(name + payload) & 0xFFFFFFFF
        return struct.pack(">I", len(payload)) + name + payload + struct.pack(">I", crc)

    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
        + chunk(b"tEXt", keyword.encode("latin-1") + b"\x00" + text.encode("latin-1"))
        + chunk(b"IEND", b"")
    )


class DeeperFieldAnalysisTests(unittest.TestCase):
    def analyze(self, name: str, data: bytes, prompt: str = ""):
        return SolverEngine(prompt=prompt).analyze([Target(name, data)])

    def values(self, findings):
        return {finding.value for finding in findings if finding.value}

    def titles(self, findings):
        return {finding.title for finding in findings}

    def test_crypto_recursive_decode(self):
        nested = base64.b64encode(b"flag{nested_decode}")
        doubly = base64.b64encode(nested)
        findings = self.analyze("nested.txt", doubly, "crypto")
        self.assertIn("flag{nested_decode}", self.values(findings))
        self.assertIn("recursive decode flag", self.titles(findings))

    def test_crypto_toy_rsa(self):
        message = int.from_bytes(b"flag{rsa_toy}", "big")
        p, q, e = 3_557, 2_579, 3
        n = p * q
        c = pow(message, e, n)
        # The tiny modulus cannot hold the full message, so use a small plaintext for this exact RSA case.
        plain = int.from_bytes(b"OK", "big")
        c = pow(plain, e, n)
        findings = self.analyze("rsa.txt", f"n={n}\ne={e}\nc={c}".encode(), "crypto rsa")
        self.assertIn("toy RSA decrypt", self.titles(findings))
        self.assertIn("OK", self.values(findings))

    def test_forensics_png_text_chunk_flag(self):
        data = png_with_text("Comment", "FORENSICS{png_chunk_flag}")
        findings = self.analyze("chunk.png", data, "forensics flag format: FORENSICS{}")
        self.assertIn("FORENSICS{png_chunk_flag}", self.values(findings))
        self.assertIn("flag inside PNG text chunk", self.titles(findings))

    def test_web_payload_candidates(self):
        html = b"<form><input name='role' value='user'></form><!-- jwt admin union select --><script>alert(1)</script>{{7*7}}"
        findings = self.analyze("web.html", html, "web sqli xss ssti jwt admin")
        values = self.values(findings)
        self.assertIn("' OR '1'='1' -- ", values)
        self.assertIn("<script>alert(1)</script>", values)
        self.assertIn("{{7*7}}", values)
        self.assertIn("role=admin", values)

    def test_pwn_target_candidates(self):
        data = b"\x7fELF" + b"\x00" * 16 + b"ret2win\x00system\x00/bin/sh\x00printf(user_input)\x00%p %n\x00"
        findings = self.analyze("pwn.bin", data, "pwn ret2win format string")
        values = self.values(findings)
        self.assertIn("ret2win", values)
        self.assertIn("system('/bin/sh')", values)
        self.assertIn("%p.%p.%p.%p.%p", values)


if __name__ == "__main__":
    unittest.main()
