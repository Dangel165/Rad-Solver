import base64
import json
import unittest

from ctfbot.engine import SolverEngine
from ctfbot.models import Target


def b64(text: str) -> bytes:
    return base64.b64encode(text.encode("utf-8"))


def b32(text: str) -> bytes:
    return base64.b32encode(text.encode("utf-8"))


def hexed(text: str) -> bytes:
    return text.encode("utf-8").hex().encode("ascii")


def caesar_decode_input(plain: str, shift: int) -> bytes:
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    trans = str.maketrans(
        alphabet + alphabet.upper(),
        alphabet[-shift:] + alphabet[:-shift] + alphabet[-shift:].upper() + alphabet[:-shift].upper(),
    )
    return plain.translate(trans).encode("ascii")


def jwt_none() -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode().rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps({"role": "admin", "flag": "WEB{jwt_none_flag}"}).encode()).decode().rstrip("=")
    return f"{header}.{payload}."


class CryptoWebAccuracyTests(unittest.TestCase):
    def analyze(self, name: str, data: bytes, prompt: str = ""):
        return SolverEngine(prompt=prompt).analyze([Target(name, data)])

    def values(self, findings):
        return {finding.value for finding in findings if finding.value}

    def titles(self, findings):
        return {finding.title for finding in findings}

    def test_base64_base32_hex_flags(self):
        cases = [
            (b64("flag{base64_crypto}"), "flag{base64_crypto}"),
            (b32("flag{base32_crypto}"), "flag{base32_crypto}"),
            (hexed("flag{hex_crypto}"), "flag{hex_crypto}"),
        ]
        for data, expected in cases:
            with self.subTest(expected=expected):
                findings = self.analyze("crypto.txt", data, "crypto")
                self.assertIn(expected, self.values(findings))

    def test_rot_flag(self):
        findings = self.analyze("rot.txt", caesar_decode_input("flag{rot_crypto}", 13), "crypto rot")
        self.assertIn("flag{rot_crypto}", self.values(findings))

    def test_hash_hint(self):
        findings = self.analyze("hash.txt", b"5d41402abc4b2a76b9719d911017c592", "crypto hash md5")
        self.assertIn("hash-shaped value", self.titles(findings))

    def test_web_comments_paths_and_flag(self):
        html = b"""
        <html><!-- TODO admin /hidden-panel WEB{comment_flag} --><script src="/static/app.js"></script></html>
        """
        findings = self.analyze("index.html", html, "web flag format: WEB{}")
        self.assertIn("WEB{comment_flag}", self.values(findings))
        self.assertIn("comments", self.titles(findings))
        self.assertIn("interesting paths", self.titles(findings))

    def test_web_jwt_alg_none(self):
        html = f"<script>localStorage.token='{jwt_none()}'</script>".encode()
        findings = self.analyze("jwt.html", html, "web jwt flag format: WEB{}")
        self.assertIn("WEB{jwt_none_flag}", self.values(findings))
        self.assertIn("JWT token", self.titles(findings))
        self.assertIn("JWT alg none hint", self.titles(findings))

    def test_web_robots_sourcemap_sqli_xss(self):
        text = b"User-agent: *\nDisallow: /admin\n//# sourceMappingURL=app.js.map\n?id=' union select password\n<script>alert(1)</script>"
        findings = self.analyze("robots.txt", text, "web sqli xss")
        titles = self.titles(findings)
        self.assertIn("robots.txt hint", titles)
        self.assertIn("source map hint", titles)
        self.assertIn("web keyword: union select", titles)
        self.assertIn("web keyword: xss", titles)


if __name__ == "__main__":
    unittest.main()
