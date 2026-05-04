import io
import unittest
import zipfile

from ctfbot.engine import SolverEngine
from ctfbot.models import Target


def make_zip(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return buffer.getvalue()


class ForensicsPwnAccuracyTests(unittest.TestCase):
    def analyze(self, name: str, data: bytes, prompt: str = ""):
        return SolverEngine(prompt=prompt).analyze([Target(name, data)])

    def values(self, findings):
        return {finding.value for finding in findings if finding.value}

    def titles(self, findings):
        return {finding.title for finding in findings}

    def test_zip_flag_inside_entry(self):
        data = make_zip({"notes.txt": b"nothing", "hidden/flag.txt": b"FORENSICS{zip_entry_flag}"})
        findings = self.analyze("archive.zip", data, "forensics flag format: FORENSICS{} zip hidden")
        self.assertIn("FORENSICS{zip_entry_flag}", self.values(findings))
        self.assertIn("zip entries", self.titles(findings))
        self.assertIn("flag inside zip entry", self.titles(findings))

    def test_png_text_and_embedded_zip_signature(self):
        data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 24 + b"tEXtsecret=FORENSICS{png_text_flag}" + b"\x00" * 8 + make_zip({"a.txt": b"x"})
        findings = self.analyze("image.png", data, "forensics png secret flag format: FORENSICS{}")
        self.assertIn("FORENSICS{png_text_flag}", self.values(findings))
        self.assertIn("file type", self.titles(findings))
        self.assertIn("embedded file signature", self.titles(findings))

    def test_pdf_hidden_token_strings(self):
        data = b"%PDF-1.7\n1 0 obj\n<< /Secret (FORENSICS{pdf_hidden_token}) >>\nendobj\n%%EOF"
        findings = self.analyze("doc.pdf", data, "forensics pdf hidden flag format: FORENSICS{}")
        self.assertIn("FORENSICS{pdf_hidden_token}", self.values(findings))
        self.assertIn("interesting string: secret", self.titles(findings))

    def test_elf_pwn_dangerous_functions_and_rop_markers(self):
        data = b"\x7fELF" + b"\x00" * 16 + b"gets\x00system\x00/bin/sh\x00ret2win\x00pop rdi; ret\x00Enter input:\x00"
        findings = self.analyze("pwn_rop", data, "pwn ret2win rop")
        self.assertIn("ELF binary", self.titles(findings))
        self.assertIn("pwn dangerous functions", self.titles(findings))
        self.assertIn("pwn exploitation hints", self.titles(findings))

    def test_format_string_markers(self):
        data = b"\x7fELF" + b"\x00" * 20 + b"printf(user_input)\x00%p %p %n\x00Enter format:\x00"
        findings = self.analyze("fmt", data, "pwn format string")
        self.assertIn("format string hints", self.titles(findings))
        self.assertIn("ELF binary", self.titles(findings))


if __name__ == "__main__":
    unittest.main()
