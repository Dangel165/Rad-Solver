import unittest

from ctfbot.engine import SolverEngine
from ctfbot.models import Target


class SolverTests(unittest.TestCase):
    def test_base64_flag(self):
        target = Target("sample", b"ZmxhZ3t1bml0X3Rlc3R9")
        findings = SolverEngine().analyze([target])
        values = [finding.value for finding in findings if finding.value]
        self.assertIn("flag{unit_test}", values)

    def test_plain_flag(self):
        target = Target("plain", b"hello flag{plain_text}")
        findings = SolverEngine().analyze([target])
        self.assertEqual(findings[0].value, "flag{plain_text}")

    def test_xor_flag(self):
        key = 0x42
        encoded = bytes(byte ^ key for byte in b"flag{xor_auto}")
        findings = SolverEngine().analyze([Target("xor", encoded)])
        values = [finding.value for finding in findings if finding.value]
        self.assertIn("flag{xor_auto}", values)

    def test_prompt_adds_flag_format_and_boosts_category(self):
        target = Target("custom", b"KEYROOT{prompt_flag}")
        findings = SolverEngine(prompt="category: web\nflag format: KEYROOT{}").analyze([target])
        values = [finding.value for finding in findings if finding.value]
        self.assertIn("KEYROOT{prompt_flag}", values)


if __name__ == "__main__":
    unittest.main()
