import unittest

from ctfbot.engine import SolverEngine
from ctfbot.models import Target
from ctfbot.plugins.reversing import ReversingPlugin


def wide(text: str) -> bytes:
    return text.encode("utf-16le")


def xor(text: str, key: int) -> bytes:
    return bytes(byte ^ key for byte in text.encode("ascii"))


class ReversingAccuracyTests(unittest.TestCase):
    def analyze(self, name: str, data: bytes, prompt: str = ""):
        return SolverEngine(prompt=prompt).analyze([Target(name, data)])

    def values(self, findings):
        return {finding.value for finding in findings if finding.value}

    def titles(self, findings):
        return {finding.title for finding in findings}

    def test_pe_ascii_flag_and_password_prompt(self):
        data = b"MZ\x90\x00" + b"\x00" * 64 + b"Enter password:\x00Wrong password!\x00REV{plain_string_flag}\x00"
        findings = self.analyze("rev_ascii.exe", data, "reversing flag format: REV{} password")
        self.assertIn("REV{plain_string_flag}", self.values(findings))
        self.assertIn("program prompt strings", self.titles(findings))

    def test_pe_utf16_flag(self):
        data = b"MZ\x90\x00" + b"\x00" * 32 + wide("Correct! REV{wide_string_flag}")
        findings = self.analyze("rev_wide.exe", data, "reversing flag format: REV{}")
        self.assertIn("REV{wide_string_flag}", self.values(findings))

    def test_xor_hidden_default_flag(self):
        data = b"MZ" + b"\x00" * 16 + xor("flag{xor_hidden_reverse}", 0x37)
        findings = self.analyze("rev_xor.exe", data, "reversing xor encoded string")
        self.assertIn("flag{xor_hidden_reverse}", self.values(findings))

    def test_xor_hidden_custom_prompt_flag(self):
        data = b"MZ" + b"\x00" * 16 + xor("REV{custom_xor_reverse}", 0x21)
        findings = self.analyze("rev_custom_xor.exe", data, "reversing xor flag format: REV{}")
        self.assertIn("REV{custom_xor_reverse}", self.values(findings))

    def test_packer_and_dangerous_api_hints(self):
        data = b"MZUPX0\x00UPX1\x00CreateProcess\x00WinExec\x00scanf\x00license serial wrong\x00"
        findings = self.analyze("rev_packed.exe", data, "reversing packed windows binary")
        self.assertIn("packer hint", self.titles(findings))
        self.assertIn("pwn/reversing API hints", self.titles(findings))
        self.assertIn("program prompt strings", self.titles(findings))

    def test_elf_pwn_hint(self):
        data = b"\x7fELF" + b"\x00" * 32 + b"gets\x00system\x00Enter input:\x00"
        findings = self.analyze("pwn_elf", data, "pwn reversing")
        self.assertIn("ELF binary", self.titles(findings))
        self.assertIn("pwn/reversing API hints", self.titles(findings))

    def test_magic_number_and_stack_xor_pattern(self):
        code = bytes.fromhex(
            "81 7d cf 39 05 00 00 75 79 "
            "c7 45 b7 55 5f 52 54 "
            "c7 45 bb 68 7e 72 74 "
            "c7 45 bf 7a 70 4c 7d "
            "c7 45 c3 66 7e 71 76 "
            "c7 45 c7 61 4c 22 20 "
            "66 c7 45 cb 20 24 "
            "c6 45 cd 6e "
            "0f b6 44 0d c7 34 13 88 44 0d e6"
        )
        plugin = ReversingPlugin()
        stack = plugin._stack_xor_string_findings(code, 0x400, "fixture", [r"\bFLAG\{[A-Za-z0-9_]+\}"])
        magic = plugin._magic_number_findings(code, 0x400, "fixture", "Enter the magic number:", [0x409])
        self.assertIn("FLAG{magic_number_1337}", {finding.value for finding in stack})
        self.assertIn("1337", {finding.value for finding in magic})

    def test_indexed_char_compare_pattern(self):
        code = b"".join(
            b"\xb8\x01\x00\x00\x00"
            + b"\x48\x6b\xc0"
            + bytes([idx])
            + b"\x48\x8b\x4c\x24\x08\x0f\xb6\x04\x01\x83\xf8"
            + bytes([byte])
            + b"\x74\x04\x33\xc0\xeb\x05"
            for idx, byte in enumerate(b"Compar3_the_ch4ract3r")
        )
        plugin = ReversingPlugin()
        findings = plugin._indexed_char_compare_findings(code, 0x400, "chall1.exe", [r"DH\{[A-Za-z0-9_]+\}"])
        values = {finding.value for finding in findings}
        self.assertIn("Compar3_the_ch4ract3r", values)
        self.assertIn("DH{Compar3_the_ch4ract3r}", values)

    def test_indexed_xor_affine_table_pattern(self):
        plain = b"I_am_X0_xo_Xor_eXcit1ng\x00"
        encoded = bytes(((byte ^ idx) + 2 * idx) & 0xFF for idx, byte in enumerate(plain))
        data = b"MZ" + b"\x00" * 64 + b"Input : \x00%256s\x00Correct\x00Wrong\x00" + encoded + b"\x00" * 16
        findings = SolverEngine(prompt="reversing flag format: DH{}").analyze([Target("chall3.exe", data)])
        self.assertIn("DH{I_am_X0_xo_Xor_eXcit1ng}", self.values(findings))

    def test_nibble_swap_table_pattern(self):
        plain = b"Br1ll1ant_bit_dr1bble_<<_>>\x00"
        encoded = bytes(((byte & 0x0F) << 4) | (byte >> 4) for byte in plain)
        code_pattern = b"\xc1\xf8\x04\xc1\xe1\x04\x81\xe1\xf0\x00\x00\x00"
        data = b"MZ" + code_pattern + b"\x00" * 64 + b"Input : \x00%256s\x00Correct\x00Wrong\x00" + encoded + b"\x00" * 16
        plugin = ReversingPlugin()
        findings = plugin._nibble_swap_table_findings(Target("chall4.exe", data), [r"DH\{[A-Za-z0-9_<>]+\}"], "Input : %256s Correct")
        self.assertIn("DH{Br1ll1ant_bit_dr1bble_<<_>>}", {finding.value for finding in findings})


if __name__ == "__main__":
    unittest.main()
