import struct
import unittest
import math

from ctfbot.engine import SolverEngine
from ctfbot.models import Target
from ctfbot.plugins.reversing import ReversingPlugin


def make_minimal_elf_with_text(code: bytes) -> bytes:
    data = bytearray(0x600)
    data[0:4] = b"\x7fELF"
    data[4] = 2
    data[5] = 1
    data[6] = 1
    e_shoff = 0x200
    e_shentsize = 64
    e_shnum = 3
    e_shstrndx = 2
    struct.pack_into("<HHIQQQIHHHHHH", data, 0x10, 2, 0x3E, 1, 0x401000, 0, e_shoff, 0, 64, 0, 0, e_shentsize, e_shnum, e_shstrndx)
    text_off = 0x100
    data[text_off : text_off + len(code)] = code
    shstr = b"\x00.text\x00.shstrtab\x00"
    shstr_off = 0x300
    data[shstr_off : shstr_off + len(shstr)] = shstr
    struct.pack_into("<IIQQQQIIQQ", data, e_shoff + 64, 1, 1, 6, 0x401000, text_off, len(code), 0, 0, 16, 0)
    struct.pack_into("<IIQQQQIIQQ", data, e_shoff + 128, 7, 3, 0, 0, shstr_off, len(shstr), 0, 0, 1, 0)
    return bytes(data)


class LinuxGenericFileTests(unittest.TestCase):
    def values(self, findings):
        return {finding.value for finding in findings if finding.value}

    def titles(self, findings):
        return {finding.title for finding in findings}

    def test_extensionless_script_file(self):
        data = b"#!/bin/sh\nSECRET_FLAG=FLAG{script_without_extension}\nTOKEN=abc123\n"
        findings = SolverEngine(prompt="forensics linux script").analyze([Target("runme", data)])
        self.assertIn("FLAG{script_without_extension}", self.values(findings))
        self.assertIn("script/shebang file", self.titles(findings))
        self.assertIn("interesting key-value", self.titles(findings))

    def test_linux_elf_stack_xor_flag(self):
        encoded = bytes(byte ^ 0x13 for byte in b"FLAG{linux_elf_xor}")
        code = (
            b"\xc7\x44\x24\x20" + encoded[0:4]
            + b"\xc7\x44\x24\x24" + encoded[4:8]
            + b"\xc7\x44\x24\x28" + encoded[8:12]
            + b"\xc7\x44\x24\x2c" + encoded[12:16]
            + b"\x66\xc7\x44\x24\x30" + encoded[16:18]
            + b"\xc6\x44\x24\x32" + encoded[18:19]
            + b"\x34\x13"
        )
        elf = make_minimal_elf_with_text(code)
        findings = SolverEngine(prompt="linux reversing elf").analyze([Target("challenge", elf)])
        self.assertIn("FLAG{linux_elf_xor}", self.values(findings))
        self.assertIn("ELF binary", self.titles(findings))
        self.assertIn("stack XOR string flag", self.titles(findings))

    def test_extensionless_elf_custom_sha256_generated_flag(self):
        plugin = ReversingPlugin()
        message = b"I will evolve into SUPER FLAG!!!!"
        constants = bytes((idx * 37 + 0xA8) & 0xFF for idx in range(256))
        k_words = [struct.unpack_from("<I", constants, idx * 4)[0] for idx in range(64)]
        expected = "DH{" + plugin._sha256_variant(message, k_words).hex() + "}"
        data = bytearray(b"\x7fELF" + b"\x00" * 0x7C)
        for value in (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A):
            data.extend(struct.pack("<I", value))
        data.extend(b"\x00" * (0x100 - len(data)))
        data.extend(b"Here's your flag: DH{\x00%02x\x00}\x00")
        data.extend(message + b"\x00")
        data.extend(b"\x00" * (0x180 - len(data)))
        data.extend(constants)
        findings = SolverEngine(prompt="reversing linux elf DH{} sha256").analyze([Target("prob", bytes(data))])
        self.assertIn(expected, self.values(findings))
        self.assertIn("custom SHA-256 generated flag candidate", self.titles(findings))

    def test_extensionless_elf_stack_printf_transform_flag(self):
        code = bytes.fromhex(
            "48 b8 6c 39 4c 36 39 2c 6c 38 "
            "48 ba 39 4c 4c ac 38 33 38 30 "
            "48 b8 34 cc cc 4c 35 30 33 35 "
            "c7 45 a8 ac 37 6c cc "
            "90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 "
            "90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 "
            "90 90 90 90 90 90 90 90 90 90 90 90 "
            "48 b8 35 13 0b 33 38 38 32 1b "
            "48 ba 33 23 1b 36 23 23 33 0b "
            "48 b8 13 0b 37 38 0b 1b 39 23 "
            "48 ba 33 35 33 39 34 35 38 33 "
            "c7 45 80 36 39 2b 38"
        )
        data = bytearray(make_minimal_elf_with_text(code))
        data.extend(b"\x00DH{%s}\x00")
        findings = SolverEngine(prompt="reversing linux elf DH{} stack transform").analyze([Target("chall", bytes(data))])
        self.assertIn(
            "DH{c8b48ac08bbe00068ffb6606e2cf6ba0002c0dc4dd0aba20ac8d0608860048e0}",
            self.values(findings),
        )
        self.assertIn("stack transform printf flag candidate (combined blocks)", self.titles(findings))

    def test_extensionless_elf_cyclic_bit_inverse_flag(self):
        constant = int("c3467a32b5eefd28b5ebfe10bc1f80fb5ccdffaf09fbf982b8a86053dd11d706", 16)
        modulus = (1 << 256) - 1
        self.assertEqual(math.gcd(constant, modulus), 1)
        inverse = pow(constant, -1, modulus)
        expected_hex = "".join(f"{(inverse >> (4 * idx)) & 0xF:x}" for idx in range(64))
        bits = [(constant >> idx) & 1 for idx in range(256)]
        data = bytearray(b"\x7fELF" + b"\x00" * 0x100)
        data.extend(b"Give me your input: \x00%64s\x00Correct! Flag is DH{%s}\x00Wrong :(\x00")
        data.extend(b"\x00" * ((4 - len(data) % 4) % 4))
        data.extend(b"".join(struct.pack("<I", bit) for bit in bits))
        findings = SolverEngine(prompt="reversing linux elf DH{} cyclic inverse").analyze([Target("main", bytes(data))])
        self.assertIn("DH{" + expected_hex + "}", self.values(findings))
        self.assertIn("cyclic bit inverse flag candidate", self.titles(findings))


if __name__ == "__main__":
    unittest.main()
