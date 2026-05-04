from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ctfbot.engine import SolverEngine
from ctfbot.models import Target


OUT_DIR = ROOT / "samples" / "reversing_fixtures" / "generated"
REPORT_PATH = ROOT / "samples" / "reversing_fixtures" / "accuracy_report.json"


def wide(text: str) -> bytes:
    return text.encode("utf-16le")


def xor(text: str, key: int) -> bytes:
    return bytes(byte ^ key for byte in text.encode("ascii"))


CASES = [
    {
        "name": "rev_ascii.exe",
        "prompt": "reversing flag format: REV{} password",
        "expected_values": ["REV{plain_string_flag}"],
        "expected_titles": ["program prompt strings", "PE binary"],
        "data": b"MZ\x90\x00" + b"\x00" * 64 + b"Enter password:\x00Wrong password!\x00REV{plain_string_flag}\x00",
    },
    {
        "name": "rev_wide.exe",
        "prompt": "reversing flag format: REV{}",
        "expected_values": ["REV{wide_string_flag}"],
        "expected_titles": ["PE binary"],
        "data": b"MZ\x90\x00" + b"\x00" * 32 + wide("Correct! REV{wide_string_flag}"),
    },
    {
        "name": "rev_xor.exe",
        "prompt": "reversing xor encoded string",
        "expected_values": ["flag{xor_hidden_reverse}"],
        "expected_titles": ["PE binary"],
        "data": b"MZ" + b"\x00" * 16 + xor("flag{xor_hidden_reverse}", 0x37),
    },
    {
        "name": "rev_custom_xor.exe",
        "prompt": "reversing xor flag format: REV{}",
        "expected_values": ["REV{custom_xor_reverse}"],
        "expected_titles": ["PE binary"],
        "data": b"MZ" + b"\x00" * 16 + xor("REV{custom_xor_reverse}", 0x21),
    },
    {
        "name": "rev_packed.exe",
        "prompt": "reversing packed windows binary",
        "expected_values": [],
        "expected_titles": ["packer hint", "pwn/reversing API hints", "program prompt strings"],
        "data": b"MZUPX0\x00UPX1\x00CreateProcess\x00WinExec\x00scanf\x00license serial wrong\x00",
    },
    {
        "name": "pwn_elf.bin",
        "prompt": "pwn reversing",
        "expected_values": [],
        "expected_titles": ["ELF binary", "pwn/reversing API hints"],
        "data": b"\x7fELF" + b"\x00" * 32 + b"gets\x00system\x00Enter input:\x00",
    },
]


def evaluate_case(case: dict[str, object]) -> dict[str, object]:
    path = OUT_DIR / str(case["name"])
    data = case["data"]
    assert isinstance(data, bytes)
    path.write_bytes(data)

    prompt = str(case["prompt"])
    findings = SolverEngine(prompt=prompt).analyze([Target(str(path), data, path)])
    values = {finding.value for finding in findings if finding.value}
    titles = {finding.title for finding in findings}
    expected_values = set(case["expected_values"])
    expected_titles = set(case["expected_titles"])
    missing_values = sorted(expected_values - values)
    missing_titles = sorted(expected_titles - titles)
    passed = not missing_values and not missing_titles
    return {
        "name": case["name"],
        "prompt": prompt,
        "passed": passed,
        "missing_values": missing_values,
        "missing_titles": missing_titles,
        "top_findings": [finding.as_dict() for finding in findings[:5]],
    }


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    results = [evaluate_case(case) for case in CASES]
    passed = sum(1 for result in results if result["passed"])
    report = {
        "total": len(results),
        "passed": passed,
        "accuracy": passed / len(results),
        "results": results,
    }
    REPORT_PATH.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Reversing fixture accuracy: {passed}/{len(results)} ({report['accuracy']:.0%})")
    print(f"Report: {REPORT_PATH}")
    for result in results:
        status = "PASS" if result["passed"] else "FAIL"
        print(f"- {status} {result['name']}")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
