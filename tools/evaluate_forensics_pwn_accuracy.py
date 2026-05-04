from __future__ import annotations

import io
import json
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ctfbot.engine import SolverEngine
from ctfbot.models import Target


OUT_DIR = ROOT / "samples" / "forensics_pwn_fixtures" / "generated"
REPORT_PATH = ROOT / "samples" / "forensics_pwn_fixtures" / "accuracy_report.json"


def make_zip(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return buffer.getvalue()


CASES = [
    {
        "name": "archive.zip",
        "prompt": "forensics flag format: FORENSICS{} zip hidden",
        "expected_values": ["FORENSICS{zip_entry_flag}"],
        "expected_titles": ["zip entries", "flag inside zip entry"],
        "data": make_zip({"notes.txt": b"nothing", "hidden/flag.txt": b"FORENSICS{zip_entry_flag}"}),
    },
    {
        "name": "image.png",
        "prompt": "forensics png secret flag format: FORENSICS{}",
        "expected_values": ["FORENSICS{png_text_flag}"],
        "expected_titles": ["file type", "embedded file signature"],
        "data": b"\x89PNG\r\n\x1a\n"
        + b"\x00" * 24
        + b"tEXtsecret=FORENSICS{png_text_flag}"
        + b"\x00" * 8
        + make_zip({"a.txt": b"x"}),
    },
    {
        "name": "doc.pdf",
        "prompt": "forensics pdf hidden flag format: FORENSICS{}",
        "expected_values": ["FORENSICS{pdf_hidden_token}"],
        "expected_titles": ["interesting string: secret"],
        "data": b"%PDF-1.7\n1 0 obj\n<< /Secret (FORENSICS{pdf_hidden_token}) >>\nendobj\n%%EOF",
    },
    {
        "name": "pwn_rop.bin",
        "prompt": "pwn ret2win rop",
        "expected_values": [],
        "expected_titles": ["ELF binary", "pwn dangerous functions", "pwn exploitation hints"],
        "data": b"\x7fELF"
        + b"\x00" * 16
        + b"gets\x00system\x00/bin/sh\x00ret2win\x00pop rdi; ret\x00Enter input:\x00",
    },
    {
        "name": "format_string.bin",
        "prompt": "pwn format string",
        "expected_values": [],
        "expected_titles": ["format string hints", "ELF binary"],
        "data": b"\x7fELF" + b"\x00" * 20 + b"printf(user_input)\x00%p %p %n\x00Enter format:\x00",
    },
]


def evaluate_case(case: dict[str, object]) -> dict[str, object]:
    path = OUT_DIR / str(case["name"])
    data = case["data"]
    assert isinstance(data, bytes)
    path.write_bytes(data)

    findings = SolverEngine(prompt=str(case["prompt"])).analyze([Target(str(path), data, path)])
    values = {finding.value for finding in findings if finding.value}
    titles = {finding.title for finding in findings}
    expected_values = set(case["expected_values"])
    expected_titles = set(case["expected_titles"])
    missing_values = sorted(expected_values - values)
    missing_titles = sorted(expected_titles - titles)
    return {
        "name": case["name"],
        "prompt": case["prompt"],
        "passed": not missing_values and not missing_titles,
        "missing_values": missing_values,
        "missing_titles": missing_titles,
        "top_findings": [finding.as_dict() for finding in findings[:6]],
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
    print(f"Forensics/Pwn fixture accuracy: {passed}/{len(results)} ({report['accuracy']:.0%})")
    print(f"Report: {REPORT_PATH}")
    for result in results:
        status = "PASS" if result["passed"] else "FAIL"
        print(f"- {status} {result['name']}")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
