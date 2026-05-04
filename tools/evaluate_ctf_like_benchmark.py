from __future__ import annotations

import base64
import io
import json
import sys
import zipfile
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ctfbot.engine import SolverEngine
from ctfbot.models import Target


OUT_DIR = ROOT / "samples" / "ctf_like_benchmark" / "generated"
REPORT_PATH = ROOT / "samples" / "ctf_like_benchmark" / "benchmark_report.json"


def make_zip(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def xor(text: str, key: int) -> bytes:
    return bytes(byte ^ key for byte in text.encode("ascii"))


def wide(text: str) -> bytes:
    return text.encode("utf-16le")


def rot_input(plain: str, shift: int) -> bytes:
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    trans = str.maketrans(
        alphabet + alphabet.upper(),
        alphabet[-shift:] + alphabet[:-shift] + alphabet[-shift:].upper() + alphabet[:-shift].upper(),
    )
    return plain.translate(trans).encode("ascii")


def jwt_none(flag: str) -> bytes:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode().rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps({"role": "admin", "flag": flag}).encode()).decode().rstrip("=")
    return f"<script>localStorage.token='{header}.{payload}.'</script>".encode()


inner_zip = make_zip({"deep/flag.txt": b"FORENSICS{nested_zip_flag}"})
png_appended_zip = b"\x89PNG\r\n\x1a\n" + b"\x00" * 40 + make_zip({"secret.txt": b"FORENSICS{png_appended_zip}"})


CASES = [
    # Crypto
    {
        "category": "crypto",
        "name": "crypto_base64.txt",
        "prompt": "crypto base64",
        "data": base64.b64encode(b"flag{ctf_like_base64}"),
        "expected_values": ["flag{ctf_like_base64}"],
        "expected_titles": ["base64 decode"],
    },
    {
        "category": "crypto",
        "name": "crypto_hex.txt",
        "prompt": "crypto hex flag format: CRYPTO{}",
        "data": b"CRYPTO{hex_ctf_like}".hex().encode(),
        "expected_values": ["CRYPTO{hex_ctf_like}"],
        "expected_titles": ["hex decode"],
    },
    {
        "category": "crypto",
        "name": "crypto_rot13.txt",
        "prompt": "crypto caesar rot",
        "data": rot_input("flag{rot13_ctf_like}", 13),
        "expected_values": ["flag{rot13_ctf_like}"],
        "expected_titles": ["ROT13 candidate"],
    },
    {
        "category": "crypto",
        "name": "crypto_xor.bin",
        "prompt": "crypto xor",
        "data": xor("flag{x0r_ctf_like}", 0x52),
        "expected_values": ["flag{x0r_ctf_like}"],
        "expected_titles": ["single-byte XOR candidate"],
    },
    {
        "category": "crypto",
        "name": "crypto_hash.txt",
        "prompt": "crypto hash md5",
        "data": b"5d41402abc4b2a76b9719d911017c592",
        "expected_values": [],
        "expected_titles": ["hash-shaped value"],
    },
    # Web
    {
        "category": "web",
        "name": "web_comment.html",
        "prompt": "web flag format: WEB{} hidden route",
        "data": b"<html><!-- admin route /console WEB{comment_route_flag} --><a href='/console'>x</a></html>",
        "expected_values": ["WEB{comment_route_flag}"],
        "expected_titles": ["comments", "interesting paths"],
    },
    {
        "category": "web",
        "name": "web_jwt.html",
        "prompt": "web jwt flag format: WEB{}",
        "data": jwt_none("WEB{jwt_ctf_like}"),
        "expected_values": ["WEB{jwt_ctf_like}"],
        "expected_titles": ["JWT token", "JWT alg none hint", "flag inside JWT"],
    },
    {
        "category": "web",
        "name": "web_static_hints.txt",
        "prompt": "web sqli xss source map robots",
        "data": b"User-agent: *\nDisallow: /admin\n//# sourceMappingURL=app.js.map\n?id=' union select password\n<script>alert(1)</script>",
        "expected_values": [],
        "expected_titles": ["robots.txt hint", "source map hint", "web keyword: union select", "web keyword: xss"],
    },
    {
        "category": "web",
        "name": "web_js_encoded.html",
        "prompt": "web javascript base64 flag format: WEB{}",
        "data": b"<script>const secret='"
        + base64.b64encode(b"WEB{js_base64_secret}")
        + b"'; fetch('/api/debug')</script>",
        "expected_values": ["WEB{js_base64_secret}"],
        "expected_titles": ["decoded base64 string", "interesting paths"],
    },
    {
        "category": "web",
        "name": "web_artifacts.html",
        "prompt": "web backup graphql ssti",
        "data": b"backup: /index.php.bak\nquery { __schema { types { name } } }\nrender('{{7*7}}')",
        "expected_values": [],
        "expected_titles": ["backup file hint", "graphql hint", "ssti hint"],
    },
    # Forensics
    {
        "category": "forensics",
        "name": "forensics_zip.zip",
        "prompt": "forensics zip flag format: FORENSICS{}",
        "data": make_zip({"readme.txt": b"look deeper", "flag.txt": b"FORENSICS{zip_ctf_like}"}),
        "expected_values": ["FORENSICS{zip_ctf_like}"],
        "expected_titles": ["zip entries", "flag inside zip entry"],
    },
    {
        "category": "forensics",
        "name": "forensics_nested_zip.zip",
        "prompt": "forensics nested zip flag format: FORENSICS{}",
        "data": make_zip({"outer.txt": b"nested archive follows", "inner.zip": inner_zip}),
        "expected_values": ["FORENSICS{nested_zip_flag}"],
        "expected_titles": ["zip entries", "flag inside zip entry"],
    },
    {
        "category": "forensics",
        "name": "forensics_png.png",
        "prompt": "forensics png embedded zip flag format: FORENSICS{}",
        "data": png_appended_zip,
        "expected_values": ["FORENSICS{png_appended_zip}"],
        "expected_titles": ["embedded file signature", "flag inside embedded zip entry"],
    },
    {
        "category": "forensics",
        "name": "forensics_pdf.pdf",
        "prompt": "forensics pdf secret flag format: FORENSICS{}",
        "data": b"%PDF-1.7\n<< /Secret (FORENSICS{pdf_ctf_like}) >>\n%%EOF",
        "expected_values": ["FORENSICS{pdf_ctf_like}"],
        "expected_titles": ["file type", "interesting string: secret"],
    },
    {
        "category": "forensics",
        "name": "forensics_wide.bin",
        "prompt": "forensics unicode flag format: FORENSICS{}",
        "data": b"\x00\x01noise" + wide("FORENSICS{utf16_ctf_like}"),
        "expected_values": ["FORENSICS{utf16_ctf_like}"],
        "expected_titles": ["flag in strings"],
    },
    # Pwnable
    {
        "category": "pwn",
        "name": "pwn_ret2win.bin",
        "prompt": "pwn ret2win rop",
        "data": b"\x7fELF" + b"\x00" * 16 + b"gets\x00system\x00/bin/sh\x00ret2win\x00pop rdi; ret\x00Enter input:\x00",
        "expected_values": [],
        "expected_titles": ["ELF binary", "pwn dangerous functions", "pwn exploitation hints"],
    },
    {
        "category": "pwn",
        "name": "pwn_format.bin",
        "prompt": "pwn format string",
        "data": b"\x7fELF" + b"\x00" * 20 + b"printf(user_input)\x00%p %p %n\x00Enter format:\x00",
        "expected_values": [],
        "expected_titles": ["format string hints", "ELF binary"],
    },
    {
        "category": "pwn",
        "name": "pwn_shell.bin",
        "prompt": "pwn shell system",
        "data": b"\x7fELF" + b"\x00" * 20 + b"scanf\x00system\x00/bin/sh\x00mprotect\x00",
        "expected_values": [],
        "expected_titles": ["pwn dangerous functions", "pwn exploitation hints"],
    },
    {
        "category": "pwn",
        "name": "pwn_overflow.bin",
        "prompt": "pwn buffer overflow",
        "data": b"\x7fELF" + b"\x00" * 20 + b"strcpy\x00sprintf\x00Wrong password\x00",
        "expected_values": [],
        "expected_titles": ["pwn dangerous functions", "program prompt strings"],
    },
    {
        "category": "pwn",
        "name": "pwn_mmap.bin",
        "prompt": "pwn mmap rop",
        "data": b"\x7fELF" + b"\x00" * 20 + b"mmap\x00mprotect\x00ROP chain\x00",
        "expected_values": [],
        "expected_titles": ["pwn exploitation hints", "ELF binary"],
    },
    # Reversing
    {
        "category": "reversing",
        "name": "rev_plain.exe",
        "prompt": "reversing password flag format: REV{}",
        "data": b"MZ" + b"\x00" * 50 + b"Enter password:\x00REV{plain_rev_ctf}\x00Wrong password\x00",
        "expected_values": ["REV{plain_rev_ctf}"],
        "expected_titles": ["PE binary", "program prompt strings"],
    },
    {
        "category": "reversing",
        "name": "rev_wide.exe",
        "prompt": "reversing unicode flag format: REV{}",
        "data": b"MZ" + b"\x00" * 32 + wide("Correct REV{wide_rev_ctf}"),
        "expected_values": ["REV{wide_rev_ctf}"],
        "expected_titles": ["PE binary", "program prompt strings"],
    },
    {
        "category": "reversing",
        "name": "rev_xor.exe",
        "prompt": "reversing xor flag format: REV{}",
        "data": b"MZ" + b"\x00" * 24 + xor("REV{xor_rev_ctf}", 0x23),
        "expected_values": ["REV{xor_rev_ctf}"],
        "expected_titles": ["single-byte XOR candidate", "PE binary"],
    },
    {
        "category": "reversing",
        "name": "rev_packed.exe",
        "prompt": "reversing packed upx",
        "data": b"MZUPX0\x00UPX1\x00license\x00serial\x00CreateProcess\x00",
        "expected_values": [],
        "expected_titles": ["packer hint", "program prompt strings", "PE binary"],
    },
    {
        "category": "reversing",
        "name": "rev_api.exe",
        "prompt": "reversing windows imports",
        "data": b"MZ" + b"\x00" * 20 + b"WinExec\x00CreateProcess\x00Enter license:\x00",
        "expected_values": [],
        "expected_titles": ["pwn/reversing API hints", "program prompt strings", "PE binary"],
    },
]


def evaluate_case(case: dict[str, object]) -> dict[str, object]:
    category_dir = OUT_DIR / str(case["category"])
    category_dir.mkdir(parents=True, exist_ok=True)
    path = category_dir / str(case["name"])
    data = case["data"]
    assert isinstance(data, bytes)
    path.write_bytes(data)

    findings = SolverEngine(prompt=str(case["prompt"])).analyze([Target(str(path), data, path)])
    values = [finding.value for finding in findings if finding.value]
    titles = [finding.title for finding in findings]
    missing_values = sorted(set(case["expected_values"]) - set(values))
    missing_titles = sorted(set(case["expected_titles"]) - set(titles))
    flag_ranks = {
        value: next((idx + 1 for idx, finding in enumerate(findings) if finding.value == value), None)
        for value in case["expected_values"]
    }
    return {
        "category": case["category"],
        "name": case["name"],
        "prompt": case["prompt"],
        "passed": not missing_values and not missing_titles,
        "missing_values": missing_values,
        "missing_titles": missing_titles,
        "flag_ranks": flag_ranks,
        "top_findings": [finding.as_dict() for finding in findings[:8]],
    }


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    results = [evaluate_case(case) for case in CASES]
    by_category: dict[str, list[dict[str, object]]] = defaultdict(list)
    for result in results:
        by_category[str(result["category"])].append(result)

    category_scores = {}
    for category, items in sorted(by_category.items()):
        passed = sum(1 for item in items if item["passed"])
        category_scores[category] = {
            "passed": passed,
            "total": len(items),
            "accuracy": passed / len(items),
        }

    passed_total = sum(1 for result in results if result["passed"])
    report = {
        "benchmark": "synthetic_ctf_like_v1",
        "total": len(results),
        "passed": passed_total,
        "accuracy": passed_total / len(results),
        "category_scores": category_scores,
        "results": results,
    }
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"CTF-like benchmark: {passed_total}/{len(results)} ({report['accuracy']:.0%})")
    for category, score in category_scores.items():
        print(f"- {category}: {score['passed']}/{score['total']} ({score['accuracy']:.0%})")
    print(f"Report: {REPORT_PATH}")
    failures = [result for result in results if not result["passed"]]
    if failures:
        print("Failures:")
        for failure in failures:
            print(f"- {failure['category']}/{failure['name']}: values={failure['missing_values']} titles={failure['missing_titles']}")
    return 0 if passed_total == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
