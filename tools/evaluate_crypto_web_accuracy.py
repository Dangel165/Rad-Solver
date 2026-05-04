from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ctfbot.engine import SolverEngine
from ctfbot.models import Target


OUT_DIR = ROOT / "samples" / "crypto_web_fixtures" / "generated"
REPORT_PATH = ROOT / "samples" / "crypto_web_fixtures" / "accuracy_report.json"


def jwt_none() -> bytes:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode().rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps({"role": "admin", "flag": "WEB{jwt_none_flag}"}).encode()).decode().rstrip("=")
    return f"<script>localStorage.token='{header}.{payload}.'</script>".encode()


def rot_input(plain: str, shift: int) -> bytes:
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    trans = str.maketrans(
        alphabet + alphabet.upper(),
        alphabet[-shift:] + alphabet[:-shift] + alphabet[-shift:].upper() + alphabet[:-shift].upper(),
    )
    return plain.translate(trans).encode("ascii")


CASES = [
    {
        "name": "base64.txt",
        "prompt": "crypto base64",
        "expected_values": ["flag{base64_crypto}"],
        "expected_titles": ["base64 decode"],
        "data": base64.b64encode(b"flag{base64_crypto}"),
    },
    {
        "name": "base32.txt",
        "prompt": "crypto base32",
        "expected_values": ["flag{base32_crypto}"],
        "expected_titles": ["base32 decode"],
        "data": base64.b32encode(b"flag{base32_crypto}"),
    },
    {
        "name": "rot13.txt",
        "prompt": "crypto rot",
        "expected_values": ["flag{rot_crypto}"],
        "expected_titles": ["ROT13 candidate"],
        "data": rot_input("flag{rot_crypto}", 13),
    },
    {
        "name": "jwt.html",
        "prompt": "web jwt flag format: WEB{}",
        "expected_values": ["WEB{jwt_none_flag}"],
        "expected_titles": ["JWT token", "JWT alg none hint", "flag inside JWT"],
        "data": jwt_none(),
    },
    {
        "name": "index.html",
        "prompt": "web flag format: WEB{}",
        "expected_values": ["WEB{comment_flag}"],
        "expected_titles": ["comments", "interesting paths"],
        "data": b"<html><!-- admin /hidden WEB{comment_flag} --><script src='/static/app.js'></script></html>",
    },
    {
        "name": "robots.txt",
        "prompt": "web sqli xss",
        "expected_values": [],
        "expected_titles": ["robots.txt hint", "source map hint", "web keyword: union select", "web keyword: xss"],
        "data": b"User-agent: *\nDisallow: /admin\n//# sourceMappingURL=app.js.map\n?id=' union select password\n<script>alert(1)</script>",
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
    print(f"Crypto/Web fixture accuracy: {passed}/{len(results)} ({report['accuracy']:.0%})")
    print(f"Report: {REPORT_PATH}")
    for result in results:
        status = "PASS" if result["passed"] else "FAIL"
        print(f"- {status} {result['name']}")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
