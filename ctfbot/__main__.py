from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .default_prompt import DEFAULT_ANALYSIS_PROMPT
from .engine import SolverEngine
from .models import Target
from .utils import DEFAULT_FLAG_PATTERNS, read_targets


def safe_print(text: str = "") -> None:
    encoding = sys.stdout.encoding or "utf-8"
    sys.stdout.write(text.encode(encoding, errors="backslashreplace").decode(encoding) + "\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rad_solver",
        description="Local CTF auto-solver and triage bot.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    for name in ("scan", "solve"):
        cmd = sub.add_parser(name, help=f"{name} a file, folder, or inline text")
        cmd.add_argument("--input", "-i", required=True, help="File path, directory path, or inline challenge text")
        cmd.add_argument(
            "--flag-format",
            action="append",
            default=[],
            help="Extra regex for the CTF flag format. Can be repeated.",
        )
        cmd.add_argument("--top", type=int, default=25, help="Number of findings to print")
        cmd.add_argument("--json", type=Path, help="Write full report as JSON")
        cmd.add_argument("--prompt", default="", help="Challenge description or solving hint to improve ranking")
        cmd.add_argument("--prompt-file", type=Path, help="Read challenge prompt/hints from a text file")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    raw_targets = read_targets(args.input)
    targets = [Target(label=label, data=data, path=path) for label, data, path in raw_targets]
    prompt = args.prompt or DEFAULT_ANALYSIS_PROMPT
    if args.prompt_file:
        prompt = args.prompt_file.read_text(encoding="utf-8", errors="ignore") + "\n" + prompt
    patterns = DEFAULT_FLAG_PATTERNS + args.flag_format
    engine = SolverEngine(flag_patterns=patterns, prompt=prompt)
    findings = engine.analyze(targets)

    report = {
        "version": __version__,
        "targets": [target.label for target in targets],
        "patterns": patterns,
        "prompt_context": engine.prompt_context.as_dict(),
        "findings": [finding.as_dict() for finding in findings],
    }

    if args.json:
        args.json.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    safe_print(f"Rad Solver v{__version__}")
    safe_print(f"Targets: {len(targets)} | Findings: {len(findings)}")
    safe_print()
    for finding in findings[: args.top]:
        value = f" | value={finding.value}" if finding.value else ""
        safe_print(f"[{finding.score:05.1f}] {finding.category}/{finding.title}{value}")
        safe_print(f"  source: {finding.source}")
        safe_print(f"  detail: {finding.detail}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
