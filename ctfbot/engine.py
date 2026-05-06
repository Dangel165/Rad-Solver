from __future__ import annotations

from collections import defaultdict
import re

from .feedback import load_feedback
from .models import Finding, PromptContext, Target
from .plugins import ALL_PLUGINS
from .utils import DEFAULT_FLAG_PATTERNS, parse_prompt_context
from .default_prompt import DEFAULT_ANALYSIS_PROMPT


class SolverEngine:
    def __init__(self, flag_patterns: list[str] | None = None, prompt: str = "") -> None:
        if not prompt:
            prompt = DEFAULT_ANALYSIS_PROMPT
        self.prompt_context = parse_prompt_context(prompt)
        self.flag_patterns = (flag_patterns or DEFAULT_FLAG_PATTERNS) + self.prompt_context.flag_patterns
        self.plugins = ALL_PLUGINS
        self.feedback = load_feedback()

    def analyze(self, targets: list[Target]) -> list[Finding]:
        findings: list[Finding] = []
        for target in targets:
            for plugin in self.plugins:
                try:
                    findings.extend(plugin.analyze(target, self.flag_patterns))
                except Exception as exc:  # pragma: no cover - defensive plugin isolation
                    findings.append(
                        Finding(
                            score=1.0,
                            title=f"{plugin.name} failed",
                            category=plugin.category,
                            detail=str(exc),
                            source=target.label,
                        )
                    )
        return self._rank(findings, self.prompt_context)

    def _rank(self, findings: list[Finding], prompt_context: PromptContext) -> list[Finding]:
        value_counts: dict[str, int] = defaultdict(int)
        for finding in findings:
            if finding.value:
                value_counts[finding.value] += 1
        for finding in findings:
            if finding.value and value_counts[finding.value] > 1:
                finding.score += min(12.0, 4.0 * (value_counts[finding.value] - 1))
            if finding.value:
                self._apply_format_boost(finding, prompt_context)
                self._apply_feedback_boost(finding)
            if finding.category in prompt_context.categories:
                finding.score += 10.0
                finding.metadata["prompt_boost"] = "category"
            detail_words = finding.detail.lower() + " " + finding.title.lower()
            keyword_hits = sorted(word for word in prompt_context.keywords if word.lower() in detail_words)
            if keyword_hits:
                finding.score += min(15.0, 3.0 * len(keyword_hits))
                finding.metadata["prompt_keywords"] = keyword_hits[:8]
        return sorted(findings, reverse=True)

    def _apply_format_boost(self, finding: Finding, prompt_context: PromptContext) -> None:
        value = finding.value or ""
        preferred_prefixes = self._preferred_prefixes(prompt_context)
        value_prefix = self._value_prefix(value)
        if not value_prefix:
            return
        if preferred_prefixes:
            preferred_lower = {prefix.lower() for prefix in preferred_prefixes}
            if value_prefix.lower() in preferred_lower:
                finding.score += 24.0
                finding.metadata["format_boost"] = value_prefix
            elif value_prefix.lower() in {"flag", "ctf", "dh", "flag", "ctf"}:
                finding.score -= 8.0
                finding.metadata["format_penalty"] = value_prefix
            return
        if value_prefix == "flag":
            finding.score += 10.0
            finding.metadata["format_boost"] = "default_flag"
        elif value_prefix in {"ctf", "dh", "FLAG", "CTF", "DH"}:
            finding.score -= 4.0
            finding.metadata["format_penalty"] = "fallback_wrapper"

    def _apply_feedback_boost(self, finding: Finding) -> None:
        value = finding.value or ""
        correct_values = self.feedback.get("correct_values", {})
        wrong_values = self.feedback.get("wrong_values", {})
        correct_titles = self.feedback.get("correct_titles", {})
        wrong_titles = self.feedback.get("wrong_titles", {})
        if isinstance(correct_values, dict) and value in correct_values:
            finding.score += min(60.0, 30.0 * int(correct_values[value]))
            finding.metadata["feedback"] = "marked_correct"
        if isinstance(wrong_values, dict) and value in wrong_values:
            finding.score -= min(80.0, 35.0 * int(wrong_values[value]))
            finding.metadata["feedback"] = "marked_wrong"
        if isinstance(correct_titles, dict) and finding.title in correct_titles:
            finding.score += min(18.0, 6.0 * int(correct_titles[finding.title]))
        if isinstance(wrong_titles, dict) and finding.title in wrong_titles:
            finding.score -= min(24.0, 8.0 * int(wrong_titles[finding.title]))

    def _preferred_prefixes(self, prompt_context: PromptContext) -> list[str]:
        prefixes: list[str] = []
        for text in [prompt_context.raw, *prompt_context.flag_patterns]:
            for match in re.finditer(r"\b([A-Za-z0-9_]{2,32})\{", text):
                prefix = match.group(1)
                if prefix.lower() in {"bflag", "bctf"}:
                    prefix = prefix[1:]
                if prefix not in prefixes and not any(char in prefix for char in "[]().?+*|"):
                    prefixes.append(prefix)
        return prefixes

    def _value_prefix(self, value: str) -> str | None:
        match = re.match(r"^([A-Za-z0-9_]{2,32})\{", value)
        return match.group(1) if match else None
