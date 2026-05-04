from __future__ import annotations

from collections import defaultdict

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
            if finding.category in prompt_context.categories:
                finding.score += 10.0
                finding.metadata["prompt_boost"] = "category"
            detail_words = finding.detail.lower() + " " + finding.title.lower()
            keyword_hits = sorted(word for word in prompt_context.keywords if word.lower() in detail_words)
            if keyword_hits:
                finding.score += min(15.0, 3.0 * len(keyword_hits))
                finding.metadata["prompt_keywords"] = keyword_hits[:8]
        return sorted(findings, reverse=True)
