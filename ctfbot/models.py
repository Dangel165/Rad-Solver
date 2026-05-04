from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(order=True)
class Finding:
    score: float
    title: str = field(compare=False)
    category: str = field(compare=False)
    detail: str = field(compare=False)
    source: str = field(default="", compare=False)
    value: str | None = field(default=None, compare=False)
    metadata: dict[str, Any] = field(default_factory=dict, compare=False)

    def as_dict(self) -> dict[str, Any]:
        return {
            "score": round(self.score, 3),
            "category": self.category,
            "title": self.title,
            "detail": self.detail,
            "source": self.source,
            "value": self.value,
            "metadata": self.metadata,
        }


@dataclass
class Target:
    label: str
    data: bytes
    path: Path | None = None

    @property
    def text(self) -> str:
        return self.data.decode("utf-8", errors="ignore")


@dataclass
class PromptContext:
    raw: str = ""
    categories: set[str] = field(default_factory=set)
    keywords: set[str] = field(default_factory=set)
    flag_patterns: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "raw": self.raw,
            "categories": sorted(self.categories),
            "keywords": sorted(self.keywords),
            "flag_patterns": self.flag_patterns,
        }


class Plugin:
    name = "base"
    category = "misc"

    def analyze(self, target: Target, flag_patterns: list[str]) -> list[Finding]:
        raise NotImplementedError
