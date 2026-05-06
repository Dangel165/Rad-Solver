from __future__ import annotations

import json
from pathlib import Path
from typing import Any


FEEDBACK_PATH = Path(__file__).resolve().parent.parent / "candidate_feedback.json"


def load_feedback(path: Path = FEEDBACK_PATH) -> dict[str, Any]:
    try:
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
    except (OSError, json.JSONDecodeError):
        pass
    return {"correct_values": {}, "wrong_values": {}, "correct_titles": {}, "wrong_titles": {}}


def save_feedback(feedback: dict[str, Any], path: Path = FEEDBACK_PATH) -> None:
    path.write_text(json.dumps(feedback, indent=2, ensure_ascii=False), encoding="utf-8")


def record_feedback(value: str, title: str, correct: bool, path: Path = FEEDBACK_PATH) -> None:
    feedback = load_feedback(path)
    value_key = "correct_values" if correct else "wrong_values"
    title_key = "correct_titles" if correct else "wrong_titles"
    _increment(feedback, value_key, value)
    if title:
        _increment(feedback, title_key, title)
    save_feedback(feedback, path)


def _increment(feedback: dict[str, Any], section: str, key: str) -> None:
    values = feedback.setdefault(section, {})
    if not isinstance(values, dict):
        values = {}
        feedback[section] = values
    values[key] = int(values.get(key, 0)) + 1
