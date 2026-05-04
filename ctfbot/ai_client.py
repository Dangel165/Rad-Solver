from __future__ import annotations

import json
import urllib.error
import urllib.request


OPENAI_RESPONSES_URL = "https://api.openai.com/v1/responses"
OPENAI_CHAT_COMPLETIONS_URL = "https://api.openai.com/v1/chat/completions"
ANTHROPIC_MESSAGES_URL = "https://api.anthropic.com/v1/messages"
GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta"
OLLAMA_CHAT_URL = "http://localhost:11434/api/chat"


def build_ai_prompt(report: dict[str, object], user_prompt: str) -> str:
    findings = report.get("findings", [])
    if not isinstance(findings, list):
        findings = []
    compact_findings = []
    for finding in findings[:20]:
        if isinstance(finding, dict):
            compact_findings.append(
                {
                    "score": finding.get("score"),
                    "category": finding.get("category"),
                    "title": finding.get("title"),
                    "value": finding.get("value"),
                    "detail": finding.get("detail"),
                    "source": finding.get("source"),
                }
            )
    payload = {
        "targets": report.get("targets", []),
        "prompt_context": report.get("prompt_context", {}),
        "top_findings": compact_findings,
        "user_prompt": user_prompt.strip(),
    }
    return (
        "You are assisting with an authorized CTF/wargame challenge. "
        "Use only the provided local analysis results. Do not suggest attacking real third-party systems. "
        "Return a detailed Korean write-up. Include these sections exactly when possible:\n"
        "1. 최종 플래그: put the most likely final flag first. If uncertain, rank candidates and say why.\n"
        "2. 핵심 근거: cite the highest-signal findings, offsets, decoded strings, formulas, constants, or file artifacts.\n"
        "3. 풀이 과정: explain step by step how the result was derived from the binary/file/challenge data.\n"
        "4. 검증 방법: describe how to locally verify the candidate, such as rerunning the program, checking the comparison, or recomputing a hash.\n"
        "5. 주의점: mention false positives, format issues, or remaining uncertainty if any.\n"
        "Do not stop at a vague summary. Prefer concrete values, formulas, and offsets from the report.\n\n"
        + json.dumps(payload, ensure_ascii=False, indent=2)
    )


def ask_openai(
    api_key: str,
    model: str,
    report: dict[str, object],
    user_prompt: str,
    provider: str = "openai",
    api_mode: str = "responses",
    base_url: str = "",
) -> str:
    provider = provider.strip().lower()
    if provider != "ollama" and not api_key.strip():
        raise ValueError("API key is empty. Enter a key in the GUI, or use Ollama for local no-key mode.")
    if not model.strip():
        raise ValueError("Model is empty.")

    if provider == "anthropic":
        return _ask_anthropic(api_key, model, report, user_prompt, base_url)
    if provider == "gemini":
        return _ask_gemini(api_key, model, report, user_prompt, base_url)
    if provider == "ollama":
        return _ask_ollama(api_key, model, report, user_prompt, base_url)
    if api_mode == "chat_completions":
        return _ask_chat_completions(api_key, model, report, user_prompt, base_url)
    return _ask_responses(api_key, model, report, user_prompt, base_url)


def _request_json(
    url: str,
    api_key: str,
    body: dict[str, object],
    headers: dict[str, str] | None = None,
) -> dict[str, object]:
    request_headers = {"Content-Type": "application/json"}
    if api_key.strip():
        request_headers["Authorization"] = f"Bearer {api_key.strip()}"
    if headers:
        request_headers.update(headers)
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers=request_headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        message = exc.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"AI API error {exc.code}: {message}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Network error while calling AI API: {exc}") from exc


def _join_base_url(base_url: str, default_url: str, suffix: str) -> str:
    clean = base_url.strip().rstrip("/")
    if not clean:
        return default_url
    if clean.endswith(suffix):
        return clean
    if clean.endswith("/v1"):
        return clean + suffix
    return clean + "/v1" + suffix


def _ask_responses(api_key: str, model: str, report: dict[str, object], user_prompt: str, base_url: str) -> str:
    body = {
        "model": model.strip(),
        "instructions": (
            "You are a careful CTF write-up assistant. Keep answers legal, local, and challenge-focused. "
            "Explain the final flag and the solving process in Korean with concrete evidence."
        ),
        "input": build_ai_prompt(report, user_prompt),
        "max_output_tokens": 900,
    }
    data = _request_json(_join_base_url(base_url, OPENAI_RESPONSES_URL, "/responses"), api_key, body)

    text = data.get("output_text")
    if isinstance(text, str) and text.strip():
        return text.strip()

    chunks: list[str] = []
    for item in data.get("output", []):
        if not isinstance(item, dict):
            continue
        for content in item.get("content", []):
            if isinstance(content, dict) and isinstance(content.get("text"), str):
                chunks.append(content["text"])
    if chunks:
        return "\n".join(chunks).strip()
    return json.dumps(data, ensure_ascii=False, indent=2)


def _ask_chat_completions(api_key: str, model: str, report: dict[str, object], user_prompt: str, base_url: str) -> str:
    body = {
        "model": model.strip(),
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a careful CTF write-up assistant. Keep answers legal, local, and challenge-focused. "
                    "Explain the final flag and the solving process in Korean with concrete evidence."
                ),
            },
            {"role": "user", "content": build_ai_prompt(report, user_prompt)},
        ],
        "max_tokens": 900,
    }
    data = _request_json(_join_base_url(base_url, OPENAI_CHAT_COMPLETIONS_URL, "/chat/completions"), api_key, body)
    choices = data.get("choices", [])
    if isinstance(choices, list) and choices:
        message = choices[0].get("message") if isinstance(choices[0], dict) else None
        if isinstance(message, dict) and isinstance(message.get("content"), str):
            return message["content"].strip()
    return json.dumps(data, ensure_ascii=False, indent=2)


def _ask_anthropic(api_key: str, model: str, report: dict[str, object], user_prompt: str, base_url: str) -> str:
    body = {
        "model": model.strip(),
        "max_tokens": 900,
        "system": (
            "You are a careful CTF write-up assistant. Keep answers legal, local, and challenge-focused. "
            "Explain the final flag and the solving process in Korean with concrete evidence."
        ),
        "messages": [{"role": "user", "content": build_ai_prompt(report, user_prompt)}],
    }
    url = base_url.strip().rstrip("/") or ANTHROPIC_MESSAGES_URL
    if not url.endswith("/messages"):
        url += "/v1/messages" if not url.endswith("/v1") else "/messages"
    data = _request_json(
        url,
        "",
        body,
        headers={
            "x-api-key": api_key.strip(),
            "anthropic-version": "2023-06-01",
        },
    )
    chunks = []
    for item in data.get("content", []):
        if isinstance(item, dict) and item.get("type") == "text" and isinstance(item.get("text"), str):
            chunks.append(item["text"])
    if chunks:
        return "\n".join(chunks).strip()
    return json.dumps(data, ensure_ascii=False, indent=2)


def _ask_gemini(api_key: str, model: str, report: dict[str, object], user_prompt: str, base_url: str) -> str:
    prompt = (
        "System: You are a careful CTF write-up assistant. Keep answers legal, local, and challenge-focused. "
        "Explain the final flag and the solving process in Korean with concrete evidence.\n\n"
        + build_ai_prompt(report, user_prompt)
    )
    body = {"contents": [{"parts": [{"text": prompt}]}]}
    clean = base_url.strip().rstrip("/") or GEMINI_BASE_URL
    if ":generateContent" in clean:
        url = clean
    else:
        url = f"{clean}/models/{model.strip()}:generateContent"
    data = _request_json(url, "", body, headers={"x-goog-api-key": api_key.strip()})
    chunks = []
    for candidate in data.get("candidates", []):
        if not isinstance(candidate, dict):
            continue
        content = candidate.get("content", {})
        if not isinstance(content, dict):
            continue
        for part in content.get("parts", []):
            if isinstance(part, dict) and isinstance(part.get("text"), str):
                chunks.append(part["text"])
    if chunks:
        return "\n".join(chunks).strip()
    return json.dumps(data, ensure_ascii=False, indent=2)


def _ask_ollama(api_key: str, model: str, report: dict[str, object], user_prompt: str, base_url: str) -> str:
    body = {
        "model": model.strip(),
        "stream": False,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a careful CTF write-up assistant. Keep answers legal, local, and challenge-focused. "
                    "Explain the final flag and the solving process in Korean with concrete evidence."
                ),
            },
            {"role": "user", "content": build_ai_prompt(report, user_prompt)},
        ],
    }
    clean = base_url.strip().rstrip("/") or OLLAMA_CHAT_URL
    if clean.endswith("/api"):
        url = clean + "/chat"
    elif clean.endswith("/api/chat"):
        url = clean
    else:
        url = clean + "/api/chat" if "/api" not in clean else clean
    data = _request_json(url, api_key, body)
    message = data.get("message")
    if isinstance(message, dict) and isinstance(message.get("content"), str):
        return message["content"].strip()
    if isinstance(data.get("response"), str):
        return str(data["response"]).strip()
    return json.dumps(data, ensure_ascii=False, indent=2)
