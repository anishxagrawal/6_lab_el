from __future__ import annotations

from typing import Any

from groq import Groq

from ai.reasoning import strip_thinking


def suggest_fix(
    finding: dict[str, Any],
    groq_client: Groq | None,
) -> str | None:
    """
    Given a single Semgrep finding (file_path, code snippet, rule_name,
    owasp_category), ask Groq for a corrected version of the snippet plus
    a one-line reason it's safer.

    Returns None if Groq isn't configured, the snippet is empty, or the
    API call fails for any reason -- callers should treat this as "no AI
    suggestion available" and fall back to the finding's existing static
    `recommendation` field, never as a scan failure.

    Intentionally only meant to be called on Semgrep-sourced findings
    (source_type == "semgrep"). Raw secret-scanner findings should never
    be passed here: their `snippet` field can contain the live secret
    value itself, and sending that to a third-party AI API would be a
    real exposure. There's also no interesting "fix" for a leaked
    secret beyond "rotate it," which doesn't need an AI call.
    """

    if groq_client is None:
        return None

    snippet = (finding.get("snippet") or "").strip()
    if not snippet:
        return None

    rule_name = finding.get("rule_name") or finding.get("secret_type") or "Unknown issue"
    owasp_category = finding.get("owasp_category") or "N/A"
    file_path = finding.get("file_path") or "unknown file"

    prompt = (
        f"Vulnerability: {rule_name}\n"
        f"OWASP category: {owasp_category}\n"
        f"File: {file_path}\n"
        f"Vulnerable code:\n{snippet}\n\n"
        "In under 80 words: show the corrected version of this exact "
        "line/snippet, then a one-sentence explanation of why it's safer. "
        "Do not add unrelated advice."
    )

    try:
        chat = groq_client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {
                    "role": "system",
                    "content": "You are a secure-coding assistant. Be concise and concrete.",
                },
                {"role": "user", "content": prompt},
            ],
            max_tokens=200,
        )

        raw = chat.choices[0].message.content or ""
        fixed = strip_thinking(raw)

        return fixed or None

    except Exception:
        return None