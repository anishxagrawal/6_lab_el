from __future__ import annotations

from typing import Any

from groq import Groq


def strip_thinking(
    text: str,
) -> str:

    if "</thinking>" in text:

        return (
            text.split(
                "</thinking>",
                maxsplit=1,
            )[-1]
            .strip()
        )

    return text.strip()


def build_reasoning(
    owner: str,
    name: str,
    findings: list[dict[str, Any]],
    groq_client: Groq | None,
) -> str:

    if not findings:

        return (
            "No exposed secrets were "
            "detected in this repository scan."
        )

    type_counts: dict[str, int] = {}

    for finding in findings:

        secret_type = (
            finding["secret_type"]
        )

        type_counts[
            secret_type
        ] = (
            type_counts.get(
                secret_type,
                0,
            )
            + 1
        )

    breakdown = ", ".join(
        (
            f"{count}x {secret_type}"
            for secret_type, count in sorted(
                type_counts.items(),
                key=lambda item: (
                    -item[1],
                    item[0],
                ),
            )
        )
    )

    critical_count = sum(
        1
        for finding in findings
        if finding["severity"]
        == "CRITICAL"
    )

    cross_repo = len(
        {
            finding["secret_hash"]
            for finding in findings
            if finding.get(
                "cluster_repo_count",
                1,
            )
            >= 2
        }
    )

    prompt = (
        f"GitHub repo {owner}/{name} scan:\n"
        f"- Total secrets exposed: {len(findings)}\n"
        f"- Critical severity: {critical_count}\n"
        f"- Types: {breakdown}\n"
        f"- Also leaked in other monitored repos: {cross_repo}\n\n"
        "What is the risk level, "
        "what are the most urgent actions, "
        "and what does cross-repo leakage imply?"
    )

    if groq_client is None:

        return (
            f"Repository {owner}/{name} "
            f"contains {len(findings)} "
            f"exposed secret(s). "
            f"Critical findings: "
            f"{critical_count}. "
            f"Types: {breakdown}. "
            "Rotate exposed credentials, "
            "remove secrets from the repository "
            "history, and investigate "
            "cross-repo reuse."
        )

    try:

        chat = (
            groq_client.chat.completions.create(
                model=
                    "llama-3.3-70b-versatile",
                messages=[
                    {
                        "role":
                            "system",
                        "content":
                            (
                                "You are a senior "
                                "security analyst. "
                                "Think step by step "
                                "inside <thinking> "
                                "tags, then write "
                                "a plain-English "
                                "summary under "
                                "120 words."
                            ),
                    },
                    {
                        "role":
                            "user",
                        "content":
                            prompt,
                    },
                ],
                max_tokens=350,
            )
        )

        raw = (
            chat.choices[0]
            .message.content
            or ""
        )

        return strip_thinking(
            raw
        )

    except Exception:

        return (
            f"Repository {owner}/{name} "
            f"contains {len(findings)} "
            f"exposed secret(s). "
            f"Critical findings: "
            f"{critical_count}. "
            f"Types: {breakdown}. "
            "Rotate exposed credentials, "
            "remove secrets from the repository "
            "history, and investigate "
            "cross-repo reuse."
        )