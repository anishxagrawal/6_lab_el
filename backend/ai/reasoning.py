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
    repo_profile: dict[str, Any] | None = None,
) -> str:

    if not findings:

        return (
            "No security findings or exposed secrets were "
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
        f"{v}x {k}"
        for k, v in sorted(
            type_counts.items(),
            key=lambda x: -x[1],
        )
    )

    critical_count = sum(
        1
        for finding in findings
        if finding["severity"].upper()
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

    # Deduplicate findings by secret_hash for the prompt to keep it concise and descriptive
    unique_hashes = set()
    details_lines = []
    for f in findings:
        h = f.get("secret_hash")
        if h not in unique_hashes:
            unique_hashes.add(h)
            desc = f.get("vulnerability_description") or f.get("snippet") or ""
            desc = desc.strip()
            if len(desc) > 80:
                desc = desc[:77] + "..."
            details_lines.append(
                f"  * [{f.get('severity')}] {f.get('secret_type')} in `{f.get('file_path')}:{f.get('line_number')}` ({desc})"
            )

    findings_details = "\n".join(details_lines[:10])

    profile_desc = ""
    if repo_profile:
        profile_desc = (
            f"Repository Technology Profile:\n"
            f"- Languages: {', '.join(repo_profile.get('languages', [])) or 'None'}\n"
            f"- Frameworks: {', '.join(repo_profile.get('frameworks', [])) or 'None'}\n"
            f"- Infrastructure: {', '.join(repo_profile.get('infrastructure', [])) or 'None'}\n"
            f"- Security Features: {', '.join(repo_profile.get('security_features', [])) or 'None'}\n"
            f"- APIs: {', '.join(repo_profile.get('apis', [])) or 'None'}\n\n"
        )

    prompt = (
        f"GitHub repo {owner}/{name} scan summary:\n"
        f"- Total findings exposed: {len(findings)}\n"
        f"- Critical severity count: {critical_count}\n"
        f"- Type breakdown: {breakdown}\n"
        f"- Leaked in other monitored repos (cross-repo reuse): {cross_repo}\n\n"
        f"{profile_desc}"
        f"Specific key findings details (up to 10 unique items):\n"
        f"{findings_details}\n\n"
        "Provide a high-quality, professional executive security report. "
        "Your report must follow these sections:\n"
        "1. **Executive Summary**: A concise assessment of the risk profile and overall security posture.\n"
        "2. **Technology Stack Context**: Relate the scanned stack and detected APIs/infrastructure to security practices.\n"
        "3. **Canary & Exploit Analysis**: Address whether the detected findings are false positives or can be actively exploited in this repository layout.\n"
        "4. **Prioritized Remediation Plan**: List clear steps to remediate the vulnerabilities, referencing the specific files.\n\n"
        "Guidelines for report generation:\n"
        "- Consider findings supported by multiple scanners (scanner agreement) as high-confidence.\n"
        "- Prioritize vulnerabilities confirmed by CodeQL.\n"
        "- Mention when vulnerabilities are confirmed by semantic data-flow analysis and call flows.\n"
        "- Do not discuss rejected findings."
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
                                "You are a senior security analyst. "
                                "Think step by step inside <thinking> tags, "
                                "then write a professional executive security report."
                            ),
                    },
                    {
                        "role":
                            "user",
                        "content":
                            prompt,
                    },
                ],
                max_tokens=750,
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