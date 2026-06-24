from __future__ import annotations

import re
from typing import Any

import httpx


PATTERNS: dict[str, tuple[str, str]] = {
    "AWS Access Key": (r"AKIA[0-9A-Z]{16}", "HIGH"),
    "AWS Secret Key": (
        r"(?i)aws.{0,20}secret.{0,20}[\'\"][0-9a-zA-Z/+=]{40}[\'\"]",
        "CRITICAL",
    ),
    "OpenAI Key": (r"sk-[a-zA-Z0-9]{32,}", "HIGH"),
    "Anthropic Key": (
        r"sk-ant-[a-zA-Z0-9\-]{90,}",
        "HIGH",
    ),
    "Groq Key": (
        r"gsk_[a-zA-Z0-9]{50,}",
        "HIGH",
    ),
    "GitHub Token": (
        r"gh[pousr]_[A-Za-z0-9_]{36,}",
        "HIGH",
    ),
    "Stripe Secret": (
        r"sk_live_[0-9a-zA-Z]{24,}",
        "CRITICAL",
    ),
    "Google API Key": (
        r"AIza[0-9A-Za-z\-_]{35}",
        "HIGH",
    ),
    "Slack Token": (
        r"xox[baprs]-[0-9a-zA-Z\-]{10,}",
        "MEDIUM",
    ),
    "Private Key": (
        r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
        "CRITICAL",
    ),
    "Generic Password": (
        r"(?i)(password|passwd|pwd)\s*[:=]\s*[\"']?[^\s\"']{8,}[\"']?",
        "MEDIUM",
    ),
    "Generic Secret": (
        r"(?i)(secret|api_key|api_secret|access_token)\s*[:=]\s*[\"']?[^\s\"']{8,}[\"']?",
        "MEDIUM",
    ),
}


SKIP_EXT = {
    ".png",
    ".jpg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".ttf",
    ".zip",
    ".pdf",
    ".lock",
    ".min.js",
    ".map",
    ".exe",
    ".bin",
}


def should_skip_file(
    path: str,
    size: int | None,
) -> bool:
    if size is not None and size >= 300_000:
        return True

    lowered = path.lower()

    return any(
        lowered.endswith(ext)
        for ext in SKIP_EXT
    )


async def scan_file(
    *,
    client: httpx.AsyncClient,
    owner: str,
    name: str,
    file_path: str,
    repo_id: str,
    findings: list[dict[str, Any]],
    get_first_commit_date,
    hash_secret,
    encrypt_snippet,
    calculate_exposure_score,
) -> None:

    raw_url = (
        f"https://raw.githubusercontent.com/"
        f"{owner}/{name}/HEAD/{file_path}"
    )

    try:

        response = await client.get(
            raw_url,
            timeout=10,
        )

        if response.status_code != 200:
            return

        first_commit_date, exposure_days = (
            await get_first_commit_date(
                client,
                owner,
                name,
                file_path,
            )
        )

        lines = response.text.splitlines()

        for line_number, line in enumerate(
            lines,
            start=1,
        ):

            for (
                secret_type,
                (
                    pattern,
                    severity,
                ),
            ) in PATTERNS.items():

                match = re.search(
                    pattern,
                    line,
                )

                if not match:
                    continue

                secret_value = match.group(0)

                secret_hash = hash_secret(
                    secret_value
                )

                plain_snippet = (
                    line.strip()[:120]
                )

                encrypted_snippet = (
                    encrypt_snippet(
                        plain_snippet
                    )
                )

                exposure_score = (
                    calculate_exposure_score(
                        severity,
                        exposure_days,
                    )
                    if first_commit_date
                    else None
                )

                finding = {
                    "repo_id":
                        repo_id,

                    "file_path":
                        file_path,

                    "line_number":
                        line_number,

                    "secret_type":
                        secret_type,

                    "severity":
                        severity,

                    "snippet":
                        plain_snippet,

                    "snippet_enc":
                        encrypted_snippet,

                    "secret_hash":
                        secret_hash,
                }

                if first_commit_date:

                    finding[
                        "first_commit_date"
                    ] = (
                        first_commit_date
                        .isoformat()
                    )

                    finding[
                        "exposure_days"
                    ] = (
                        exposure_days
                    )

                    finding[
                        "exposure_score"
                    ] = (
                        exposure_score
                    )

                findings.append(
                    finding
                )

    except Exception as e:

        print(
            f"WARNING: Error scanning {file_path}: {e}"
        )

        return