from __future__ import annotations

import re
from typing import Any

import httpx

from security.entropy import find_high_entropy_tokens

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
    ".wasm",
}
# NOTE: .js/.jsx/.ts/.tsx/.html/.vue are intentionally NOT in this set.
# The Phase 5 frontend_rules.yml Semgrep pack (XSS, insecure storage,
# missing rel=noopener, etc.) depends on these files reaching the scanner.
# Do not add them here without updating security/semgrep/rules/frontend_rules.yml
# accordingly.


def should_skip_file(
    path: str,
    size: int | None,
) -> bool:
    if size is not None and size >= 300_000:
        return True

    lowered = path.lower()

    # Skip ZK verification key files which only contain public cryptographic parameters
    if "vkey" in lowered or "verification_key" in lowered:
        return True

    if any(lock in lowered for lock in ["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "composer.lock"]):
        return True

    return any(
        lowered.endswith(ext)
        for ext in SKIP_EXT
    )


def _build_finding(
    *,
    repo_id: str,
    file_path: str,
    line_number: int,
    secret_type: str,
    severity: str,
    line: str,
    secret_value: str,
    detection_method: str,
    entropy_score: float | None,
    hash_secret,
    encrypt_snippet,
    calculate_exposure_score,
    hmac_secret_key: str,
    first_commit_date,
    exposure_days: int | None,
) -> dict[str, Any]:
    """
    Build a single finding dict. Shared by both the regex-pattern detection
    path and the entropy-based detection path in scan_file, so the two
    detection methods produce a consistent schema.
    """
    secret_hash = hash_secret(
        secret_value,
        hmac_secret_key,
    )

    plain_snippet = line.strip()[:120]
    encrypted_snippet = encrypt_snippet(plain_snippet)

    exposure_score = (
        calculate_exposure_score(severity, exposure_days)
        if first_commit_date
        else None
    )

    finding: dict[str, Any] = {
        "repo_id": repo_id,
        "file_path": file_path,
        "line_number": line_number,
        "secret_type": secret_type,
        "severity": severity,
        "snippet": plain_snippet,
        "snippet_enc": encrypted_snippet,
        "secret_hash": secret_hash,
        "detection_method": detection_method,
    }

    if entropy_score is not None:
        finding["entropy_score"] = entropy_score

    if first_commit_date:
        finding["first_commit_date"] = first_commit_date.isoformat()
        finding["exposure_days"] = exposure_days
        finding["exposure_score"] = exposure_score

    return finding


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
    hmac_secret_key,
    repo_path: str | None = None
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
                repo_path=repo_path,
            )
        )

        lines = response.text.splitlines()

        for line_number, line in enumerate(
            lines,
            start=1,
        ):
            matched_spans: list[tuple[int, int]] = []

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

                matched_spans.append(match.span())

                findings.append(
                    _build_finding(
                        repo_id=repo_id,
                        file_path=file_path,
                        line_number=line_number,
                        secret_type=secret_type,
                        severity=severity,
                        line=line,
                        secret_value=match.group(0),
                        detection_method="pattern",
                        entropy_score=None,
                        hash_secret=hash_secret,
                        encrypt_snippet=encrypt_snippet,
                        calculate_exposure_score=calculate_exposure_score,
                        hmac_secret_key=hmac_secret_key,
                        first_commit_date=first_commit_date,
                        exposure_days=exposure_days,
                    )
                )

            # Entropy pass: catches token-shaped strings that don't match any
            # named PATTERNS above (custom/internal secrets). Skip tokens that
            # overlap a span already reported by a pattern match on this line,
            # so the same secret isn't reported twice under two detection
            # methods.
            # Skip entropy checks on test files, documentation, and config files to reduce false positive noise.
            lowered_path = file_path.lower()
            is_test_or_doc = (
                "test" in lowered_path 
                or lowered_path.endswith(".md") 
                or lowered_path.endswith(".txt")
                or lowered_path.endswith(".json")
            )
            if not is_test_or_doc:
                for hit in find_high_entropy_tokens(line):
                    token_start = hit["start"]
                    token_end = token_start + len(str(hit["token"]))

                    overlaps_existing_match = any(
                        token_start < span_end and token_end > span_start
                        for span_start, span_end in matched_spans
                    )
                    if overlaps_existing_match:
                        continue

                    findings.append(
                        _build_finding(
                            repo_id=repo_id,
                            file_path=file_path,
                            line_number=line_number,
                            secret_type="High-Entropy String",
                            severity="MEDIUM",
                            line=line,
                            secret_value=str(hit["token"]),
                            detection_method="entropy",
                            entropy_score=hit["entropy"],
                            hash_secret=hash_secret,
                            encrypt_snippet=encrypt_snippet,
                            calculate_exposure_score=calculate_exposure_score,
                            hmac_secret_key=hmac_secret_key,
                            first_commit_date=first_commit_date,
                            exposure_days=exposure_days,
                        )
                    )

    except Exception as e:

        print(
            f"WARNING: Error scanning {file_path}: {e}"
        )

        return