from __future__ import annotations

import re
import subprocess
from typing import Any

from security.entropy import find_high_entropy_tokens
from security.secret_scanner import PATTERNS

GIT_LOG_TIMEOUT_SECONDS = 60
DEFAULT_MAX_COMMITS = 200

_COMMIT_LINE_RE = re.compile(r"^commit ([0-9a-f]{7,40})")
_DIFF_FILE_LINE_RE = re.compile(r"^diff --git a/(.+?) b/(.+)$")


class GitHistoryScanError(Exception):
    pass


def _run_git_log(repo_path: str, max_commits: int) -> str:
    """
    Run `git log -p --all` against an already-cloned, full-history repo
    and return the raw diff output. Requires the clone to NOT be shallow
    (see security.github_clone.clone_repository(..., full_history=True)).
    """
    try:
        result = subprocess.run(
            [
                "git", "-C", repo_path,
                "log", "-p", "--all", "--no-color",
                "-n", str(max_commits),
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=GIT_LOG_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise GitHistoryScanError(
            f"git log exceeded {GIT_LOG_TIMEOUT_SECONDS}s time limit for {repo_path}"
        ) from exc

    if result.returncode != 0:
        raise GitHistoryScanError(f"git log failed:\n{result.stderr}")

    return result.stdout


def _build_history_finding(
    *,
    repo_id: str,
    file_path: str,
    commit_hash: str,
    secret_type: str,
    severity: str,
    line_content: str,
    secret_value: str,
    detection_method: str,
    entropy_score: float | None,
    secret_hash: str,
    encrypt_snippet,
) -> dict[str, Any]:
    plain_snippet = line_content.strip()[:120]
    encrypted_snippet = encrypt_snippet(plain_snippet)

    finding: dict[str, Any] = {
        "repo_id": repo_id,
        "file_path": file_path,
        # 0 is a sentinel meaning "found via git history diff, not a specific
        # line in the current file" - deliberately NOT None/NULL, because
        # main.py's upsert on_conflict key is (repo_id, file_path,
        # line_number, secret_hash), and SQL unique constraints treat every
        # NULL as distinct, which would silently break dedup/re-scan updates.
        "line_number": 0,
        "secret_type": secret_type,
        "severity": severity,
        "snippet": plain_snippet,
        "snippet_enc": encrypted_snippet,
        "secret_hash": secret_hash,
        "detection_method": detection_method,
        "found_in": "history",
        "commit_hash": commit_hash,
    }

    if entropy_score is not None:
        finding["entropy_score"] = entropy_score

    return finding


def scan_git_history(
    *,
    repo_path: str,
    repo_id: str,
    hash_secret,
    encrypt_snippet,
    hmac_secret_key: str,
    max_commits: int = DEFAULT_MAX_COMMITS,
) -> list[dict[str, Any]]:
    """
    Walk up to `max_commits` of git log -p output for a repo already cloned
    at `repo_path` (must be a FULL, non-shallow clone - see
    security.github_clone.clone_repository(full_history=True)) and run the
    same regex + entropy secret detectors used in secret_scanner.py against
    every ADDED line in every diff.

    This exists to catch secrets that were committed and later removed from
    the codebase - they're permanently recoverable via `git log -p` even
    though a HEAD-only scan (secret_scanner.scan_file) would report the
    repo as clean.

    Returns a list of findings tagged found_in='history' and commit_hash=<sha>.
    A given (file_path, secret) combination is only reported once even if it
    reappears across multiple commits, to avoid flooding the results with
    duplicates of the same leaked secret.
    """
    log_output = _run_git_log(repo_path, max_commits)

    findings: list[dict[str, Any]] = []
    seen_secret_keys: set[str] = set()

    current_commit: str | None = None
    current_file: str | None = None

    for raw_line in log_output.splitlines():
        commit_match = _COMMIT_LINE_RE.match(raw_line)
        if commit_match:
            current_commit = commit_match.group(1)
            continue

        diff_file_match = _DIFF_FILE_LINE_RE.match(raw_line)
        if diff_file_match:
            current_file = diff_file_match.group(2)
            continue

        # Only inspect added lines; "+++ b/..." is a diff header, not content.
        if not raw_line.startswith("+") or raw_line.startswith("+++"):
            continue

        if current_commit is None or current_file is None:
            continue

        added_content = raw_line[1:]
        matched_spans: list[tuple[int, int]] = []

        for secret_type, (pattern, severity) in PATTERNS.items():
            match = re.search(pattern, added_content)
            if not match:
                continue

            matched_spans.append(match.span())
            secret_value = match.group(0)
            secret_hash = hash_secret(secret_value, hmac_secret_key)

            dedup_key = f"{current_file}:{secret_hash}"
            if dedup_key in seen_secret_keys:
                continue
            seen_secret_keys.add(dedup_key)

            findings.append(
                _build_history_finding(
                    repo_id=repo_id,
                    file_path=current_file,
                    commit_hash=current_commit,
                    secret_type=secret_type,
                    severity=severity,
                    line_content=added_content,
                    secret_value=secret_value,
                    detection_method="pattern",
                    entropy_score=None,
                    secret_hash=secret_hash,
                    encrypt_snippet=encrypt_snippet,
                )
            )

        # Entropy pass: same overlap-skip logic as secret_scanner.scan_file,
        # so a secret already caught by a named pattern isn't double-reported.
        # Skip entropy checks on test files, documentation, and config files to reduce false positive noise.
        lowered_file = current_file.lower()
        is_test_or_doc = (
            "test" in lowered_file 
            or lowered_file.endswith(".md") 
            or lowered_file.endswith(".txt")
            or lowered_file.endswith(".json")
            or "vkey" in lowered_file
            or "verification_key" in lowered_file
        )
        if not is_test_or_doc:
            for hit in find_high_entropy_tokens(added_content):
                token = str(hit["token"])
                token_start = hit["start"]
                token_end = token_start + len(token)

                overlaps_existing_match = any(
                    token_start < span_end and token_end > span_start
                    for span_start, span_end in matched_spans
                )
                if overlaps_existing_match:
                    continue

                secret_hash = hash_secret(token, hmac_secret_key)
                dedup_key = f"{current_file}:{secret_hash}"
                if dedup_key in seen_secret_keys:
                    continue
                seen_secret_keys.add(dedup_key)

                findings.append(
                    _build_history_finding(
                        repo_id=repo_id,
                        file_path=current_file,
                        commit_hash=current_commit,
                        secret_type="High-Entropy String",
                        severity="MEDIUM",
                        line_content=added_content,
                        secret_value=token,
                        detection_method="entropy",
                        entropy_score=hit["entropy"],
                        secret_hash=secret_hash,
                        encrypt_snippet=encrypt_snippet,
                    )
                )

    return findings