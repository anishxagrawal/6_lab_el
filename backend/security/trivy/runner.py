import json
import os
import shutil
import subprocess
from pathlib import Path

TRIVY_TIMEOUT_SECONDS = 120


class TrivyExecutionError(Exception):
    pass


def _find_trivy_executable() -> str | None:
    """
    Locate the trivy executable.

    Priority:
        1. TRIVY_PATH environment variable
        2. PATH

    Returns None (rather than raising) when trivy isn't installed, so
    callers can treat "Trivy not available" as a skippable, non-fatal
    condition - same graceful-degradation philosophy as
    _resolve_custom_configs() in security/semgrep/runner.py, since
    Trivy is a separate binary (not a pip package) and shouldn't be a
    hard requirement to run the rest of the scan pipeline.
    """

    env_path = os.getenv("TRIVY_PATH")

    if env_path and Path(env_path).exists():
        return env_path

    return shutil.which("trivy")


def run_trivy(repo_path: str) -> dict:
    """
    Execute a Trivy filesystem scan for dependency (SCA) vulnerabilities.

    Scoped to --scanners vuln only (not misconfig/secret/license) - this
    project already has dedicated secret detection (security/secret_scanner.py,
    git_history_scanner.py) and static analysis (Semgrep); Trivy's role
    here is specifically to fill the one gap those don't cover:
    OWASP A06:2021 (Vulnerable and Outdated Components).

    Returns:
        Raw Trivy JSON output. Returns an empty-results dict (rather
        than raising) if the trivy binary isn't installed, since Trivy
        is an optional additive scanner, not a hard dependency of the
        rest of the pipeline.
    """

    trivy_executable = _find_trivy_executable()

    if trivy_executable is None:
        return {"Results": []}

    command = [
        trivy_executable,
        "fs",
        "--scanners",
        "vuln",
        "--format",
        "json",
        repo_path,
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=TRIVY_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise TrivyExecutionError(
            f"Trivy scan exceeded the {TRIVY_TIMEOUT_SECONDS}s time limit "
            f"for {repo_path}."
        ) from exc

    # Trivy returns 0 on a clean scan and can return non-zero when
    # --exit-code is set (not used here, so this is defensive) or on a
    # genuine failure. Unlike Semgrep's 0/1 convention, treat only 0 as
    # success; anything else surfaces stderr for diagnosis.
    if result.returncode != 0:
        raise TrivyExecutionError(
            f"Trivy failed:\n{result.stderr}"
        )

    try:
        return json.loads(result.stdout)

    except json.JSONDecodeError as exc:
        raise TrivyExecutionError(
            f"Failed to parse Trivy output: {exc}"
        ) from exc