import json
import os
import shutil
import subprocess
from pathlib import Path

from .constants import SEMGREP_CONFIG


class SemgrepExecutionError(Exception):
    pass


def _find_semgrep_executable() -> str:
    """
    Locate semgrep executable.

    Priority:
        1. Environment variable
        2. PATH
        3. Common Windows locations
    """

    env_path = os.getenv("SEMGREP_PATH")

    if env_path and Path(env_path).exists():
        return env_path

    path_semgrep = shutil.which("semgrep")

    if path_semgrep:
        return path_semgrep

    path_pysemgrep = shutil.which("pysemgrep")

    if path_pysemgrep:
        return path_pysemgrep

    common_windows_paths = [
        Path.home()
        / "AppData"
        / "Local"
        / "Packages"
        / "PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0"
        / "LocalCache"
        / "local-packages"
        / "Python311"
        / "Scripts"
        / "pysemgrep.exe",
        Path.home()
        / "AppData"
        / "Local"
        / "Packages"
        / "PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0"
        / "LocalCache"
        / "local-packages"
        / "Python311"
        / "Scripts"
        / "semgrep.exe",
    ]

    for path in common_windows_paths:
        if path.exists():
            return str(path)

    raise SemgrepExecutionError(
        "Semgrep executable not found."
    )


def run_semgrep(
    repo_path: str,
) -> dict:
    """
    Execute Semgrep scan.

    Returns:
        Raw Semgrep JSON output.
    """

    semgrep_executable = (
        _find_semgrep_executable()
    )

    command = [
        semgrep_executable,
        "scan",
        "--config",
        SEMGREP_CONFIG,
        "--json",
        repo_path,
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore",
    )

    if result.returncode not in [0, 1]:
        raise SemgrepExecutionError(
            f"Semgrep failed:\n{result.stderr}"
        )

    try:
        return json.loads(result.stdout)

    except json.JSONDecodeError as exc:
        raise SemgrepExecutionError(
            f"Failed to parse Semgrep output: {exc}"
        ) from exc


def run_semgrep_with_stats(
    repo_path: str,
) -> tuple[dict, dict]:
    """
    Returns:
        (
            semgrep_json,
            stats
        )
    """

    semgrep_json = run_semgrep(repo_path)

    stats = {
        "total_results": len(
            semgrep_json.get("results", [])
        ),
        "errors": len(
            semgrep_json.get("errors", [])
        ),
        "paths_scanned": len(
            semgrep_json.get("paths", {})
            .get("scanned", [])
        ),
    }

    return semgrep_json, stats