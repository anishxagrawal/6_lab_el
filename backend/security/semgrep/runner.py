import json
import os
import shutil
import subprocess
from pathlib import Path

from .constants import CUSTOM_RULE_PATHS, SEMGREP_CONFIG

SEMGREP_TIMEOUT_SECONDS = 120


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


def _resolve_custom_configs() -> list[str]:
    """
    Return the custom rule-pack paths that currently exist on disk.

    Missing/renamed files are skipped rather than raised, so a fresh
    clone that hasn't pulled the rules/ folder yet doesn't crash the
    scan endpoint.
    """

    return [
        str(path)
        for path in CUSTOM_RULE_PATHS
        if Path(path).exists()
    ]


def run_semgrep(
    repo_path: str,
) -> dict:
    """
    Execute Semgrep scan.

    Loads Semgrep registry rule packs dynamically based on the detected
    languages and infrastructure, combined with local custom rule packs.
    """
    from core.profiler import build_repository_profile

    semgrep_executable = (
        _find_semgrep_executable()
    )

    command = [
        semgrep_executable,
        "scan",
    ]

    try:
        profile = build_repository_profile(repo_path)
    except Exception as e:
        print(f"WARNING: Repository profiling failed: {e}")
        profile = {}

    configs = []
    
    langs = profile.get("languages", [])
    if "Python" in langs:
        configs += ["p/python", "p/security-audit", "p/secrets"]
    if "JavaScript" in langs or "TypeScript" in langs or "JavaScript (React)" in langs or "TypeScript (React)" in langs:
        configs += ["p/javascript", "p/react", "p/nodejs"]

    infra = profile.get("infrastructure", [])
    if "Docker" in infra or "Docker Compose" in infra:
        configs += ["p/docker"]
    if "Terraform" in infra:
        configs += ["p/terraform"]
    if "Kubernetes" in infra:
        configs += ["p/kubernetes"]

    if not configs:
        configs = [SEMGREP_CONFIG]

    for config in configs:
        command += ["--config", config]

    for custom_config in _resolve_custom_configs():
        command += ["--config", custom_config]

    command += [
        "--json",
        repo_path,
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=SEMGREP_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise SemgrepExecutionError(
            f"Semgrep scan exceeded the {SEMGREP_TIMEOUT_SECONDS}s time limit "
            f"for {repo_path}."
        ) from exc

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