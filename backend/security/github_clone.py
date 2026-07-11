from __future__ import annotations

import re
import shutil
import subprocess
import tempfile

# Only allow well-formed https GitHub URLs. This blocks:
#   - argument injection (a value starting with "-" being parsed as a git flag)
#   - non-GitHub / non-https targets (file://, ssh with embedded flags, etc.)
_GITHUB_HTTPS_URL_RE = re.compile(
    r"^https://github\.com/[\w.-]+/[\w.-]+(?:\.git)?/?$"
)

CLONE_TIMEOUT_SECONDS = 60
FULL_HISTORY_CLONE_TIMEOUT_SECONDS = 180


class InvalidRepositoryUrlError(ValueError):
    """Raised when a github_url does not match the expected safe pattern."""


def _validate_github_url(github_url: str) -> None:
    if not github_url or not _GITHUB_HTTPS_URL_RE.match(github_url.strip()):
        raise InvalidRepositoryUrlError(
            f"Refusing to clone: '{github_url}' is not a well-formed "
            "https://github.com/<owner>/<repo> URL."
        )


def parse_github_url(github_url: str) -> tuple[str, str]:
    """
    Validates `github_url` against the same allowlist pattern used before
    cloning, then extracts (owner, name) from it. Used by the /repos
    creation endpoint so a repo can't be registered in the DB with an
    unvalidated URL that later fails (or worse, is unsafe) when /scan
    passes it to clone_repository.

    Raises:
        InvalidRepositoryUrlError: if github_url isn't a well-formed
            https://github.com/<owner>/<repo> URL.
    """
    _validate_github_url(github_url)

    trimmed = github_url.strip().rstrip("/")
    if trimmed.endswith(".git"):
        trimmed = trimmed[: -len(".git")]

    owner, name = trimmed.removeprefix("https://github.com/").split("/", maxsplit=1)
    return owner, name


def clone_repository(
    github_url: str,
    full_history: bool = False,
) -> str:
    """
    Clone repository into a temporary directory.

    Validates github_url against a strict allowlist pattern before ever
    reaching subprocess, and enforces a hard timeout so a slow/huge/malicious
    clone target can't hang the scan endpoint indefinitely.

    Args:
        github_url: must match https://github.com/<owner>/<repo>.
        full_history: if False (default), does a shallow --depth 1 clone -
            fast, but `git log` on the result only shows one commit. Pass
            True when the caller also needs to walk commit history (e.g.
            security.git_history_scanner.scan_git_history), which needs
            the full clone and gets a longer timeout to allow for it.

    Returns:
        Path to cloned repository.

    Raises:
        InvalidRepositoryUrlError: if github_url isn't a well-formed
            https://github.com/<owner>/<repo> URL.
        subprocess.TimeoutExpired: if the clone exceeds its timeout.
        subprocess.CalledProcessError: if git itself fails (bad repo, private, etc).
    """

    _validate_github_url(github_url)

    temp_dir = tempfile.mkdtemp(
        prefix="darkshield_"
    )

    clone_command = ["git", "clone"]
    if not full_history:
        clone_command += ["--depth", "1"]
    clone_command += [github_url, temp_dir]

    timeout = (
        FULL_HISTORY_CLONE_TIMEOUT_SECONDS
        if full_history
        else CLONE_TIMEOUT_SECONDS
    )

    try:

        subprocess.run(
            clone_command,
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        print(
            f"OK: Repository cloned to {temp_dir} "
            f"({'full history' if full_history else 'shallow'})"
        )

        return temp_dir

    except Exception:

        shutil.rmtree(
            temp_dir,
            ignore_errors=True,
        )

        raise


def cleanup_repository(
    repo_path: str,
) -> None:
    """
    Remove cloned repository.
    """

    if not repo_path:
        return

    try:

        shutil.rmtree(
            repo_path,
            ignore_errors=True,
        )

    except Exception:
        pass