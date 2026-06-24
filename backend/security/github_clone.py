from __future__ import annotations

import shutil
import subprocess
import tempfile


def clone_repository(
    github_url: str,
) -> str:
    """
    Clone repository into a temporary directory.

    Returns:
        Path to cloned repository.
    """

    temp_dir = tempfile.mkdtemp(
        prefix="darkshield_"
    )

    try:

        subprocess.run(
            [
                "git",
                "clone",
                "--depth",
                "1",
                github_url,
                temp_dir,
            ],
            check=True,
            capture_output=True,
            text=True,
        )

        print(
            f"OK: Repository cloned to {temp_dir}"
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