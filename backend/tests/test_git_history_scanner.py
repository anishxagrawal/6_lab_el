"""
Tests for security/git_history_scanner.py — recovering secrets from git
history that are no longer present in the current working tree.

Builds real, throwaway git repos in a temp directory for each test rather
than mocking subprocess, since the diff-parsing logic (commit headers,
"diff --git a/x b/y" lines, "+" prefixes) is exactly the part worth testing
against real `git log -p` output.
"""

import shutil
import subprocess
import tempfile

import pytest

from security.git_history_scanner import GitHistoryScanError, scan_git_history

MOCK_STRIPE_KEY = "sk_live_" + "ABCDEFGHIJKLMNOPQRSTUVWX"



def _run(cmd: list[str], cwd: str) -> None:
    subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, text=True)


@pytest.fixture
def git_repo():
    """A real, throwaway git repo, cleaned up after the test."""
    repo_dir = tempfile.mkdtemp(prefix="darkshield_test_repo_")
    _run(["git", "init", "-q"], cwd=repo_dir)
    _run(["git", "config", "user.email", "test@example.com"], cwd=repo_dir)
    _run(["git", "config", "user.name", "Test User"], cwd=repo_dir)

    yield repo_dir

    shutil.rmtree(repo_dir, ignore_errors=True)


def _write_and_commit(repo_dir: str, filename: str, content: str, message: str) -> None:
    with open(f"{repo_dir}/{filename}", "w") as f:
        f.write(content)
    _run(["git", "add", filename], cwd=repo_dir)
    _run(["git", "commit", "-q", "-m", message], cwd=repo_dir)


def _fake_hash_secret(value: str, pepper: str) -> str:
    # Deterministic-enough fake for tests: doesn't need to be real HMAC/SHA,
    # just needs to be stable per (value, pepper) pair for dedup logic to work.
    return f"hash-{hash(value + pepper)}"


def _fake_encrypt_snippet(snippet: str) -> str:
    return f"enc({snippet})"


class TestScanGitHistory:
    def test_finds_secret_that_was_later_deleted(self, git_repo):
        _write_and_commit(git_repo, "app.py", "def add(a, b):\n    return a + b\n", "initial commit")
        _write_and_commit(
            git_repo,
            "config.py",
            f'STRIPE_KEY = "{MOCK_STRIPE_KEY}"\n',
            "add config with secret (oops)",
        )
        _write_and_commit(
            git_repo,
            "config.py",
            "# secret removed, now loaded from environment\n",
            "remove hardcoded secret",
        )

        findings = scan_git_history(
            repo_path=git_repo,
            repo_id="repo-1",
            hash_secret=_fake_hash_secret,
            encrypt_snippet=_fake_encrypt_snippet,
            hmac_secret_key="pepper",
        )

        assert len(findings) == 1
        assert findings[0]["secret_type"] == "Stripe Secret"
        assert findings[0]["found_in"] == "history"
        assert findings[0]["file_path"] == "config.py"
        assert findings[0]["commit_hash"]  # non-empty sha
        assert findings[0]["line_number"] == 0

    def test_clean_repo_with_no_secrets_ever_committed_produces_no_findings(self, git_repo):
        _write_and_commit(git_repo, "app.py", "def add(a, b):\n    return a + b\n", "initial commit")
        _write_and_commit(git_repo, "app.py", "def add(a, b):\n    return a + b\n\ndef sub(a, b):\n    return a - b\n", "add subtract")

        findings = scan_git_history(
            repo_path=git_repo,
            repo_id="repo-1",
            hash_secret=_fake_hash_secret,
            encrypt_snippet=_fake_encrypt_snippet,
            hmac_secret_key="pepper",
        )

        assert findings == []

    def test_same_secret_across_multiple_commits_in_same_file_reported_once(self, git_repo):
        secret_line = f'STRIPE_KEY = "{MOCK_STRIPE_KEY}"\n'
        _write_and_commit(git_repo, "config.py", secret_line, "add secret")
        _write_and_commit(git_repo, "config.py", secret_line + "\n# comment\n", "touch file, secret still there")

        findings = scan_git_history(
            repo_path=git_repo,
            repo_id="repo-1",
            hash_secret=_fake_hash_secret,
            encrypt_snippet=_fake_encrypt_snippet,
            hmac_secret_key="pepper",
        )

        assert len(findings) == 1

    def test_same_secret_leaked_in_two_different_files_reported_twice(self, git_repo):
        secret_line = f'STRIPE_KEY = "{MOCK_STRIPE_KEY}"\n'
        _write_and_commit(git_repo, "config.py", secret_line, "add secret in config")
        _write_and_commit(git_repo, "other.py", secret_line, "accidentally reuse same secret elsewhere")

        findings = scan_git_history(
            repo_path=git_repo,
            repo_id="repo-1",
            hash_secret=_fake_hash_secret,
            encrypt_snippet=_fake_encrypt_snippet,
            hmac_secret_key="pepper",
        )

        file_paths = {f["file_path"] for f in findings}
        assert file_paths == {"config.py", "other.py"}

    def test_custom_token_with_no_named_pattern_caught_by_entropy_in_history(self, git_repo):
        _write_and_commit(
            git_repo,
            "config.py",
            'INTERNAL_TOKEN = "a1B9x7Qm2Zk8Ln4Rp6Ty0Wc3Fe5Hj1Sd9Va7Xb"\n',
            "add internal token",
        )
        _write_and_commit(git_repo, "config.py", "# token removed\n", "remove internal token")

        findings = scan_git_history(
            repo_path=git_repo,
            repo_id="repo-1",
            hash_secret=_fake_hash_secret,
            encrypt_snippet=_fake_encrypt_snippet,
            hmac_secret_key="pepper",
        )

        assert len(findings) == 1
        assert findings[0]["detection_method"] == "entropy"

    def test_raises_clean_error_on_non_git_directory(self):
        non_git_dir = tempfile.mkdtemp(prefix="darkshield_not_a_repo_")

        try:
            with pytest.raises(GitHistoryScanError):
                scan_git_history(
                    repo_path=non_git_dir,
                    repo_id="repo-1",
                    hash_secret=_fake_hash_secret,
                    encrypt_snippet=_fake_encrypt_snippet,
                    hmac_secret_key="pepper",
                )
        finally:
            shutil.rmtree(non_git_dir, ignore_errors=True)

    def test_respects_max_commits_cap(self, git_repo):
        # Commit a secret first, then pile on enough unrelated commits that
        # a max_commits=1 scan (only looking at the newest commit) can't
        # see the original secret-adding commit at all.
        _write_and_commit(
            git_repo,
            "config.py",
            f'STRIPE_KEY = "{MOCK_STRIPE_KEY}"\n',
            "add secret",
        )
        for i in range(3):
            _write_and_commit(git_repo, "notes.txt", f"note {i}\n", f"unrelated commit {i}")

        findings_full = scan_git_history(
            repo_path=git_repo,
            repo_id="repo-1",
            hash_secret=_fake_hash_secret,
            encrypt_snippet=_fake_encrypt_snippet,
            hmac_secret_key="pepper",
            max_commits=200,
        )
        findings_capped = scan_git_history(
            repo_path=git_repo,
            repo_id="repo-1",
            hash_secret=_fake_hash_secret,
            encrypt_snippet=_fake_encrypt_snippet,
            hmac_secret_key="pepper",
            max_commits=1,
        )

        assert len(findings_full) == 1
        assert len(findings_capped) == 0