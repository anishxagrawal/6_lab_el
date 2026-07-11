"""
Unit tests for security/github_clone.py's URL validation/parsing helpers.
No network access or actual git calls involved.
"""

from __future__ import annotations

import pytest

from security.github_clone import InvalidRepositoryUrlError, parse_github_url


class TestParseGithubUrl:
    def test_parses_owner_and_name(self):
        assert parse_github_url("https://github.com/octocat/hello-world") == (
            "octocat",
            "hello-world",
        )

    def test_strips_dot_git_suffix(self):
        assert parse_github_url("https://github.com/octocat/hello-world.git") == (
            "octocat",
            "hello-world",
        )

    def test_strips_trailing_slash(self):
        assert parse_github_url("https://github.com/octocat/hello-world/") == (
            "octocat",
            "hello-world",
        )

    def test_strips_trailing_slash_and_dot_git_together(self):
        assert parse_github_url("https://github.com/octocat/hello-world.git/") == (
            "octocat",
            "hello-world",
        )

    @pytest.mark.parametrize(
        "bad_url",
        [
            "not-a-url",
            "http://github.com/octocat/hello-world",  # not https
            "https://gitlab.com/octocat/hello-world",  # not github.com
            "https://github.com/octocat",  # missing repo name
            "https://github.com/--upload-pack=touch /tmp/pwned;/x",  # injection attempt
            "",
        ],
    )
    def test_rejects_invalid_urls(self, bad_url):
        with pytest.raises(InvalidRepositoryUrlError):
            parse_github_url(bad_url)