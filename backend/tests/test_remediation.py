"""
Tests for ai/remediation.py (Phase 6: AI-powered remediation suggestions).

These tests use a small fake Groq client rather than hitting the real
Groq API, so they run offline and deterministically.
"""

from __future__ import annotations

from ai.remediation import suggest_fix


class _FakeMessage:
    def __init__(self, content: str):
        self.content = content


class _FakeChoice:
    def __init__(self, content: str):
        self.message = _FakeMessage(content)


class _FakeCompletion:
    def __init__(self, content: str):
        self.choices = [_FakeChoice(content)]


class _FakeCompletions:
    def __init__(self, content: str, raise_error: bool = False):
        self._content = content
        self._raise_error = raise_error
        self.last_kwargs: dict | None = None

    def create(self, **kwargs):
        self.last_kwargs = kwargs
        if self._raise_error:
            raise RuntimeError("simulated Groq API failure")
        return _FakeCompletion(self._content)


class _FakeChat:
    def __init__(self, content: str, raise_error: bool = False):
        self.completions = _FakeCompletions(content, raise_error=raise_error)


class _FakeGroqClient:
    def __init__(self, content: str = "fixed snippet here", raise_error: bool = False):
        self.chat = _FakeChat(content, raise_error=raise_error)


def _semgrep_finding(**overrides) -> dict:
    finding = {
        "file_path": "src/app.js",
        "line_number": 42,
        "secret_type": "frontend-react-dangerously-set-innerhtml",
        "rule_name": "frontend-react-dangerously-set-innerhtml",
        "severity": "CRITICAL",
        "snippet": "<div dangerouslySetInnerHTML={{__html: props.comment}} />",
        "owasp_category": "A03:2021",
        "source_type": "semgrep",
    }
    finding.update(overrides)
    return finding


class TestSuggestFixGuardClauses:
    def test_returns_none_when_groq_client_is_none(self):
        finding = _semgrep_finding()

        assert suggest_fix(finding, None) is None

    def test_returns_none_when_snippet_is_empty(self):
        finding = _semgrep_finding(snippet="")

        assert suggest_fix(finding, _FakeGroqClient()) is None

    def test_returns_none_when_snippet_is_whitespace_only(self):
        finding = _semgrep_finding(snippet="   \n  ")

        assert suggest_fix(finding, _FakeGroqClient()) is None

    def test_returns_none_and_does_not_raise_on_api_failure(self):
        finding = _semgrep_finding()
        client = _FakeGroqClient(raise_error=True)

        assert suggest_fix(finding, client) is None


class TestSuggestFixSuccess:
    def test_returns_model_output_on_success(self):
        finding = _semgrep_finding()
        client = _FakeGroqClient(content="Use textContent instead. This avoids raw HTML injection.")

        result = suggest_fix(finding, client)

        assert result == "Use textContent instead. This avoids raw HTML injection."

    def test_strips_thinking_tags_from_model_output(self):
        finding = _semgrep_finding()
        client = _FakeGroqClient(
            content="<thinking>reasoning about the fix</thinking>Use textContent instead."
        )

        result = suggest_fix(finding, client)

        assert result == "Use textContent instead."

    def test_prompt_includes_rule_name_owasp_category_and_snippet(self):
        finding = _semgrep_finding()
        client = _FakeGroqClient()

        suggest_fix(finding, client)

        prompt = client.chat.completions.last_kwargs["messages"][-1]["content"]
        assert finding["rule_name"] in prompt
        assert finding["owasp_category"] in prompt
        assert finding["file_path"] in prompt
        assert finding["snippet"] in prompt

    def test_falls_back_to_secret_type_when_rule_name_missing(self):
        finding = _semgrep_finding(rule_name=None, secret_type="some-rule")
        client = _FakeGroqClient()

        suggest_fix(finding, client)

        prompt = client.chat.completions.last_kwargs["messages"][-1]["content"]
        assert "some-rule" in prompt

    def test_returns_none_when_model_output_is_empty(self):
        finding = _semgrep_finding()
        client = _FakeGroqClient(content="")

        assert suggest_fix(finding, client) is None