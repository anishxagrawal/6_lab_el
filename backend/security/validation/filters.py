import re
from pathlib import Path

IGNORED_PATHS = [
    "docs/",
    "examples/",
    "example/",
    "samples/",
    "sample/",
    "fixtures/",
    "mock/",
    "tests/",
    "__tests__/",
    "demo/",
    "vulnerable_frontend_demo/",
    "playground/",
    "tutorial/",
]

IGNORED_FILES = [
    ".env.example",
    ".env.sample",
    "readme.md",
    "readme.txt",
    "readme",
]

MOCK_CRED_KEYWORDS = [
    "your-",
    "your_",
    "placeholder",
    "mock-",
    "mock_",
    "test-",
    "test_",
    "dummy-",
    "dummy_",
    "example-",
    "example_",
    "my-secret",
    "api_key_here",
    "insert_here",
    "foo_bar",
    "00000000000",
    "1234567890",
]

def is_ignored_finding(file_path: str, snippet: str, secret_value: str = "") -> bool:
    """
    Apply Rule 1 & Rule 2 to reject findings that belong to documentation,
    examples, mock setups, or test environments.
    """
    path_lower = file_path.replace("\\", "/").lower()
    
    # Rule 1: Ignored paths
    if any(ignored in path_lower for ignored in IGNORED_PATHS):
        return True

    # Rule 2: Ignored files
    filename = Path(path_lower).name
    if any(ignored == filename for ignored in IGNORED_FILES):
        return True

    # Ignored mock credentials & placeholders in snippet/value
    lower_snippet = snippet.lower()
    lower_val = secret_value.lower()
    
    for keyword in MOCK_CRED_KEYWORDS:
        if keyword in lower_snippet or (lower_val and keyword in lower_val):
            return True

    # Ignore obvious dummy/placeholder secrets (e.g. sk_live_yourkeyhere)
    if "your" in lower_val or "placeholder" in lower_val or "dummy" in lower_val or "example" in lower_val:
        return True

    return False
