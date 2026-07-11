from __future__ import annotations

import math
import re

# Candidate "looks like a token" substrings: 20+ chars of letters, digits,
# and the symbols commonly found in base64/API-key style tokens.
# Deliberately excludes "/" - it's the single biggest source of false
# positives (URL paths look high-entropy but aren't secrets), and any
# secret type that legitimately needs "/" (e.g. base64 AWS keys) is already
# covered by the named regex PATTERNS in secret_scanner.py.
TOKEN_CANDIDATE_RE = re.compile(r"[A-Za-z0-9+_=\-]{20,}")

# Pure-hex tokens (commit hashes, hex-encoded secrets/API keys) use a
# 16-symbol alphabet, so their theoretical max entropy is 4.0 bits/char -
# a base64-tuned 4.0 threshold would almost never fire on them. They get
# their own detector with a lower, hex-appropriate threshold.
HEX_CANDIDATE_RE = re.compile(r"\b[0-9a-fA-F]{32,}\b")

# Requires the candidate to actually mix letters and digits - filters out
# long English identifiers/words (camelCase, snake_case) that read as
# high-entropy purely from letter variety but aren't token-shaped.
_HAS_DIGIT_RE = re.compile(r"\d")
_HAS_LETTER_RE = re.compile(r"[A-Za-z]")

# Standard starting thresholds. Base64/mixed-charset tokens (~4.0) and
# pure-hex tokens (~3.0) need different cutoffs because their alphabets
# have different theoretical maximums (log2(64)=6.0 vs log2(16)=4.0).
DEFAULT_ENTROPY_THRESHOLD = 4.0
HEX_ENTROPY_THRESHOLD = 3.0


def shannon_entropy(value: str) -> float:
    """
    Compute the Shannon entropy of a string, in bits per character.

    Low entropy (~0-2): repetitive/predictable text ("aaaaaaaa", "helloworld").
    High entropy (~4.5-6): looks close to random noise, characteristic of
    generated tokens, keys, and hashes.
    """
    if not value:
        return 0.0

    length = len(value)
    frequency: dict[str, int] = {}
    for ch in value:
        frequency[ch] = frequency.get(ch, 0) + 1

    entropy = 0.0
    for count in frequency.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def find_high_entropy_tokens(
    line: str,
    threshold: float = DEFAULT_ENTROPY_THRESHOLD,
    hex_threshold: float = HEX_ENTROPY_THRESHOLD,
) -> list[dict[str, float | int | str]]:
    """
    Scan a single line of source code for token-like substrings whose
    Shannon entropy exceeds `threshold`, and return each as a small dict
    with the token itself, its entropy score, and its column offset.

    This exists to catch secrets that don't match any of the named regex
    PATTERNS in secret_scanner.py (custom/internal tokens, one-off API
    keys, etc.) by looking at how "random" a string looks rather than
    relying on a known prefix. Runs two passes with different thresholds:
    one for mixed-charset (base64-like) tokens, one for pure-hex tokens,
    since hex's smaller alphabet caps its max possible entropy lower.
    """
    results: list[dict[str, float | int | str]] = []
    seen_spans: set[tuple[int, int]] = set()

    for match in TOKEN_CANDIDATE_RE.finditer(line):
        token = match.group(0)

        if not (_HAS_DIGIT_RE.search(token) and _HAS_LETTER_RE.search(token)):
            continue

        score = shannon_entropy(token)

        if score >= threshold:
            span = (match.start(), match.end())
            seen_spans.add(span)
            results.append(
                {
                    "token": token,
                    "entropy": round(score, 2),
                    "start": match.start(),
                }
            )

    for match in HEX_CANDIDATE_RE.finditer(line):
        span = (match.start(), match.end())
        if span in seen_spans:
            continue  # already caught by the mixed-charset pass above

        token = match.group(0)
        score = shannon_entropy(token)

        if score >= hex_threshold:
            results.append(
                {
                    "token": token,
                    "entropy": round(score, 2),
                    "start": match.start(),
                }
            )

    return results