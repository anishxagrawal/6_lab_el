"""
Tests for security/entropy.py — Shannon entropy scoring and high-entropy
token detection (Phase 2: catches secrets that don't match a named regex
pattern in secret_scanner.py).
"""

from security.entropy import find_high_entropy_tokens, shannon_entropy


class TestShannonEntropy:
    def test_empty_string_has_zero_entropy(self):
        assert shannon_entropy("") == 0.0

    def test_single_repeated_character_has_zero_entropy(self):
        assert shannon_entropy("aaaaaaaaaa") == 0.0

    def test_random_looking_string_has_high_entropy(self):
        # A 32-char string mixing case + digits should land well above 4.0
        random_like = "a1B9x7Qm2Zk8Ln4Rp6Ty0Wc3Fe5Hj1S"

        assert shannon_entropy(random_like) > 4.0

    def test_predictable_english_word_has_lower_entropy_than_random_token(self):
        english_word = "thisisaverylongreadablesentence"
        random_token = "a1B9x7Qm2Zk8Ln4Rp6Ty0Wc3Fe5Hj1S"

        assert shannon_entropy(english_word) < shannon_entropy(random_token)

    def test_pure_hex_string_caps_below_mixed_charset_entropy(self):
        # Hex has a 16-symbol alphabet (max 4.0 bits/char theoretically),
        # base64-like has a much larger alphabet - hex should score lower.
        hex_string = "7f3a9c1e5b8d2046af90c3e7b1d5f8a2"
        mixed_string = "a1B9x7Qm2Zk8Ln4Rp6Ty0Wc3Fe5Hj1Sd"

        assert shannon_entropy(hex_string) < shannon_entropy(mixed_string)


class TestFindHighEntropyTokens:
    def test_detects_random_looking_token(self):
        line = 'INTERNAL_TOKEN = "a1B9x7Qm2Zk8Ln4Rp6Ty0Wc3Fe5Hj1Sd9Va7Xb"'

        hits = find_high_entropy_tokens(line)

        assert len(hits) == 1
        assert hits[0]["token"] == "a1B9x7Qm2Zk8Ln4Rp6Ty0Wc3Fe5Hj1Sd9Va7Xb"

    def test_detects_hex_secret_via_hex_specific_threshold(self):
        line = 'SECRET_TOKEN = "7f3a9c1e5b8d2046af90c3e7b1d5f8a2c6e0941"'

        hits = find_high_entropy_tokens(line)

        assert len(hits) == 1

    def test_no_false_positive_on_normal_python_function(self):
        line = "def calculate_exposure_score(severity, days): return severity_rank * math.log2(days+2)"

        assert find_high_entropy_tokens(line) == []

    def test_no_false_positive_on_import_statement(self):
        line = 'import { useState, useEffect } from "react";'

        assert find_high_entropy_tokens(line) == []

    def test_no_false_positive_on_url(self):
        line = 'raw_url = f"https://raw.githubusercontent.com/{owner}/{name}/HEAD/{file_path}"'

        assert find_high_entropy_tokens(line) == []

    def test_no_false_positive_on_long_camel_case_identifier(self):
        line = "    def processOrderAndCalculateFinalTotalForCustomer(self, order):"

        assert find_high_entropy_tokens(line) == []

    def test_threshold_parameter_is_respected(self):
        line = 'TOKEN = "a1B9x7Qm2Zk8Ln4Rp6Ty0Wc3Fe5Hj1Sd9Va7Xb"'

        # An unreasonably high threshold should suppress the same hit
        # that the default threshold catches.
        assert find_high_entropy_tokens(line) != []
        assert find_high_entropy_tokens(line, threshold=7.5) == []

    def test_repetitive_numeric_id_is_not_flagged(self):
        # Low-diversity numeric IDs (mostly-repeated digits) score low
        # entropy and correctly aren't flagged.
        line = "order_reference = 11111111111111111111111111112222"

        assert find_high_entropy_tokens(line) == []

    def test_evenly_distributed_digit_sequence_can_still_be_flagged(self):
        # Documented limitation: a numeric string using all 10 digits
        # roughly equally (e.g. a sequential-looking ID) can score as
        # "random" as a real hex secret under Shannon entropy alone,
        # since entropy only measures symbol frequency, not semantic
        # meaning. This is a known tradeoff of entropy-based detection
        # (shared by tools like gitleaks/trufflehog), not a bug.
        line = "order_reference = 12345678901234567890123456789012"

        hits = find_high_entropy_tokens(line)

        assert len(hits) == 1