"""
Tests for core/exposure.py — exposure scoring (severity_rank x log2(days+2)).
"""

import math

from core.exposure import calculate_exposure_score


class TestCalculateExposureScore:
    def test_zero_days_matches_formula(self):
        # severity_rank(LOW) = 1, log2(0 + 2) = 1.0 -> score = 1.0
        score = calculate_exposure_score("LOW", 0)

        assert score == 1.0

    def test_score_increases_with_more_exposure_days(self):
        score_at_zero_days = calculate_exposure_score("HIGH", 0)
        score_at_ninety_days = calculate_exposure_score("HIGH", 90)

        assert score_at_ninety_days > score_at_zero_days

    def test_score_matches_manual_formula_for_arbitrary_input(self):
        severity_rank = 3  # HIGH
        exposure_days = 30

        expected = round(severity_rank * math.log2(exposure_days + 2), 2)
        actual = calculate_exposure_score("HIGH", exposure_days)

        assert actual == expected

    def test_severity_ordering_for_same_exposure_days(self):
        days = 15

        critical_score = calculate_exposure_score("CRITICAL", days)
        high_score = calculate_exposure_score("HIGH", days)
        medium_score = calculate_exposure_score("MEDIUM", days)
        low_score = calculate_exposure_score("LOW", days)

        assert critical_score > high_score > medium_score > low_score

    def test_negative_days_are_clamped_to_zero(self):
        score_with_negative_days = calculate_exposure_score("LOW", -100)
        score_with_zero_days = calculate_exposure_score("LOW", 0)

        assert score_with_negative_days == score_with_zero_days

    def test_unknown_severity_defaults_to_rank_one(self):
        score_for_unknown = calculate_exposure_score("NOT_A_REAL_SEVERITY", 0)
        score_for_low = calculate_exposure_score("LOW", 0)

        assert score_for_unknown == score_for_low

    def test_severity_is_case_insensitive(self):
        assert calculate_exposure_score("critical", 10) == calculate_exposure_score("CRITICAL", 10)