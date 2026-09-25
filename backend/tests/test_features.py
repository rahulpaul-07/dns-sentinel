"""Unit tests for the DNS feature-extraction layer (backend/features.py).

These lock in the numerical behaviour of the 22-vector feature extractor so
future model or refactor work can't silently change detection inputs.
"""

import pytest

from features import (
    calculate_entropy,
    calculate_ngram_score,
    get_max_continuous_same_char,
    extract_features,
)


def test_entropy_empty_domain_is_zero():
    assert calculate_entropy("") == 0


def test_entropy_uniform_string_matches_log2_of_alphabet():
    # 4 distinct chars, each equally likely -> entropy == log2(4) == 2.0
    assert calculate_entropy("abcd") == pytest.approx(2.0)


def test_entropy_random_looking_domain_exceeds_regular_domain():
    dga = calculate_entropy("kq3z9xvbwp7f")
    normal = calculate_entropy("google")
    assert dga > normal


def test_ngram_score_short_domain_returns_floor():
    assert calculate_ngram_score("a") == 0.01


def test_ngram_score_english_beats_random():
    english = calculate_ngram_score("theinternet")
    random_ = calculate_ngram_score("zxqwkjvblq")
    assert english > random_


def test_max_continuous_same_char():
    assert get_max_continuous_same_char("aabbbc") == 3
    assert get_max_continuous_same_char("") == 0
    assert get_max_continuous_same_char("abc") == 1


def test_extract_features_returns_full_vector():
    feats = extract_features({"query": "example.com", "source_ip": "1.1.1.1"})
    expected_keys = {
        "entropy", "length", "subdomain_length", "ngram_score",
        "consonant_ratio", "digit_ratio", "unique_char",
        "vowels_consonant_ratio", "max_continuous_numeric_len",
        "max_continuous_alphabet_len", "max_continuous_consonants_len",
        "max_continuous_same_char", "upper_count", "lower_count",
        "special_count", "labels", "labels_max", "labels_average",
        "entropy_to_length_ratio", "high_entropy_flag", "domain_complexity",
    }
    assert expected_keys.issubset(feats.keys())


def test_extract_features_handles_empty_query_without_crashing():
    feats = extract_features({"query": ""})
    assert feats["length"] == 0
    assert feats["entropy"] == 0
    # ratios must not divide-by-zero
    assert feats["digit_ratio"] == 0
    assert feats["consonant_ratio"] == 0


def test_high_entropy_flag_trips_for_dga_like_domain():
    feats = extract_features({"query": "kq3z9xvbwp7ftgh2.com"})
    assert feats["high_entropy_flag"] == 1


def test_digit_ratio_is_bounded():
    feats = extract_features({"query": "12345.com"})
    assert 0.0 <= feats["digit_ratio"] <= 1.0
