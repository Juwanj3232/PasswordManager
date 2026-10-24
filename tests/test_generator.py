"""
Unit tests for password and passphrase generation, randomness, and entropy metrics.
"""

import string
from src.crypto.generator import (
    AMBIGUOUS_CHARS,
    calculate_entropy,
    generate_passphrase,
    generate_password,
)


def test_password_length_and_sets():
    """Generated password must match requested length and include required character sets."""
    pwd = generate_password(
        length=24,
        use_upper=True,
        use_lower=True,
        use_digits=True,
        use_symbols=True,
    )
    assert len(pwd) == 24
    assert any(c in string.ascii_uppercase for c in pwd)
    assert any(c in string.ascii_lowercase for c in pwd)
    assert any(c in string.digits for c in pwd)
    assert any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?/~" for c in pwd)


def test_exclude_ambiguous():
    """Generated password must omit ambiguous glyphs when exclude_ambiguous is True."""
    for _ in range(20):
        pwd = generate_password(length=32, exclude_ambiguous=True)
        assert all(c not in AMBIGUOUS_CHARS for c in pwd)


def test_passphrase_generation():
    """Generated passphrase must respect word count, separator, and capitalization."""
    phrase = generate_passphrase(
        word_count=5,
        separator=".",
        capitalize=True,
        include_number=True,
    )
    parts = phrase.split(".")
    assert len(parts) == 5
    assert all(p[0].isupper() for p in parts)
    assert any(any(c.isdigit() for c in p) for p in parts)


def test_entropy_calculation():
    """Entropy score should accurately classify weak vs strong passwords."""
    weak = calculate_entropy("123456")
    assert weak["score"] < 40
    assert weak["rating"] == "Very Weak"

    strong = calculate_entropy("9X#kP$2mQ!zL@7vW&4rT")
    assert strong["score"] > 80
    assert strong["rating"] in ("Strong", "Very Strong")
    assert strong["bits"] > 80
