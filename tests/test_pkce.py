"""
Unit tests for PKCE generation utilities.
"""
import pytest
import re
import hashlib
import base64

from mcp_vacuum.auth.pkce import generate_pkce_challenge_pair
from mcp_vacuum.models.auth import PKCEChallenge

def test_generate_pkce_s256():
    """Test S256 PKCE challenge generation."""
    pkce_pair = generate_pkce_challenge_pair(code_challenge_method="S256")

    assert isinstance(pkce_pair, PKCEChallenge)
    assert pkce_pair.code_challenge_method == "S256"

    # Verifier constraints are validated by the PKCEChallenge model
    # Default generation aims for 128 characters.
    assert len(pkce_pair.code_verifier) == 128 # Current generate_pkce_challenge_pair behavior
    assert re.match(r"^[A-Za-z0-9\-._~]*$", pkce_pair.code_verifier), "Verifier contains invalid characters"


    # Challenge constraints (Base64url encoding of SHA256 hash)
    # SHA256 digest is 32 bytes. Base64url encoding of 32 bytes is 43 characters ( (32 * 4/3) rounded up, then remove padding).
    # (Actually, (32 * 8 / 6) = 42.66, so 43 chars. Example: `echo -n "test" | sha256sum | head -c 32 | base64url` needs 32 bytes input for hash)
    # The digest of the verifier should result in a 43-char challenge after base64url encoding and padding removal.
    expected_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(pkce_pair.code_verifier.encode("ascii")).digest()
    ).decode("ascii").rstrip("=")
    assert pkce_pair.code_challenge == expected_challenge
    assert len(pkce_pair.code_challenge) == 43 # Base64URL of SHA256 hash is always 43 chars

def test_generate_pkce_plain():
    """Test 'plain' PKCE challenge generation."""
    pkce_pair = generate_pkce_challenge_pair(code_challenge_method="plain")

    assert isinstance(pkce_pair, PKCEChallenge)
    assert pkce_pair.code_challenge_method == "plain"
    # Verifier constraints are validated by the PKCEChallenge model
    # Default generation aims for 128 characters.
    assert len(pkce_pair.code_verifier) == 128 # Current generate_pkce_challenge_pair behavior
    assert re.match(r"^[A-Za-z0-9\-._~]*$", pkce_pair.code_verifier)

    # For "plain", challenge is the same as verifier
    assert pkce_pair.code_challenge == pkce_pair.code_verifier

def test_generate_pkce_unsupported_method():
    """Test error handling for unsupported challenge methods."""
    with pytest.raises(ValueError) as excinfo:
        generate_pkce_challenge_pair(code_challenge_method="MD5")
    assert "Unsupported code_challenge_method: MD5" in str(excinfo.value)

def test_pkce_verifier_default_generation():
    """Test that the default generate_pkce_challenge_pair function generates a verifier of max allowed length."""
    for _ in range(10):  # Repeat a few times for randomness
        pkce_pair = generate_pkce_challenge_pair()  # Defaults to S256
        # The model PKCEChallenge validates 43 <= len <= 128.
        # The current implementation of generate_pkce_challenge_pair aims for max length (128).
        assert len(pkce_pair.code_verifier) == 128

        pkce_pair_plain = generate_pkce_challenge_pair(code_challenge_method="plain")
        assert len(pkce_pair_plain.code_verifier) == 128


@pytest.mark.parametrize("verifier_length", [43, 64, 128]) # Test min, mid, and max
def test_pkce_model_accepts_various_verifier_lengths(verifier_length):
    """Test that the PKCEChallenge model accepts verifiers of various allowed lengths."""
    import secrets
    import string

    # Generate a verifier of the specified length using allowed characters
    # RFC 7636: code-verifier = high-entropy cryptographic random STRING using the unreserved characters
    # [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
    allowed_chars = string.ascii_letters + string.digits + "-._~"
    code_verifier = ''.join(secrets.choice(allowed_chars) for _ in range(verifier_length))

    # Test S256 method
    pkce_s256 = PKCEChallenge(code_verifier=code_verifier, code_challenge_method="S256")
    assert len(pkce_s256.code_verifier) == verifier_length
    expected_challenge_s256 = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode("ascii")).digest()
    ).decode("ascii").rstrip("=")
    assert pkce_s256.code_challenge == expected_challenge_s256

    # Test plain method
    pkce_plain = PKCEChallenge(code_verifier=code_verifier, code_challenge_method="plain")
    assert len(pkce_plain.code_verifier) == verifier_length
    assert pkce_plain.code_challenge == code_verifier


def test_pkce_model_rejects_invalid_verifier_lengths():
    """Test that the PKCEChallenge model rejects verifiers of invalid lengths."""
    # Too short
    with pytest.raises(ValueError): # Pydantic validation error
        PKCEChallenge(code_verifier="A"*42, code_challenge_method="S256")
    # Too long
    with pytest.raises(ValueError): # Pydantic validation error
        PKCEChallenge(code_verifier="A"*129, code_challenge_method="S256")


def test_pkce_minimum_length_verifier_challenge_computation():
    """Test that a 43-character code_verifier is accepted and challenge is computed correctly by the model."""
    min_length_verifier = "A" * 43 # Example min length verifier

    # S256 method
    pkce_s256 = PKCEChallenge(
        code_verifier=min_length_verifier,
        code_challenge_method="S256"
    )
    expected_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(min_length_verifier.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")
    assert pkce_s256.code_challenge == expected_challenge
    assert len(pkce_s256.code_verifier) == 43

    # plain method
    pkce_plain = PKCEChallenge(
        code_verifier=min_length_verifier,
        code_challenge_method="plain"
    )
    assert pkce_plain.code_challenge == min_length_verifier
    assert len(pkce_plain.code_verifier) == 43
