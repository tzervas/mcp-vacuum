"""
Unit tests for PKCE Challenge validation.

Tests for invalid code verifier characters as per RFC 7636:
    - The code verifier should only contain unreserved characters: [A-Za-z0-9-._~]
- Test inputs containing spaces, Unicode non-ASCII, and forbidden symbols
- Assert that the Pydantic model raises a validation error
- Add tests for valid cases to confirm no false positives
"""
import pytest
from pydantic import ValidationError

from mcp_vacuum.models.auth import PKCEChallenge


@pytest.fixture
def valid_challenge():
    """Fixture providing a valid PKCE challenge string."""
    return "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"


@pytest.fixture
def valid_verifier():
    """Fixture providing a simple valid verifier string."""
    return "A" * 43


class TestPKCEChallengeValidation:
    """Test PKCE Challenge model validation for code verifier characters."""

    @pytest.mark.parametrize("verifier", [
        pytest.param("A" * 43, id="uppercase-min-length"),
        pytest.param("a" * 43, id="lowercase-min-length"),
        pytest.param("0" * 43, id="digits-min-length"),
        pytest.param("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrs", id="mixed-exact-length"),
        pytest.param("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm-._~", id="all-valid-chars"),
        pytest.param(
            "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef-._~0123456789ABCDEFGHIJKLMNOP",
            id="max-length"
        ),
        pytest.param("abc-def_ghi.jkl~mno" + "p" * 24, id="special-chars-mix"),
        pytest.param("test-verifier_with.valid~chars" + "0" * 12, id="realistic-example")
    ])
    def test_valid_code_verifier_characters(self, verifier, valid_challenge):
        """Test that valid code verifier characters are accepted."""
        # Should not raise ValidationError
        pkce = PKCEChallenge(
            code_verifier=verifier,
            code_challenge=valid_challenge,
            code_challenge_method="S256"
        )
        assert pkce.code_verifier == verifier
        assert len(pkce.code_verifier) >= 43
        assert len(pkce.code_verifier) <= 128

    @pytest.mark.parametrize("verifier", [
        pytest.param(" " + "A" * 42, id="leading-space"),
        pytest.param("A" * 42 + " ", id="trailing-space"),
        pytest.param("A" * 21 + " " + "A" * 21, id="middle-space"),
        pytest.param("test verifier with spaces" + "A" * 17, id="multiple-spaces"),
        pytest.param("A A A A A A A A A A A A A A A A A A A A A A", id="many-spaces")
    ])
    def test_invalid_code_verifier_with_spaces(self, verifier, valid_challenge):
        """Test that code verifier with spaces raises ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            PKCEChallenge(
                code_verifier=verifier,
                code_challenge=valid_challenge,
                code_challenge_method="S256"
            )
        # Check that the error message mentions invalid characters
        assert "code_verifier" in str(exc_info.value).lower()

    @pytest.mark.parametrize("verifier", [
        pytest.param("café" + "A" * 39, id="accented-e"),
        pytest.param("résumé" + "A" * 37, id="multiple-accents"),
        pytest.param("naïve" + "A" * 38, id="accented-i"),
        pytest.param("京都" + "A" * 41, id="japanese"),
        pytest.param("🔐" + "A" * 39, id="emoji"),
        pytest.param("Москва" + "A" * 37, id="cyrillic"),
        pytest.param("αβγδε" + "A" * 38, id="greek"),
        pytest.param("مرحبا" + "A" * 38, id="arabic")
    ])
    def test_invalid_code_verifier_with_unicode_non_ascii(self, verifier, valid_challenge):
        """Test that code verifier with Unicode non-ASCII characters raises ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            PKCEChallenge(
                code_verifier=verifier,
                code_challenge=valid_challenge,
                code_challenge_method="S256"
            )
        # Check that the error message mentions invalid characters
        assert "code_verifier" in str(exc_info.value).lower()

    @pytest.mark.parametrize("verifier", [
        pytest.param("test!" + "A" * 38, id="exclamation"),
        pytest.param("test@domain.com" + "A" * 28, id="at-symbol"),
        pytest.param("test#hashtag" + "A" * 31, id="hash"),
        pytest.param("test$money" + "A" * 33, id="dollar"),
        pytest.param("test%percent" + "A" * 31, id="percent"),
        pytest.param("test^caret" + "A" * 33, id="caret"),
        pytest.param("test&ampersand" + "A" * 29, id="ampersand"),
        pytest.param("test*asterisk" + "A" * 30, id="asterisk"),
        pytest.param("test(parenthesis)" + "A" * 26, id="parentheses"),
        pytest.param("test+plus" + "A" * 34, id="plus"),
        pytest.param("test=equals" + "A" * 32, id="equals"),
        pytest.param("test[bracket]" + "A" * 30, id="square-brackets"),
        pytest.param("test{brace}" + "A" * 32, id="curly-braces"),
        pytest.param("test|pipe" + "A" * 34, id="pipe"),
        pytest.param("test\\backslash" + "A" * 29, id="backslash"),
        pytest.param("test:colon" + "A" * 33, id="colon"),
        pytest.param("test;semicolon" + "A" * 29, id="semicolon"),
        pytest.param('test"quote' + "A" * 33, id="double-quote"),
        pytest.param("test'apostrophe" + "A" * 28, id="single-quote"),
        pytest.param("test<less>" + "A" * 33, id="angle-brackets"),
        pytest.param("test,comma" + "A" * 33, id="comma"),
        pytest.param("test?question" + "A" * 30, id="question-mark"),
        pytest.param("test/slash" + "A" * 33, id="forward-slash")
    ])
    def test_invalid_code_verifier_with_forbidden_symbols(self, verifier, valid_challenge):
        """Test that code verifier with forbidden symbols raises ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            PKCEChallenge(
                code_verifier=verifier,
                code_challenge=valid_challenge,
                code_challenge_method="S256"
            )
        # Check that the error message mentions invalid characters
        assert "code_verifier" in str(exc_info.value).lower()

    @pytest.mark.parametrize("verifier", [
        pytest.param("test with spaces and! symbols" + "A" * 13, id="spaces-and-symbols"),
        pytest.param("café@example.com" + "A" * 27, id="unicode-and-symbols"),
        pytest.param("test 123!@#$%^&*()" + "A" * 26, id="spaces-and-multiple-symbols"),
        pytest.param(" unicode_café_with_spaces " + "A" * 16, id="spaces-with-unicode")
    ])
    def test_invalid_code_verifier_mixed_invalid_characters(self, verifier, valid_challenge):
        """Test code verifier with mixed invalid characters."""
        with pytest.raises(ValidationError) as exc_info:
            PKCEChallenge(
                code_verifier=verifier,
                code_challenge=valid_challenge,
                code_challenge_method="S256"
            )
        # Check that the error message mentions invalid characters
        assert "code_verifier" in str(exc_info.value).lower()

    @pytest.mark.parametrize("challenge", [
        pytest.param("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", id="standard-sha256"),
        pytest.param("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", id="alternate-valid"),
        pytest.param("A" * 43, id="uppercase-min"),
        pytest.param("a" * 43, id="lowercase-min"),
        pytest.param("0" * 43, id="numbers-min"),
        pytest.param("A-_" * 14 + "A", id="base64url-chars"),
        pytest.param("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm" + "0-_", id="mixed-chars")
    ])
    def test_valid_code_challenge_characters(self, challenge, valid_verifier):
        """Test that code challenge validation doesn't produce false positives."""
        # Should not raise ValidationError
        pkce = PKCEChallenge(
            code_verifier=valid_verifier,
            code_challenge=challenge,
            code_challenge_method="S256"
        )
        assert pkce.code_challenge == challenge
        assert len(pkce.code_challenge) >= 43
        assert len(pkce.code_challenge) <= 128

    def test_length_validation_still_works(self):
        """Test that length validation still works alongside character validation."""
        valid_challenge = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        
        # Test minimum length violation (less than 43 chars)
        with pytest.raises(ValidationError) as exc_info:
            PKCEChallenge(
                code_verifier="A" * 42,  # One char short
                code_challenge=valid_challenge,
                code_challenge_method="S256"
            )
        assert "at least 43 characters" in str(exc_info.value) or "min_length" in str(exc_info.value)
        
        # Test maximum length violation (more than 128 chars)
        with pytest.raises(ValidationError) as exc_info:
            PKCEChallenge(
                code_verifier="A" * 129,  # One char over
                code_challenge=valid_challenge,
                code_challenge_method="S256"
            )
        assert "at most 128 characters" in str(exc_info.value) or "max_length" in str(exc_info.value)

    def test_edge_cases(self):
        """Test edge cases for character validation."""
        valid_challenge = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        
        # Empty string (should fail on length first)
        with pytest.raises(ValidationError):
            PKCEChallenge(
                code_verifier="",
                code_challenge=valid_challenge,
                code_challenge_method="S256"
            )
        
        # Only invalid characters (should fail on character validation)
        with pytest.raises(ValidationError):
            PKCEChallenge(
                code_verifier="!" * 43,  # 43 invalid chars
                code_challenge=valid_challenge,
                code_challenge_method="S256"
            )
        
        # Valid length but one invalid character
        with pytest.raises(ValidationError):
            PKCEChallenge(
                code_verifier="A" * 42 + "!",  # 42 valid + 1 invalid = 43 chars
                code_challenge=valid_challenge,
                code_challenge_method="S256"
            )
