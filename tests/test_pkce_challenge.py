"""
Unit tests for PKCE Challenge validation.

Tests for invalid code verifier characters as per RFC 7636:
- The code verifier should only contain unreserved characters: [A-Za-z0-9\-._~]
- Test inputs containing spaces, Unicode non-ASCII, and forbidden symbols
- Assert that the Pydantic model raises a validation error
- Add tests for valid cases to confirm no false positives
"""
import pytest
from pydantic import ValidationError

from mcp_vacuum.models.auth import PKCEChallenge


class TestPKCEChallengeValidation:
    """Test PKCE Challenge model validation for code verifier characters."""

    def test_valid_code_verifier_characters(self):
        """Test that valid code verifier characters are accepted."""
        # Valid characters: [A-Za-z0-9\-._~]
        valid_verifiers = [
            # Basic alphanumeric
            "A" * 43,  # Minimum length with uppercase
            "a" * 43,  # Minimum length with lowercase
            "0" * 43,  # Minimum length with digits
            
            # Mixed valid characters
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqr",  # 42 chars, one short
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrs",  # 43 chars exactly
            
            # Include all valid unreserved characters
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm-._~",  # 43 chars with special chars
            "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef-._~0123456789ABCDEFGHIJKLMNOP",  # 128 chars max
            
            # Hyphen, underscore, dot, tilde combinations
            "abc-def_ghi.jkl~mno" + "p" * 24,  # 43 chars with all valid special chars
            "test-verifier_with.valid~chars" + "0" * 12,  # 43 chars realistic example
        ]
        
        valid_challenge = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"  # Example valid challenge
        
        for verifier in valid_verifiers:
            # Should not raise ValidationError
            pkce = PKCEChallenge(
                code_verifier=verifier,
                code_challenge=valid_challenge,
                code_challenge_method="S256"
            )
            assert pkce.code_verifier == verifier
            assert len(pkce.code_verifier) >= 43
            assert len(pkce.code_verifier) <= 128

    def test_invalid_code_verifier_with_spaces(self):
        """Test that code verifier with spaces raises ValidationError."""
        invalid_verifiers_with_spaces = [
            " " + "A" * 42,  # Leading space
            "A" * 42 + " ",  # Trailing space
            "A" * 21 + " " + "A" * 21,  # Space in middle
            "test verifier with spaces" + "A" * 17,  # Multiple spaces
            "A A A A A A A A A A A A A A A A A A A A A A",  # Many spaces (43 chars)
        ]
        
        valid_challenge = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        
        for verifier in invalid_verifiers_with_spaces:
            with pytest.raises(ValidationError) as exc_info:
                PKCEChallenge(
                    code_verifier=verifier,
                    code_challenge=valid_challenge,
                    code_challenge_method="S256"
                )
            # Check that the error message mentions invalid characters
            assert "code_verifier" in str(exc_info.value).lower()

    def test_invalid_code_verifier_with_unicode_non_ascii(self):
        """Test that code verifier with Unicode non-ASCII characters raises ValidationError."""
        invalid_verifiers_unicode = [
            "café" + "A" * 39,  # Contains é (U+00E9)
            "résumé" + "A" * 37,  # Contains é and é
            "naïve" + "A" * 38,  # Contains ï (U+00EF)
            "京都" + "A" * 41,  # Japanese characters
            "🔐" + "A" * 39,  # Emoji (U+1F510)
            "Москва" + "A" * 37,  # Cyrillic characters
            "αβγδε" + "A" * 38,  # Greek characters
            "مرحبا" + "A" * 38,  # Arabic characters
        ]
        
        valid_challenge = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        
        for verifier in invalid_verifiers_unicode:
            with pytest.raises(ValidationError) as exc_info:
                PKCEChallenge(
                    code_verifier=verifier,
                    code_challenge=valid_challenge,
                    code_challenge_method="S256"
                )
            # Check that the error message mentions invalid characters
            assert "code_verifier" in str(exc_info.value).lower()

    def test_invalid_code_verifier_with_forbidden_symbols(self):
        """Test that code verifier with forbidden symbols raises ValidationError."""
        invalid_verifiers_symbols = [
            "test!" + "A" * 38,  # Exclamation mark
            "test@domain.com" + "A" * 28,  # At symbol
            "test#hashtag" + "A" * 31,  # Hash symbol
            "test$money" + "A" * 33,  # Dollar sign
            "test%percent" + "A" * 31,  # Percent sign
            "test^caret" + "A" * 33,  # Caret
            "test&ampersand" + "A" * 29,  # Ampersand
            "test*asterisk" + "A" * 30,  # Asterisk
            "test(parenthesis)" + "A" * 26,  # Parentheses
            "test+plus" + "A" * 34,  # Plus sign
            "test=equals" + "A" * 32,  # Equals sign
            "test[bracket]" + "A" * 30,  # Square brackets
            "test{brace}" + "A" * 32,  # Curly braces
            "test|pipe" + "A" * 34,  # Pipe
            "test\\backslash" + "A" * 29,  # Backslash
            "test:colon" + "A" * 33,  # Colon
            "test;semicolon" + "A" * 29,  # Semicolon
            'test"quote' + "A" * 33,  # Double quote
            "test'apostrophe" + "A" * 28,  # Single quote/apostrophe
            "test<less>" + "A" * 33,  # Angle brackets
            "test,comma" + "A" * 33,  # Comma
            "test?question" + "A" * 30,  # Question mark
            "test/slash" + "A" * 33,  # Forward slash
        ]
        
        valid_challenge = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        
        for verifier in invalid_verifiers_symbols:
            with pytest.raises(ValidationError) as exc_info:
                PKCEChallenge(
                    code_verifier=verifier,
                    code_challenge=valid_challenge,
                    code_challenge_method="S256"
                )
            # Check that the error message mentions invalid characters
            assert "code_verifier" in str(exc_info.value).lower()

    def test_invalid_code_verifier_mixed_invalid_characters(self):
        """Test code verifier with mixed invalid characters."""
        invalid_verifiers_mixed = [
            "test with spaces and! symbols" + "A" * 13,  # Spaces and symbols
            "café@example.com" + "A" * 27,  # Unicode and symbols
            "test 123!@#$%^&*()" + "A" * 26,  # Spaces and multiple symbols
            " unicode_café_with_spaces " + "A" * 16,  # Leading/trailing spaces with unicode
        ]
        
        valid_challenge = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        
        for verifier in invalid_verifiers_mixed:
            with pytest.raises(ValidationError) as exc_info:
                PKCEChallenge(
                    code_verifier=verifier,
                    code_challenge=valid_challenge,
                    code_challenge_method="S256"
                )
            # Check that the error message mentions invalid characters
            assert "code_verifier" in str(exc_info.value).lower()

    def test_valid_code_challenge_characters(self):
        """Test that code challenge validation doesn't produce false positives."""
        # Code challenges are base64url encoded, so they have a more restricted character set
        # Valid base64url characters: [A-Za-z0-9\-_] (no padding)
        valid_challenges = [
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",  # Standard SHA256 challenge
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",  # Another valid challenge
            "A" * 43,  # Minimum length
            "a" * 43,  # Lowercase
            "0" * 43,  # Numbers
            "A-_" * 14 + "A",  # 43 chars with valid base64url chars
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm" + "0-_",  # Mixed valid chars
        ]
        
        valid_verifier = "A" * 43  # Simple valid verifier
        
        for challenge in valid_challenges:
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
