"""
PKCE (Proof Key for Code Exchange) utilities for OAuth 2.1.
As per RFC 7636.
"""
import base64
import hashlib
import secrets

from ..models.auth import PKCEChallenge


def generate_pkce_challenge_pair(code_challenge_method: str = "S256") -> PKCEChallenge:
    """
    Generates a PKCE code_verifier and a corresponding code_challenge.

    Args:
        code_challenge_method: The method used to generate the challenge.
                               Currently supports "S256" or "plain".

    Returns:
        A PKCEChallenge object containing the verifier, challenge, and method.

    Raises:
        ValueError: If an unsupported code_challenge_method is provided.
    """
    # The following condition was a no-op and has been removed.
    # if not 43 <= 128 <= 128: # Standard length constraints for verifier
    #     # This is a fixed range, but good to be aware if it were configurable
    #     # For verifier: min 43, max 128 chars. secrets.token_urlsafe(96) gives 128 chars.
    #     # secrets.token_urlsafe(32) gives ~43 chars. Let's aim for a good length.
    #     pass

    # Generate a high-entropy cryptographic random string as the code verifier
    # RFC 7636 recommends a length between 43 and 128 characters.
    # secrets.token_urlsafe(n) returns a URL-safe text string, containing n random bytes.
    # Each byte is encoded to roughly 1.3 characters (log_64(256)).
    # So, for 128 chars, need 128 / 1.33 ~= 96 bytes.
    # For 43 chars, need 43 / 1.33 ~= 32 bytes.
    # We'll use a verifier length that's substantial, e.g., 96 bytes -> 128 chars.
    # Generate a secure random verifier of approximately 96 chars (72 bytes)
    # This gives us plenty of entropy while staying within the 43-128 char limit
    verifier_bytes = secrets.token_bytes(72)  # (72 * 8 / 6) ≈ 96 base64 chars
    code_verifier = base64.urlsafe_b64encode(verifier_bytes).decode('ascii').rstrip('=')
    
    # Let PKCEChallenge handle validation of the verifier length and character set
    # The length will be ~96 chars, well within the 43-128 limit

    if code_challenge_method == "S256":
        # Transform the code verifier using SHA256
        hashed_verifier = hashlib.sha256(code_verifier.encode("ascii")).digest()
        # Base64url-encode the hashed verifier
        code_challenge = (
            base64.urlsafe_b64encode(hashed_verifier).decode("ascii").rstrip("=")
        )
    elif code_challenge_method == "plain":
        # For "plain", the code_challenge is the same as the code_verifier
        # Note: "plain" is NOT RECOMMENDED for production unless S256 is
        # unavailable.
        code_challenge = code_verifier
    else:
        raise ValueError(
            f"Unsupported code_challenge_method: {code_challenge_method}. "
            "Must be 'S256' or 'plain'."
        )

    return PKCEChallenge(
        code_verifier=code_verifier,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
    )

# The __main__ block below was for example usage and has been removed to
# address S101 (asserts) and PLR2004 (magic values) Ruff warnings,
# as it's not part of the library's core functionality.
# Tests for this functionality are in tests/test_pkce.py.
