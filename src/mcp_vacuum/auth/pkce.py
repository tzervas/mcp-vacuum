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
    # Generate a verifier of exactly 128 characters from a 96-byte token.
    # This ensures maximum length and entropy as per common practice.
    # The model PKCEChallenge will validate if the length is within 43-128.
    # 96 bytes will give us a 128-character string: (96 * 8) / 6 = 128 chars
    verifier_bytes = secrets.token_bytes(96)
    code_verifier = base64.urlsafe_b64encode(verifier_bytes).decode('ascii').rstrip('=')
    
    # Ensure exactly 128 characters even if urlsafe_b64encode behaves unexpectedly
    if len(code_verifier) > 128:
        code_verifier = code_verifier[:128]
    elif len(code_verifier) < 128:
        # Pad with 'A' up to 128 chars if encoding produces less (should never happen)
        code_verifier = code_verifier.ljust(128, 'A')

    # The code_verifier is now guaranteed to be exactly 128 characters
    # Let PKCEChallenge handle any other validation

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
