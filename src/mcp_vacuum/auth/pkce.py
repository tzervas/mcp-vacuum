"""
PKCE (Proof Key for Code Exchange) utilities for OAuth 2.1.
As per RFC 7636.
"""
import secrets
import hashlib
import base64
from typing import Tuple

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
    code_verifier = secrets.token_urlsafe(96)
    if code_challenge_method == "S256":
        # Transform the code verifier using SHA256
        hashed_verifier = hashlib.sha256(code_verifier.encode("ascii")).digest()
        # Base64url-encode the hashed verifier
        code_challenge = base64.urlsafe_b64encode(hashed_verifier).decode("ascii").rstrip("=")
    elif code_challenge_method == "plain":
        # For "plain", the code_challenge is the same as the code_verifier
        # Note: "plain" is NOT RECOMMENDED for production unless S256 is unavailable.
        code_challenge = code_verifier
    else:
        raise ValueError(f"Unsupported code_challenge_method: {code_challenge_method}. Must be 'S256' or 'plain'.")

    return PKCEChallenge(
        code_verifier=code_verifier,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
    )

if __name__ == '__main__':
    # Example usage:
    pkce_pair_s256 = generate_pkce_challenge_pair(code_challenge_method="S256")
    print("S256 PKCE Pair:")
    print(f"  Verifier: {pkce_pair_s256.code_verifier}")
    print(f"  Challenge: {pkce_pair_s256.code_challenge}")
    print(f"  Method: {pkce_pair_s256.code_challenge_method}")
    assert len(pkce_pair_s256.code_verifier) >= 43 and len(pkce_pair_s256.code_verifier) <= 128

    try:
        pkce_pair_plain = generate_pkce_challenge_pair(code_challenge_method="plain")
        print("\nPlain PKCE Pair (for testing/compatibility only):")
        print(f"  Verifier: {pkce_pair_plain.code_verifier}")
        print(f"  Challenge: {pkce_pair_plain.code_challenge}")
        print(f"  Method: {pkce_pair_plain.code_challenge_method}")
        assert pkce_pair_plain.code_challenge == pkce_pair_plain.code_verifier
    except ValueError as e:
        print(f"\nError generating plain PKCE pair: {e}") # Should not happen with "plain"

    try:
        generate_pkce_challenge_pair(code_challenge_method="MD5")
    except ValueError as e:
        print(f"\nSuccessfully caught error for unsupported method: {e}")

    # Verify verifier length constraints (example with a different token length)
    # For a verifier of length 43 (minimum allowed)
    min_len_verifier = secrets.token_urlsafe(32)[:43]
    min_len_challenge = base64.urlsafe_b64encode(hashlib.sha256(min_len_verifier.encode("ascii")).digest()).decode("ascii").rstrip("=")
    print(f"\nMin length verifier ({len(min_len_verifier)}): {min_len_verifier}")
    print(f"Min length challenge ({len(min_len_challenge)}): {min_len_challenge}")
    assert len(min_len_verifier) == 43

    # Max length verifier (128) is already tested by default.
    # pkce_max_len_pair = generate_pkce_challenge_pair()
    # assert len(pkce_max_len_pair.code_verifier) == 128
