import base64
import hashlib
import time
from enum import Enum
from typing import Any

from pydantic import Field, HttpUrl, model_validator

from .common import BasePydanticModel


class AuthMethod(str, Enum):
    """Enum for supported authentication methods."""
    OAUTH2 = 'oauth2'
    NONE = 'none'


class PKCEChallenge(BasePydanticModel):
    # RFC 7636: unreserved characters only [A-Za-z0-9-._~], length 43–128
    code_verifier: str = Field(
        ...,
        min_length=43,
        max_length=128,
        pattern=r"^[A-Za-z0-9\-._~]+$",
        description="PKCE code_verifier (RFC 7636 unreserved charset)",
    )
    code_challenge: str | None = Field(
        default=None,
        min_length=43,
        max_length=128,
        pattern=r"^[A-Za-z0-9\-._~]+$",
        description="PKCE code_challenge (RFC 7636 unreserved charset); computed if omitted",
    )
    code_challenge_method: str = Field(default="S256")

    @model_validator(mode="before")
    @classmethod
    def _compute_challenge_if_missing(cls, data: Any) -> Any:
        """Derive code_challenge from code_verifier when not provided."""
        if not isinstance(data, dict):
            return data
        verifier = data.get("code_verifier")
        challenge = data.get("code_challenge")
        method = data.get("code_challenge_method", "S256") or "S256"
        if verifier and not challenge:
            if method == "S256":
                digest = hashlib.sha256(verifier.encode("ascii")).digest()
                data["code_challenge"] = (
                    base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
                )
            elif method == "plain":
                data["code_challenge"] = verifier
            else:
                raise ValueError(f"Unsupported code_challenge_method: {method}")
        return data

class OAuth2Token(BasePydanticModel):
    access_token: str
    token_type: str = Field(default="Bearer")
    expires_in: int | None = Field(default=3600, gt=0) # Standard is int, but some providers might not return it
    refresh_token: str | None = None
    scope: str | None = None # Space-separated list of scopes
    id_token: str | None = None # For OpenID Connect
    created_at: float = Field(default_factory=time.time)

    @property
    def is_expired(self) -> bool:
        """Check if token is expired with a 60-second buffer."""
        if self.expires_in is None:
            return False # Cannot determine expiration
        return time.time() > self.created_at + self.expires_in - 60

    @property
    def expires_at(self) -> float | None:
        if self.expires_in is None:
            return None
        return self.created_at + self.expires_in

class ClientCredentials(BasePydanticModel):
    client_id: str
    client_secret: str | None = None # For confidential clients, not typically used with PKCE public clients
    # Other registration metadata if needed, like client_id_issued_at, etc.

class OAuth2ClientConfig(BasePydanticModel): # Configuration for an OAuth2 client instance
    client_id: str
    client_secret: str | None = None # If applicable
    token_endpoint: HttpUrl
    authorization_endpoint: HttpUrl
    redirect_uri: HttpUrl # Must be pre-registered with the auth server
    scopes: list[str] = Field(default_factory=list)
    # For dynamic registration, these might be discovered or templated
    registration_endpoint: HttpUrl | None = None
    # Additional custom parameters for token/auth requests
    extra_auth_params: dict | None = None
    extra_token_params: dict | None = None

class TokenRequest(BasePydanticModel):
    grant_type: str
    code: str | None = None # For authorization_code grant
    redirect_uri: HttpUrl | None = None # Required for authorization_code
    code_verifier: str | None = None # For PKCE
    refresh_token: str | None = None # For refresh_token grant
    client_id: str | None = None # Sometimes required in body for public clients
    # Can add other fields like 'scope', 'username', 'password' for other grant types

class AuthorizationCodeResponse(BasePydanticModel): # Query params in redirect URI
    code: str
    state: str | None = None
    error: str | None = None
    error_description: str | None = None

# Could also include models for error responses from OAuth server (RFC 6749, Section 5.2)
class OAuthError(BasePydanticModel):
    error: str
    error_description: str | None = None
    error_uri: HttpUrl | None = None
