import time
from typing import Optional, Tuple, List

from pydantic import BaseModel, Field, HttpUrl

from .common import BasePydanticModel

class PKCEChallenge(BasePydanticModel):
    code_verifier: str = Field(..., min_length=43, max_length=128)
    code_challenge: str = Field(..., min_length=43, max_length=128)
    code_challenge_method: str = Field(default="S256")

class OAuth2Token(BasePydanticModel):
    access_token: str
    token_type: str = Field(default="Bearer")
    expires_in: Optional[int] = Field(default=3600, gt=0) # Standard is int, but some providers might not return it
    refresh_token: Optional[str] = None
    scope: Optional[str] = None # Space-separated list of scopes
    id_token: Optional[str] = None # For OpenID Connect
    created_at: float = Field(default_factory=time.time)

    @property
    def is_expired(self) -> bool:
        """Check if token is expired with a 60-second buffer."""
        if self.expires_in is None:
            return False # Cannot determine expiration
        return time.time() > self.created_at + self.expires_in - 60

    @property
    def expires_at(self) -> Optional[float]:
        if self.expires_in is None:
            return None
        return self.created_at + self.expires_in

class ClientCredentials(BasePydanticModel):
    client_id: str
    client_secret: Optional[str] = None # For confidential clients, not typically used with PKCE public clients
    # Other registration metadata if needed, like client_id_issued_at, etc.

class OAuth2ClientConfig(BasePydanticModel): # Configuration for an OAuth2 client instance
    client_id: str
    client_secret: Optional[str] = None # If applicable
    token_endpoint: HttpUrl
    authorization_endpoint: HttpUrl
    redirect_uri: HttpUrl # Must be pre-registered with the auth server
    scopes: List[str] = Field(default_factory=list)
    # For dynamic registration, these might be discovered or templated
    registration_endpoint: Optional[HttpUrl] = None
    # Additional custom parameters for token/auth requests
    extra_auth_params: Optional[dict] = None
    extra_token_params: Optional[dict] = None

class TokenRequest(BasePydanticModel):
    grant_type: str
    code: Optional[str] = None # For authorization_code grant
    redirect_uri: Optional[HttpUrl] = None # Required for authorization_code
    code_verifier: Optional[str] = None # For PKCE
    refresh_token: Optional[str] = None # For refresh_token grant
    client_id: Optional[str] = None # Sometimes required in body for public clients
    # Can add other fields like 'scope', 'username', 'password' for other grant types

class AuthorizationCodeResponse(BasePydanticModel): # Query params in redirect URI
    code: str
    state: Optional[str] = None
    error: Optional[str] = None
    error_description: Optional[str] = None

# Could also include models for error responses from OAuth server (RFC 6749, Section 5.2)
class OAuthError(BasePydanticModel):
    error: str
    error_description: Optional[str] = None
    error_uri: Optional[HttpUrl] = None
