"""
OAuth 2.1 Client implementation with PKCE support.
Adheres to RFC 6749 (OAuth 2.0), RFC 7636 (PKCE), and elements of OAuth 2.1 draft.
"""
import asyncio
import json
from typing import Any, Dict, Optional, Tuple, Union
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

import aiohttp
import structlog

from ..models.auth import OAuth2Token, PKCEChallenge, OAuth2ClientConfig, TokenRequest, AuthorizationCodeResponse, OAuthError
from ..mcp_client.exceptions import MCPAuthError, MCPConnectionError # Reusing connection error
from .pkce import generate_pkce_challenge_pair
from ..config import Config # For global app config, if needed for session or http client settings

logger = structlog.get_logger(__name__)

class OAuth2Client:
    """
    An OAuth 2.1 client capable of performing the Authorization Code Flow with PKCE.
    """

    def __init__(self, client_config: OAuth2ClientConfig, app_config: Config, session: Optional[aiohttp.ClientSession] = None):
        """
        Initializes the OAuth2 client.

        Args:
            client_config: Configuration specific to this OAuth client instance (client_id, endpoints, etc.).
            app_config: Global application configuration, used for HTTP client settings.
            session: An optional shared aiohttp.ClientSession. If None, one will be created.
        """
        self.client_config = client_config
        self.app_config = app_config # Used for http client settings from MCPClientConfig
        self._session = session
        self._session_owner = session is None # True if this instance created the session
        self.logger = logger.bind(client_id=client_config.client_id)

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            # Create a new session if one wasn't provided or is closed
            # Use settings from app_config.mcp_client for consistency
            mcp_client_cfg = self.app_config.mcp_client

            ssl_context = None
            # Assuming token_endpoint scheme dictates SSL for OAuth comms
            if urlparse(str(self.client_config.token_endpoint)).scheme == "https":
                if mcp_client_cfg.ssl_verify:
                    pass # Default aiohttp handling
                else:
                    self.logger.warning("SSL verification is DISABLED for OAuth2 client. This is insecure.")
                    ssl_context = False

            connector = aiohttp.TCPConnector(
                limit=mcp_client_cfg.connection_pool_total_limit,
                limit_per_host=mcp_client_cfg.connection_pool_per_host_limit,
                ttl_dns_cache=mcp_client_cfg.connection_pool_dns_cache_ttl_seconds,
                ssl=ssl_context
            )
            self._session = aiohttp.ClientSession(connector=connector)
            self._session_owner = True # This instance owns the session
        return self._session

    async def close_session(self):
        """Closes the aiohttp session if it was created by this instance."""
        if self._session and not self._session.closed and self._session_owner:
            self.logger.debug("Closing owned aiohttp session for OAuth2 client.")
            await self._session.close()
        self._session = None

    def create_authorization_url(self, state: str, pkce: PKCEChallenge, extra_params: Optional[Dict[str, str]] = None) -> Tuple[str, str, str]:
        """
        Creates the authorization URL to redirect the user to.

        Args:
            state: An opaque value used to maintain state between the request and callback.
            pkce: The PKCEChallenge object containing verifier, challenge, and method.
            extra_params: Additional query parameters to include in the authorization request.

        Returns:
            A tuple containing:
            - The full authorization URL.
            - The state parameter used.
            - The PKCE code verifier.
        """
        self.logger.debug("Creating authorization URL.")
        params = {
            "response_type": "code",
            "client_id": self.client_config.client_id,
            "redirect_uri": str(self.client_config.redirect_uri),
            "scope": " ".join(self.client_config.scopes),
            "state": state,
            "code_challenge": pkce.code_challenge,
            "code_challenge_method": pkce.code_challenge_method,
        }
        if extra_params:
            params.update(extra_params)

        # Ensure no None values are in params before urlencode
        encoded_params = urlencode({k: v for k, v in params.items() if v is not None})
        auth_url = f"{str(self.client_config.authorization_endpoint)}?{encoded_params}"

        self.logger.info("Authorization URL created", url_host=urlparse(auth_url).hostname)
        return auth_url, state, pkce.code_verifier

    def _prepare_token_request(self, token_request_data: TokenRequest) -> tuple[dict, dict, aiohttp.ClientTimeout]:
        """
        Prepares the token request payload, headers and timeout settings.

        Args:
            token_request_data: The token request data object.

        Returns:
            A tuple containing (payload, headers, timeout) for the token request.
        """
        # Pydantic's model_dump with exclude_none=True for clean payload
        payload = token_request_data.model_dump(exclude_none=True, by_alias=True)

        headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
        # Basic Auth for confidential clients, not typically used with PKCE public clients
        auth = None  # Assuming public client for PKCE

        timeout_settings = self.app_config.mcp_client
        request_timeout = aiohttp.ClientTimeout(
            total=timeout_settings.request_timeout_seconds,
            connect=timeout_settings.connect_timeout_seconds
        )

        return payload, headers, request_timeout

    async def _send_token_request(self, payload: dict, headers: dict, timeout: aiohttp.ClientTimeout) -> dict:
        """
        Sends a token request to the authorization server.

        Args:
            payload: The request payload.
            headers: The request headers.
            timeout: The request timeout settings.

        Returns:
            The parsed JSON response from the server.

        Raises:
            MCPAuthError: If the server returns an error response.
            MCPConnectionError: If there's a network or connection error.
        """
        session = await self._get_session()
        self.logger.info("Requesting token from endpoint", token_url_host=urlparse(str(self.client_config.token_endpoint)).hostname)

        try:
            async with session.post(
                str(self.client_config.token_endpoint),
                data=payload,
                headers=headers,
                auth=None,  # Public client
                timeout=timeout
            ) as response:
                response_text = await response.text()
                self.logger.debug("Token endpoint response status", status=response.status)

                if response.status != 200:
                    await self._handle_error_response(response.status, response_text)

                try:
                    return json.loads(response_text)
                except json.JSONDecodeError as e:
                    self.logger.error("Failed to decode JSON from token response", error=str(e), response_text=response_text[:500])
                    raise MCPAuthError(f"Failed to decode JSON from token response: {e}") from e

        except aiohttp.ClientConnectorError as e:
            self.logger.error("Token endpoint connection failed", error=str(e.os_error or e))
            raise MCPConnectionError(f"Connection to token endpoint {self.client_config.token_endpoint} failed: {e.os_error or str(e)}") from e
        except asyncio.TimeoutError as e:
            self.logger.error("Token request timed out", token_url=str(self.client_config.token_endpoint))
            raise MCPConnectionError(f"Request to token endpoint {self.client_config.token_endpoint} timed out.") from e
        except aiohttp.ClientError as e:
            self.logger.error("AIOHTTP client error during token exchange", error_type=type(e).__name__, error_message=str(e))
            raise MCPConnectionError(f"HTTP client error during token exchange: {e}") from e

    async def _handle_error_response(self, status: int, body: str) -> None:
        """
        Handles error responses from the token endpoint.

        Args:
            status: The HTTP status code.
            body: The response body.

        Raises:
            MCPAuthError: Always raised with appropriate error details.
        """
        self.logger.error("Token request failed", status=status, response_body=body[:500])
        try:
            error_data = json.loads(body)
            oauth_error = OAuthError.model_validate(error_data)
            
            # Special handling for invalid_grant during refresh
            error_desc = error_data.get("error_description")
            if oauth_error.error == "invalid_grant" and isinstance(error_desc, str) and "refresh" in error_desc.lower():
                raise MCPAuthError(
                    f"Token refresh failed: {oauth_error.error} - {oauth_error.error_description or 'Refresh token likely invalid/revoked'}. Re-authentication required.",
                    server_error=oauth_error,
                    requires_reauth=True
                )
            
            raise MCPAuthError(
                f"Token request failed: {oauth_error.error} - {oauth_error.error_description if oauth_error.error_description else 'No description available'}",
                server_error=oauth_error
            )
        except (json.JSONDecodeError, ValueError):
            raise MCPAuthError(f"Token request failed with status {status}. Response: {body[:500]}")

    def _parse_token_response(self, token_data: dict, existing_refresh_token: str | None = None) -> OAuth2Token:
        """
        Parses and validates the token response data.

        Args:
            token_data: The raw token response data.
            existing_refresh_token: The current refresh token to preserve if a new one isn't provided.

        Returns:
            An OAuth2Token instance.

        Raises:
            MCPAuthError: If the token data is invalid or malformed.
        """
        try:
            token = OAuth2Token.model_validate(token_data)
            
            # Preserve existing refresh token if new one not provided
            if not token.refresh_token and existing_refresh_token:
                self.logger.debug("Refresh token not returned in response, reusing existing one.")
                token.refresh_token = existing_refresh_token
                
            self.logger.info("Token successfully processed.")
            return token
        except ValueError as e:
            self.logger.error("Failed to validate token response", error=str(e), raw_data=token_data)
            raise MCPAuthError(f"Invalid token data received: {e}") from e

async def exchange_code_for_token(
        self,
        code: str,
        code_verifier: str,
        state: str | None = None,
        expected_state: str | None = None,
    ) -> OAuth2Token:
        """
        Exchanges an authorization code for an access token and refresh token.

        Args:
            code: The authorization code received from the authorization server.
            code_verifier: The PKCE code verifier.
            state: The state parameter received from the authorization server (optional).
            expected_state: The state parameter initially sent to the server (optional, for validation).

        Returns:
            An OAuth2Token object containing the token information.

        Raises:
            MCPAuthError: If the state is invalid or token exchange fails.
            MCPConnectionError: If there's a problem communicating with the token endpoint.
        """
        self.logger.debug("Exchanging authorization code for token.")
        if expected_state and state != expected_state:
            self.logger.error("OAuth state mismatch", received_state=state, expected_state=expected_state)
            raise MCPAuthError(f"Invalid OAuth state: received '{state}', expected '{expected_state}'. Possible CSRF attack.")

        token_request_data = TokenRequest(
            grant_type="authorization_code",
            code=code,
            redirect_uri=self.client_config.redirect_uri,  # Must match the one used in auth request
            client_id=self.client_config.client_id,  # Required for public clients
            code_verifier=code_verifier
        )

        payload, headers, timeout = self._prepare_token_request(token_request_data)
        token_data = await self._send_token_request(payload, headers, timeout)
        return self._parse_token_response(token_data)

    async def refresh_token(self, refresh_token_value: str) -> OAuth2Token:
        """
        Refreshes an access token using a refresh token.

        Args:
            refresh_token_value: The refresh token string.

        Returns:
            A new OAuth2Token object.

        Raises:
            MCPAuthError: If token refresh fails or refresh token is invalid.
            MCPConnectionError: If there's a problem communicating with the token endpoint.
        """
        self.logger.debug("Refreshing access token.")
        if not refresh_token_value:
            self.logger.error("Refresh token is missing.")
            raise MCPAuthError("Cannot refresh token: refresh_token is missing.")

        token_request_data = TokenRequest(
            grant_type="refresh_token",
            refresh_token=refresh_token_value,
            client_id=self.client_config.client_id,  # May be required by some servers even for refresh
            # scope: Optional, some servers allow requesting same or narrower scope
        )

        payload, headers, timeout = self._prepare_token_request(token_request_data)
        token_data = await self._send_token_request(payload, headers, timeout)
        return self._parse_token_response(token_data, refresh_token_value)

    async def __aenter__(self):
        await self._get_session() # Ensure session is ready
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close_session()


# Example usage (conceptual, would be part of a larger flow):
async def main_oauth_flow(app_config: Config, client_id: str, auth_server_url_base: str):
    # This is a simplified conceptual flow. Real flow involves user interaction via browser.

    oauth_client_cfg = OAuth2ClientConfig(
        client_id=client_id, # This would come from pre-configuration or dynamic registration
        token_endpoint=f"{auth_server_url_base}/token",
        authorization_endpoint=f"{auth_server_url_base}/authorize",
        redirect_uri="http://localhost:8080/callback", # Example for local CLI/test app
        scopes=["openid", "profile", "mcp:tools"]
    )

    async with OAuth2Client(client_config=oauth_client_cfg, app_config=app_config) as client:
        pkce = generate_pkce_challenge_pair()
        auth_url, state, verifier = client.create_authorization_url(state="your_random_state_123", pkce=pkce)

        print(f"1. Please authorize here: {auth_url}")
        print(f"   Code Verifier (keep secret until token exchange): {verifier}")

        # --- User interaction step (simulated) ---
        # User goes to auth_url, authenticates, authorizes.
        # Auth server redirects to redirect_uri with `code` and `state`.
        # Example redirect: http://localhost:8080/callback?code=AUTH_CODE_HERE&state=your_random_state_123

        auth_code_response_url = input("2. Enter the full redirect URL you received: ")
        parsed_url = urlparse(auth_code_response_url)
        query_params = parse_qs(parsed_url.query)

        auth_code = query_params.get("code", [None])[0]
        received_state = query_params.get("state", [None])[0]

        if not auth_code:
            print("Error: Authorization code not found in redirect URL.")
            return

        print(f"   Auth Code: {auth_code}")
        print(f"   Received State: {received_state}")

        try:
            token_response = await client.exchange_code_for_token(
                code=auth_code,
                code_verifier=verifier,
                state=received_state,
                expected_state=state
            )
            print("\n3. Token obtained successfully:")
            print(f"   Access Token: {token_response.access_token[:20]}...")
            print(f"   Refresh Token: {token_response.refresh_token[:20] if token_response.refresh_token else 'N/A'}...")
            print(f"   Expires in: {token_response.expires_in}s")

            if token_response.refresh_token:
                await asyncio.sleep(2) # Wait a bit
                print("\n4. Attempting to refresh token...")
                refreshed_token = await client.refresh_token(token_response.refresh_token)
                print("   Token refreshed successfully:")
                print(f"   New Access Token: {refreshed_token.access_token[:20]}...")
                print(f"   New Refresh Token: {refreshed_token.refresh_token[:20] if refreshed_token.refresh_token else 'N/A'}...")
                print(f"   Expires in: {refreshed_token.expires_in}s")

        except MCPAuthError as e:
            print(f"\nOAuth Error: {e}")
            if hasattr(e, 'server_error') and e.server_error:
                print(f"   Server Error Details: {e.server_error}")
            if hasattr(e, 'requires_reauth') and e.requires_reauth:
                print("   Re-authentication is required.")
        except MCPConnectionError as e:
            print(f"\nConnection Error: {e}")
        except Exception as e:
            print(f"\nAn unexpected error occurred: {e}")

if __name__ == "__main__":
    # To run this example, you'd need a compatible OAuth 2.1 server.
    # This is for conceptual demonstration.
    # asyncio.run(main_oauth_flow(app_config=Config(), client_id="your_test_client_id", auth_server_url_base="http://localhost:8000/oauth"))
    pass
