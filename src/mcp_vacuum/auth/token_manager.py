"""
Manages OAuth 2.1 tokens, including retrieval, storage, caching, and automatic refresh.
"""
import asyncio

import structlog

from ..config import (  # For global app config and auth specific config
    AuthConfig,
    Config,
)
from ..mcp_client.exceptions import MCPAuthError, MCPConnectionError
from ..models.auth import ClientCredentials, OAuth2ClientConfig, OAuth2Token
from ..models.mcp import MCPServerInfo  # For context
from .dynamic_registration import DynamicClientRegistrar, DynamicRegistrationError
from .oauth_client import OAuth2Client
from .token_storage import (
    BaseTokenStorage,
    TokenNotFoundError,
    TokenStorageError,  # Added import
    get_token_storage,
)
from typing import Any # Added import

logger = structlog.get_logger(__name__)

class TokenManager:
    """
    Orchestrates OAuth token acquisition, storage, and lifecycle management
    (caching, refresh). It can also handle dynamic client registration if
    configured.
    """

    def __init__(
        self, app_config: Config, token_storage: BaseTokenStorage | None = None
    ):
        """
        Initializes the TokenManager.

        Args:
            app_config: The global application configuration.
            token_storage: An instance of a token storage backend. If None,
                           one will be created based on app_config.auth.
        """
        self.app_config = app_config
        self.auth_config: AuthConfig = app_config.auth  # Convenience accessor
        self._token_storage: BaseTokenStorage = (
            token_storage or get_token_storage(self.auth_config)
        )

        # In-memory cache for frequently accessed tokens to reduce storage I/O
        self._token_cache: dict[str, OAuth2Token] = {}  # Key: server_id

        # Lock for critical sections like token refresh to prevent race conditions
        self._locks: dict[str, asyncio.Lock] = {} # Key: server_id

        self.logger = logger

    async def _get_lock(self, server_id: str) -> asyncio.Lock:
        if server_id not in self._locks:
            self._locks[server_id] = asyncio.Lock()
        return self._locks[server_id]

    async def get_valid_oauth_token(
        self,
        server_id: str,
        server_info: MCPServerInfo,
        force_refresh: bool = False,
    ) -> OAuth2Token | None:
        """
        Retrieves a valid OAuth2Token for the given server_id.
        Handles caching, checking expiration, and automatic refresh.
        This is the primary method clients should use to get a token.

        Args:
            server_id: Unique identifier for the MCP server.
            server_info: MCPServerInfo object providing context like endpoints
                         needed for auth. This is crucial if client credentials
                         or endpoints need to be discovered/fetched.
            force_refresh: If True, forces a token refresh even if a
                           cached/stored token seems valid.

        Returns:
            A valid OAuth2Token, or None if authentication is not possible or
            fails.
        """
        log = self.logger.bind(server_id=server_id, server_name=server_info.name)
        log.debug("Attempting to get valid OAuth token.")

        # Ensure only one refresh attempt per server_id at a time
        async with await self._get_lock(server_id):
            if not force_refresh:
                # 1. Check in-memory cache
                cached_token = self._token_cache.get(server_id)
                if cached_token and not cached_token.is_expired:
                    log.debug("Found valid token in memory cache.")
                    return cached_token

                # 2. Check persistent storage
                try:
                    stored_token = await self._token_storage.get_oauth_token(server_id)
                    if stored_token:
                        log.debug("Found token in persistent storage.")
                        if not stored_token.is_expired:
                            # Update cache
                            self._token_cache[server_id] = stored_token
                            log.debug("Stored token is valid.")
                            return stored_token
                        else:
                            log.info("Stored token is expired, attempting refresh.")
                            # Proceed to refresh logic using
                            # stored_token.refresh_token
                            refreshed_token = (
                                await self._perform_token_refresh(
                                    server_id, server_info, stored_token
                                )
                            )
                            if refreshed_token:
                                return refreshed_token
                            else:
                                # Refresh failed, token is invalid. Fall through
                                # to re-authentication or failure.
                                log.warning(
                                    "Token refresh failed after finding expired "
                                    "stored token."
                                )
                                # Clear invalid data
                                await self._clear_token_data(
                                    server_id, log_context=log
                                )
                                # Fall through to attempt full re-authentication
                                # if configured, or return None
                    else:
                        log.debug(
                            "No token found in persistent storage for this "
                            "server_id."
                        )
                except TokenNotFoundError:
                    log.debug(
                        "No token found in persistent storage "
                        "(TokenNotFoundError)."
                    )
                except TokenStorageError as e:
                    log.error("Error accessing token storage", error=str(e))
                    # Depending on error, might proceed to re-auth or fail.
                    # For now, log and try re-auth.

            # 3. If force_refresh or no valid token found/refreshed, attempt
            # full authentication flow (if applicable)
            # This part is complex as it requires either pre-configured
            # client_id or dynamic registration, and then initiating the auth
            # code flow which requires user interaction.
            # For an automated agent, this step might mean "cannot get token
            # automatically".
            # For now, this method focuses on stored/refreshable tokens.
            # A separate method like `initiate_new_authentication` would
            # handle the interactive part.
            if (
                force_refresh
                and not self._token_cache.get(server_id)
                and not await self._token_storage.get_oauth_token(server_id)
            ):
                # If force_refresh is true, but there's no token to refresh,
                # this path is tricky. It implies we need to start a new auth flow.
                log.warning(
                    "Force refresh requested, but no existing token to refresh. "
                    "Full authentication flow needed (not implemented here)."
                )
                # Or raise an error indicating full auth is needed.
                return None

            log.info(
                "No valid token found through cache, storage, or refresh for "
                "automated retrieval."
            )
            # No valid token could be automatically obtained/refreshed.
            return None

    async def _perform_token_refresh(
        self,
        server_id: str,
        server_info: MCPServerInfo,
        expired_token: OAuth2Token,
    ) -> OAuth2Token | None:
        """Helper to refresh a token and update storage/cache."""
        log = self.logger.bind(server_id=server_id, server_name=server_info.name)
        if not expired_token.refresh_token:
            log.warning("Cannot refresh token: no refresh_token available.")
            return None

        oauth_client_cfg = await self._get_oauth_client_config(
            server_id, server_info, log_context=log
        )
        if not oauth_client_cfg:
            log.error(
                "Failed to obtain OAuth client configuration for token refresh."
            )
            return None

        async with OAuth2Client(
            client_config=oauth_client_cfg, app_config=self.app_config
        ) as client:
            try:
                log.info("Attempting token refresh via OAuth client.")
                new_token = await client.refresh_token(
                    expired_token.refresh_token
                )

                await self._token_storage.store_oauth_token(server_id, new_token)
                self._token_cache[server_id] = new_token
                log.info("Token refreshed and stored successfully.")
                return new_token
            except MCPAuthError as e:
                log.error(
                    "MCPAuthError during token refresh",
                    error=str(e),
                    requires_reauth=getattr(e, "requires_reauth", False),
                )
                # Custom attribute in MCPAuthError if refresh token is
                # definitively invalid
                if getattr(e, "requires_reauth", False):
                    log.warning(
                        "Refresh token is invalid, clearing stored token data."
                    )
                    await self._clear_token_data(server_id, log_context=log)
            except MCPConnectionError as e:
                log.error(
                    "MCPConnectionError during token refresh", error=str(e)
                )
            except Exception as e:
                log.exception(
                    "Unexpected error during token refresh",
                    error_type=type(e).__name__,
                )
        return None

    async def _get_oauth_client_config(
        self, server_id: str, server_info: MCPServerInfo, log_context: Any
    ) -> OAuth2ClientConfig | None:
        """
        Gets OAuth2ClientConfig for a server.
        Tries to use stored client credentials, falls back to dynamic registration or default config.
        """
        # 1. Try to get stored client credentials for this server_id
        client_creds: ClientCredentials | None = None
        try:
            client_creds = await self._token_storage.get_client_credentials(server_id)
            if client_creds:
                log_context.debug("Found stored client credentials for server.")
        except TokenStorageError as e:
            log_context.warning(
                "Error retrieving stored client credentials", error=str(e)
            )

        # 2. If no stored creds, and dynamic registration is enabled, try to
        # register
        if not client_creds and self.auth_config.oauth_dynamic_client_registration:
            if server_info.registration_endpoint:  # MCPServerInfo needs this field
                log_context.info("Attempting dynamic client registration.")
                try:
                    registrar = DynamicClientRegistrar(app_config=self.app_config)
                    async with registrar:
                        # Pass software_id and software_version from
                        # app_config if available
                        client_creds = await registrar.register_client(
                            # Ensure str
                            registration_endpoint=str(
                                server_info.registration_endpoint
                            ),
                            server_info=server_info,
                        )
                    await self._token_storage.store_client_credentials(
                        server_id, client_creds
                    )
                    log_context.info(
                        "Dynamic client registration successful, credentials stored."
                    )
                except DynamicRegistrationError as e:
                    log_context.error(
                        "Dynamic client registration failed", error=str(e)
                    )
                except MCPConnectionError as e:
                    log_context.error(
                        "Connection error during dynamic client registration",
                        error=str(e),
                    )
            else:
                log_context.debug(
                    "Dynamic registration enabled, but server has no "
                    "registration_endpoint."
                )

        # 3. Construct OAuth2ClientConfig
        # Base it on default OAuth client config if available, then override
        # with specific credentials
        final_client_id: str | None = None
        final_client_secret: str | None = None

        if client_creds:
            final_client_id = client_creds.client_id
            final_client_secret = client_creds.client_secret
        elif self.auth_config.oauth_default_client:
            log_context.debug(
                "Using default OAuth client credentials from config."
            )
            final_client_id = self.auth_config.oauth_default_client.client_id
            final_client_secret = (
                self.auth_config.oauth_default_client.client_secret
            )

        if not final_client_id:
            log_context.error(
                "No client_id available (neither stored, dynamically registered, "
                "nor default in config). Cannot proceed with OAuth."
            )
            return None

        # Determine endpoints: Prefer server_info (discovered), fallback to
        # default config. MCPServerInfo should have auth_metadata with these
        # endpoints.
        auth_meta = server_info.auth_metadata
        auth_endpoint = (
            auth_meta.authorization_endpoint
            if auth_meta and auth_meta.authorization_endpoint
            else (
                self.auth_config.oauth_default_client.authorization_endpoint
                if self.auth_config.oauth_default_client
                else None
            )
        )
        token_endpoint = (
            auth_meta.token_endpoint
            if auth_meta and auth_meta.token_endpoint
            else (
                self.auth_config.oauth_default_client.token_endpoint
                if self.auth_config.oauth_default_client
                else None
            )
        )

        if not auth_endpoint or not token_endpoint:
            log_context.error(
                "Authorization or Token endpoint not found for server or in "
                "default config."
            )
            return None

        # Redirect URI - this is tricky for an agent. Use default from config.
        redirect_uri = (
            self.auth_config.oauth_default_client.redirect_uri
            if self.auth_config.oauth_default_client
            else f"http://localhost:{self.auth_config.oauth_redirect_uri_port}/oauth/callback"
        )

        scopes = (
            self.auth_config.oauth_default_client.scopes
            if self.auth_config.oauth_default_client
            else ["openid", "profile", "mcp:tools"]
        )

        return OAuth2ClientConfig(
            client_id=final_client_id,
            client_secret=final_client_secret,  # Will be None for public clients
            authorization_endpoint=str(auth_endpoint),  # Ensure str
            token_endpoint=str(token_endpoint),  # Ensure str
            redirect_uri=str(redirect_uri),  # Ensure str
            scopes=scopes,
        )

    async def store_new_token(
        self, server_id: str, token: OAuth2Token, log_context: Any | None = None
    ) -> None:
        """Stores a newly obtained token and updates the cache."""
        lg = log_context or self.logger.bind(server_id=server_id)
        try:
            await self._token_storage.store_oauth_token(server_id, token)
            self._token_cache[server_id] = token
            lg.info("New token stored and cached successfully.")
        except TokenStorageError as e:
            lg.error("Failed to store new token", error=str(e))
            # Decide if this should re-raise or just log. For now, just logs.

    async def _clear_token_data(self, server_id: str, log_context: Any) -> None:
        """Clears token data from cache and storage, e.g., if refresh token is invalid."""
        log_context.info("Clearing token data from cache and storage.")
        self._token_cache.pop(server_id, None)
        try:
            await self._token_storage.delete_oauth_token(server_id)
        except TokenStorageError as e:
            log_context.error(
                "Failed to delete token from storage during cleanup", error=str(e)
            )

    async def clear_all_server_credentials(self, server_id: str) -> None:
        """Clears all OAuth tokens and client credentials for a server."""
        log = self.logger.bind(server_id=server_id)
        log.info(
            "Clearing ALL credentials (OAuth token and Client Credentials) "
            "for server."
        )
        self._token_cache.pop(server_id, None)
        try:
            await self._token_storage.delete_oauth_token(server_id)
            log.debug("Deleted OAuth token from storage.")
        except TokenStorageError as e:
            log.error("Failed to delete OAuth token from storage", error=str(e))
        try:
            await self._token_storage.delete_client_credentials(server_id)
            log.debug("Deleted Client Credentials from storage.")
        except TokenStorageError as e:
            log.error(
                "Failed to delete Client Credentials from storage", error=str(e)
            )


# Note: The interactive part of the OAuth flow (redirecting user to auth
# server, handling callback) is not handled by TokenManager directly.
# TokenManager expects to be given a token (e.g. via store_new_token) or to be
# able to refresh an existing one.
# The `get_valid_oauth_token` method is for non-interactive scenarios where a
# token might already exist or be refreshable.
# A higher-level "AuthenticationAgent" would use TokenManager and OAuth2Client
# to run the full flow.
# MCPServerInfo model needs to be updated to include
# `registration_endpoint: Optional[HttpUrl]` and ensure `auth_metadata` is
# populated with `authorization_endpoint` and `token_endpoint` if known.
# This will likely come from discovery
# (e.g. .well-known/oauth-authorization-server).
