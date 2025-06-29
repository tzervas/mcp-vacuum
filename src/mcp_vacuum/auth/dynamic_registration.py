"""
OAuth 2.1 Dynamic Client Registration (RFC 7591).
"""
import json
from typing import Any

import aiohttp  # type: ignore[import-not-found]
import structlog  # type: ignore[import-not-found]
from .. import __version__ as app_version  # Get app version
from ..config import Config  # For global app config, http client settings
from ..mcp_client.exceptions import (  # Reusing exceptions
    MCPAuthError,
    MCPConnectionError,
)
from ..models.auth import ClientCredentials
from ..models.mcp import MCPServerInfo  # For context like server name

logger = structlog.get_logger(__name__)

DEFAULT_REDIRECT_URIS = [
    "urn:ietf:wg:oauth:2.0:oob",
    "http://localhost:8080/oauth/callback",
]  # Common defaults
DEFAULT_GRANT_TYPES = ["authorization_code", "refresh_token"]
DEFAULT_RESPONSE_TYPES = ["code"]
# For public clients using PKCE
DEFAULT_TOKEN_ENDPOINT_AUTH_METHOD = "none"
# Example scopes
DEFAULT_SCOPES = "openid profile mcp:tools mcp:resources mcp:prompts"

class DynamicRegistrationError(MCPAuthError):
    """Custom exception for dynamic client registration failures."""
    pass

class DynamicClientRegistrar:
    """
    Handles dynamic client registration with an OAuth 2.1 authorization server
    as per RFC 7591.
    """

    def __init__(
        self, app_config: Config, session: aiohttp.ClientSession | None = None
    ):
        """
        Initializes the DynamicClientRegistrar.

        Args:
            app_config: Global application configuration.
            session: An optional shared aiohttp.ClientSession.
        """
        self.app_config = app_config
        self._session = session
        self._session_owner = session is None
        self.logger = logger # Default logger, can bind more context if needed

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            mcp_client_cfg = self.app_config.mcp_client
            ssl_context = None # Simplified: assume registration endpoint scheme dictates SSL

            # This logic should be robust, checking scheme of registration_endpoint
            # For now, assume same SSL settings as general MCP client.
            if mcp_client_cfg.ssl_verify:
                pass
            else:
                self.logger.warning(
                    "SSL verification is DISABLED for DynamicClientRegistrar. "
                    "This is insecure."
                )
                ssl_context = False

            connector = aiohttp.TCPConnector(
                limit=mcp_client_cfg.connection_pool_total_limit,
                limit_per_host=mcp_client_cfg.connection_pool_per_host_limit,
                ttl_dns_cache=mcp_client_cfg.connection_pool_dns_cache_ttl_seconds,
                ssl=ssl_context
            )
            self._session = aiohttp.ClientSession(connector=connector)
            self._session_owner = True
        return self._session

    async def close_session(self):
        if self._session and not self._session.closed and self._session_owner:
            self.logger.debug(
                "Closing owned aiohttp session for DynamicClientRegistrar."
            )
            await self._session.close()
        self._session = None

    async def register_client(  # noqa: PLR0913
        self,
        registration_endpoint: str,  # Should be HttpUrl from Pydantic model
        server_info: MCPServerInfo,  # Provides context like server name
        client_name: str | None = None,
        redirect_uris: list[str] | None = None,
        grant_types: list[str] | None = None,
        response_types: list[str] | None = None,
        token_endpoint_auth_method: str | None = None,
        scope: str | None = None,  # Space-separated string of scopes
        software_id: str | None = None,  # e.g. a UUID for the client software
        software_version: str | None = None,  # e.g. app_config.agent_version
        extra_metadata: dict[str, Any] | None = None,
    ) -> ClientCredentials:
        """
        Dynamically registers this client with the MCP server's authorization
        provider.

        Args:
            registration_endpoint: The server's client registration endpoint URL.
            server_info: Information about the MCP server this client is for.
            client_name: A human-readable name for the client.
            redirect_uris: List of redirection URIs for use in authorization
                           grants.
            grant_types: List of OAuth 2.0 grant types the client will restrict
                         itself to using.
            response_types: List of OAuth 2.0 response type values the client
                            will restrict itself to using.
            token_endpoint_auth_method: Requested client authentication method
                                        for the token endpoint.
            scope: Space-separated string of requested scopes.
            software_id: A unique identifier for the client software.
            software_version: Version of the client software.
            extra_metadata: Additional client metadata fields to include in the
                            registration request.

        Returns:
            ClientCredentials containing the registered client_id and other
            metadata.

        Raises:
            DynamicRegistrationError: If registration fails.
            MCPConnectionError: If communication with the endpoint fails.
        """
        self.logger = self.logger.bind(
            server_name=server_info.name,
            registration_endpoint=registration_endpoint,
        )
        self.logger.info("Attempting dynamic client registration.")

        session = await self._get_session()

        # Get dynamic client metadata from config
        meta_cfg = self.app_config.auth.dynamic_client_metadata

        base_client_name = (
            f"MCP Vacuum ({self.app_config.agent_name}) for {server_info.name}"
        )
        if meta_cfg.client_name_suffix:
            final_client_name = f"{base_client_name} - {meta_cfg.client_name_suffix}"
        else:
            final_client_name = base_client_name

        registration_request = {
            "client_name": client_name or final_client_name,
            "redirect_uris": redirect_uris or DEFAULT_REDIRECT_URIS,
            "grant_types": grant_types or DEFAULT_GRANT_TYPES,
            "response_types": response_types or DEFAULT_RESPONSE_TYPES,
            "token_endpoint_auth_method": token_endpoint_auth_method
            or DEFAULT_TOKEN_ENDPOINT_AUTH_METHOD,
            "scope": scope or DEFAULT_SCOPES,
            # Default if not set
            "client_uri": str(meta_cfg.client_uri)
            if meta_cfg.client_uri
            else "https://github.com/tzervas/mcp-vacuum",
            # None if not set, will be cleaned
            "logo_uri": str(meta_cfg.logo_uri) if meta_cfg.logo_uri else None,
            # None if not set, will be cleaned
            "contacts": meta_cfg.contacts if meta_cfg.contacts else None,
            "software_id": software_id or f"mcp-vacuum-{server_info.id}",
            "software_version": software_version or app_version,
        }
        if extra_metadata:
            registration_request.update(extra_metadata)

        # Remove any keys with None values or empty lists, as some servers
        # might be strict
        registration_request_cleaned = {
            k: v
            for k, v in registration_request.items()
            if v is not None and v != []
        }

        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        # Some registration endpoints might require an initial access token or
        # Bearer token. This example assumes an open registration endpoint or
        # one protected by other means (e.g. network ACLs)

        timeout_settings = self.app_config.mcp_client
        request_timeout = aiohttp.ClientTimeout(
            total=timeout_settings.request_timeout_seconds,
            connect=timeout_settings.connect_timeout_seconds,
        )

        self.logger.debug(
            "Sending client registration request",
            payload_keys=list(registration_request_cleaned.keys()),
        )
        try:
            async with session.post(
                registration_endpoint,  # Already a string from HttpUrl conversion
                json=registration_request_cleaned,
                headers=headers,
                timeout=request_timeout
            ) as response:
                response_text = await response.text()
                self.logger.debug(
                    "Registration endpoint response status", status=response.status
                )

                if response.status == 201:  # HTTP 201 Created is success
                    try:
                        client_data = json.loads(response_text)
                        # Validate against ClientCredentials model
                        # Note: ClientCredentials model is simple (client_id,
                        # client_secret). The response might include more
                        # (client_id_issued_at, client_secret_expires_at etc.)
                        # We should parse into a more comprehensive model if
                        # needed, or allow extra fields.

                        # For now, let's assume ClientCredentials model is
                        # sufficient or use a temp dict.
                        # Using Pydantic's model_validate for robustness
                        registered_client = ClientCredentials.model_validate(
                            client_data
                        )
                        self.logger.info(
                            "Client registration successful",
                            client_id=registered_client.client_id,
                        )
                        return registered_client
                    except json.JSONDecodeError as e:
                        self.logger.error(
                            "Failed to decode JSON from registration response",
                            error=str(e),
                            response_text=response_text[:500],
                        )
                        raise DynamicRegistrationError(
                            "Failed to decode JSON from successful (201 Created) "
                            f"registration response: {e}"
                        ) from e
                    except ValueError as e:  # Pydantic validation error
                        self.logger.error(
                            "Failed to validate registration response against "
                            "ClientCredentials model",
                            error=str(e),
                            raw_data=client_data,
                        )
                        raise DynamicRegistrationError(
                            "Invalid client credentials data received from "
                            f"registration: {e}"
                        ) from e
                else:
                    # Handle error response (RFC 7591, Section 3.2.2)
                    self.logger.error(
                        "Dynamic client registration failed",
                        status=response.status,
                        response_body=response_text[:500],
                    )
                    try:
                        error_data = json.loads(response_text)
                        # RFC 7591 specifies error codes like
                        # 'invalid_redirect_uri', 'invalid_client_metadata'
                        err_type = error_data.get("error", "unknown_error")
                        err_desc = error_data.get(
                            "error_description", "No description provided."
                        )
                        raise DynamicRegistrationError(
                            f"Registration failed: {err_type} - {err_desc}",
                            error_code=err_type,
                            error_details=error_data,
                        )
                    except (json.JSONDecodeError, ValueError):
                        raise DynamicRegistrationError(
                            f"Registration failed with status {response.status}. "
                            f"Response: {response_text[:500]}"
                        )

        except aiohttp.ClientConnectorError as e:
            self.logger.error(
                "Registration endpoint connection failed",
                error=str(e.os_error or e),
            )
            raise MCPConnectionError(
                f"Connection to registration endpoint {registration_endpoint} "
                f"failed: {e.os_error or str(e)}"
            ) from e
        except TimeoutError as e:
            self.logger.error(
                "Registration request timed out",
                registration_url=registration_endpoint,
            )
            raise MCPConnectionError(
                f"Request to registration endpoint {registration_endpoint} timed out."
            ) from e
        except aiohttp.ClientError as e:
            self.logger.error(
                "AIOHTTP client error during registration",
                error_type=type(e).__name__,
                error_message=str(e),
            )
            raise MCPConnectionError(
                f"HTTP client error during registration: {e}"
            ) from e

    async def __aenter__(self):
        await self._get_session()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close_session()

# Conceptual usage:
# async def perform_dynamic_registration(
#     app_cfg: Config, server_info_model: MCPServerInfo
# ):
#     # Assuming MCPServerInfo has this
#     if not server_info_model.registration_endpoint:
#         print(
#             "Server does not support dynamic registration (no "
#             "registration_endpoint)."
#         )
#         return None
#
#     registrar = DynamicClientRegistrar(app_config=app_cfg)
#     try:
#         async with registrar: # Manages session
#             client_creds = await registrar.register_client(
#                 registration_endpoint=str(server_info_model.registration_endpoint),
#                 server_info=server_info_model
#             )
#             print(f"Successfully registered client: ID = {client_creds.client_id}")
#             # Store client_creds securely associated with this server_info_model.id
#             return client_creds
#     except DynamicRegistrationError as e:
#         print(f"Dynamic Registration Error: {e}")
#         if hasattr(e, 'error_details'): print(f"  Details: {e.error_details}")
#     except MCPConnectionError as e:
#         print(f"Connection Error during registration: {e}")
#     return None
