"""
MCP Client implementation using HTTP/HTTPS transport.
"""
import json
from typing import Any

import aiohttp
import structlog  # Import structlog

from ..config import Config
from ..models.mcp import MCPServiceRecord
from .base_client import BaseMCPClient
from .exceptions import (
    MCPAuthError,
    MCPConnectionError,
    MCPProtocolError,
    MCPTimeoutError,
)

logger = structlog.get_logger(__name__) # Initialize logger at module level

class HTTPMCPClient(BaseMCPClient):
    """
    MCP Client that communicates with an MCP server over HTTP or HTTPS.
    It uses aiohttp.ClientSession for making asynchronous HTTP requests.
    """

    def __init__(self, service_record: MCPServiceRecord, config: Config, aiohttp_session: aiohttp.ClientSession | None = None):
        super().__init__(service_record, config, aiohttp_session)
        self._is_connected_status = False # For HTTP, connection is per-request, but we can simulate a state.
        self.logger = logger.bind(server_name=service_record.name, server_endpoint=str(service_record.endpoint), transport="http")


    async def _get_session(self) -> aiohttp.ClientSession:
        """
        Returns the current aiohttp session or creates a new one if none exists.
        It's recommended to share a session across multiple client instances for connection pooling.
        """
        if self._session is None or self._session.closed:
            self.logger.info("No existing aiohttp session or session closed, creating a new one.")
            # Configure TCPConnector based on docs (DiscoveryClient example)
            # These now come directly from config.mcp_client
            client_cfg = self.config.mcp_client

            ssl_context = None
            if self.service_record.endpoint.scheme == "https":
                if client_cfg.ssl_verify:
                    # Default SSL context, will use system CAs.
                    # If client_cfg.ssl_ca_bundle is implemented, load it here.
                    # import ssl
                    # ssl_context = ssl.create_default_context(cafile=client_cfg.ssl_ca_bundle)
                    pass # aiohttp uses its own logic by default for system CAs
                else:
                    # This is insecure, log a warning
                    self.logger.warning("SSL verification is DISABLED for HTTP client. This is insecure for production.")
                    ssl_context = False # Tells aiohttp to skip verification

            connector = aiohttp.TCPConnector(
                limit=client_cfg.connection_pool_total_limit,
                limit_per_host=client_cfg.connection_pool_per_host_limit,
                ttl_dns_cache=client_cfg.connection_pool_dns_cache_ttl_seconds,
                ssl=ssl_context
            )
            self._session = aiohttp.ClientSession(connector=connector)
        return self._session

    async def connect(self) -> None:
        """
        For HTTP, 'connect' can mean ensuring a session is ready.
        Actual network connection happens per request.
        We can perform a capabilities check or a simple HEAD request to verify connectivity.
        """
        self.logger.debug("Attempting to 'connect' (verify endpoint or prepare session).")
        await self._get_session() # Ensure session is initialized

        # Optionally, make a test call like fetching capabilities or a HEAD request
        # For now, just ensuring session is ready is sufficient.
        # Consider adding a health check endpoint to MCP spec.
        try:
            # A light way to check: make a HEAD request if server supports it, or options.
            # If JSONRPC is the only interface, this might not be possible without a dummy call.
            # For now, we'll assume session readiness is enough.
            self.logger.info("HTTP client 'connected' (session initialized).", endpoint=str(self.service_record.endpoint))
            self._is_connected_status = True
        except aiohttp.ClientError as e:
            self.logger.error("Failed to connect or verify endpoint.", error=str(e))
            self._is_connected_status = False
            await self.close_session() # Clean up session if connect failed
            raise MCPConnectionError(f"Failed to connect to {self.service_record.endpoint}: {e}") from e


    async def disconnect(self) -> None:
        """
        Closes the aiohttp session if it was created and is managed by this client.
        If the session was passed in, its lifecycle should be managed externally.
        """
        self.logger.debug("HTTP client 'disconnect' called.")
        # The decision to close the session here depends on who owns it.
        # BaseClient's close_session can be called if this instance created it.
        # For now, we assume if _session exists, we can close it.
        # This might be an issue if the session is shared and passed in.
        # A better approach: only close if self._session_owner is True (set if client creates it)
        await self.close_session() # Uses BaseClient's method
        self._is_connected_status = False
        self.logger.info("HTTP client 'disconnected' (session closed).")

    async def is_connected(self) -> bool:
        """
        For HTTP, this indicates if the client is prepared to send requests (e.g., session is open).
        True connectivity is per-request.
        """
        if self._session and not self._session.closed:
            return True # Session is open and ready
        return self._is_connected_status # Fallback to simulated status

    async def _send_request_raw(self, request_payload: dict[str, Any]) -> dict[str, Any]:
        session = await self._get_session()
        from .. import __version__  # Dynamically import version

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": f"MCPVacuumAgent/{__version__} ({self.config.agent_name})"
        }
        if self._current_token:
            headers["Authorization"] = f"Bearer {self._current_token.access_token}"

        request_timeout_seconds = self.config.mcp_client.request_timeout_seconds
        connect_timeout_seconds = self.config.mcp_client.connect_timeout_seconds

        timeout = aiohttp.ClientTimeout(total=request_timeout_seconds, connect=connect_timeout_seconds)

        self.logger.debug("Sending HTTP JSONRPC request", endpoint=str(self.service_record.endpoint), method=request_payload.get('method'))
        try:
            async with session.post(
                str(self.service_record.endpoint), # Ensure endpoint is a string
                json=request_payload,
                headers=headers,
                timeout=timeout,
            ) as response:
                response_text = await response.text()
                self.logger.debug("Received HTTP response", status=response.status, content_length=len(response_text))

                if response.status == 401:
                    self.logger.warning("Authentication failed (401 Unauthorized)", server_response=response_text[:500])
                    raise MCPAuthError(f"Authentication failed (401) for {self.service_record.endpoint}")
                if response.status == 403:
                    self.logger.warning("Forbidden (403)", server_response=response_text[:500])
                    raise MCPAuthError(f"Forbidden (403) for {self.service_record.endpoint}. Check permissions/scopes.")

                # According to JSONRPC spec, content type should be application/json
                # However, some servers might not set it correctly, so be a bit lenient
                # if response.content_type != "application/json":
                #     self.logger.warning("Unexpected Content-Type", received_content_type=response.content_type, expected="application/json")
                #     # raise MCPProtocolError(f"Expected Content-Type application/json, got {response.content_type}")

                if response.status >= 300: # Includes 4xx and 5xx errors not caught above
                    self.logger.error("HTTP error status received", status=response.status, reason=response.reason, response_body=response_text[:500]) # Log snippet of body
                    raise MCPConnectionError(f"HTTP error {response.status} {response.reason} from {self.service_record.endpoint}")

                try:
                    response_data = json.loads(response_text)
                except json.JSONDecodeError as e:
                    self.logger.error("Failed to decode JSON response", error=str(e), response_text=response_text[:500])
                    raise MCPProtocolError(f"Failed to decode JSON response from server: {e}") from e

                return response_data

        except aiohttp.ClientConnectorError as e:
            self.logger.error("Client connector error", error_os_error=e.os_error, error_str=str(e))
            raise MCPConnectionError(f"Connection failed to {self.service_record.endpoint}: {e.os_error or str(e)}") from e
        except TimeoutError as e: # Catches aiohttp.ServerTimeoutError, ClientTimeoutError
            self.logger.error("Request timed out", endpoint=str(self.service_record.endpoint), timeout_total=request_timeout_seconds)
            raise MCPTimeoutError(f"Request to {self.service_record.endpoint} timed out after {request_timeout_seconds}s.") from e
        except aiohttp.ClientError as e: # Catch other aiohttp client errors
            self.logger.error("AIOHTTP client error", error_type=type(e).__name__, error_message=str(e))
            raise MCPConnectionError(f"HTTP client error for {self.service_record.endpoint}: {e}") from e


    # Example of a non-JSONRPC HTTP GET method, if needed for /capabilities
    async def get_http_capabilities(self) -> dict[str, Any]:
        """
        Fetches capabilities from a dedicated HTTP GET endpoint (e.g., /capabilities),
        if the server provides one outside of JSONRPC.
        """
        session = await self._get_session()
        from .. import __version__  # Dynamically import version
        headers = {"Accept": "application/json", "User-Agent": f"MCPVacuumAgent/{__version__} ({self.config.agent_name})"}
        if self._current_token:
            headers["Authorization"] = f"Bearer {self._current_token.access_token}"

        # Assuming capabilities endpoint is base_url + "/capabilities"
        capabilities_url = str(self.service_record.endpoint).rstrip('/') + "/capabilities"

        request_timeout_seconds = self.config.mcp_client.request_timeout_seconds
        connect_timeout_seconds = self.config.mcp_client.connect_timeout_seconds
        timeout = aiohttp.ClientTimeout(total=request_timeout_seconds, connect=connect_timeout_seconds)

        self.logger.info("Fetching capabilities via HTTP GET", url=capabilities_url)
        try:
            async with session.get(capabilities_url, headers=headers, timeout=timeout) as response:
                response_text = await response.text()
                self.logger.debug("Received HTTP GET response for capabilities", status=response.status)
                if response.status == 200:
                    try:
                        return json.loads(response_text)
                    except json.JSONDecodeError as e:
                        self.logger.error("Failed to decode JSON from /capabilities", error=str(e), response_text=response_text[:500])
                        raise MCPProtocolError(f"Failed to decode JSON from {capabilities_url}: {e}") from e
                else:
                    self.logger.warning("Failed to get /capabilities", status=response.status, reason=response.reason, response_body=response_text[:500])
                    raise MCPConnectionError(f"Failed to fetch capabilities from {capabilities_url}: HTTP {response.status}")
        except TimeoutError as e:
            self.logger.error("Timeout fetching /capabilities", url=capabilities_url)
            raise MCPTimeoutError(f"Request to {capabilities_url} timed out.") from e
        except aiohttp.ClientError as e:
            self.logger.error("Client error fetching /capabilities", url=capabilities_url, error=str(e))
            raise MCPConnectionError(f"Client error fetching capabilities from {capabilities_url}: {e}") from e

    # Override get_server_capabilities if it uses HTTP GET /capabilities
    # async def get_server_capabilities(self) -> Dict[str, Any]:
    #     # This depends on whether MCP spec says capabilities is JSONRPC or HTTP GET
    #     # If it's HTTP GET, uncomment this and use self.get_http_capabilities()
    #     # self.logger.info("Using HTTP GET for /capabilities")
    #     # return await self.get_http_capabilities()
    #     # Otherwise, fall back to base class JSONRPC method
    #     self.logger.info("Using JSONRPC mcp.capabilities method")
    #     return await super().get_server_capabilities()
    pass # End of HTTPMCPClient class
