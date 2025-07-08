"""
Base MCP Client Abstract Class.
"""
import abc
import asyncio
import random
import uuid
from collections.abc import AsyncGenerator
from typing import Any, List, Dict

import aiohttp  # type: ignore[import-not-found]
import structlog # Added import for structlog
from ..config import Config, MCPClientConfig  # MCPClientConfig for CB settings
from ..models.auth import OAuth2Token
from ..models.mcp import MCPServiceRecord
from ..utils.resilience import CircuitBreaker, CircuitBreakerOpenError
from .exceptions import (
    MCPClientError,
    MCPConnectionError,
    MCPProtocolError,
    MCPTimeoutError,
    MCPToolInvocationError,
)

# Consider using a dedicated JSON-RPC library or building a robust handler.
# For now, a simple request/response formatter.

def generate_jsonrpc_request(method: str, params: dict[str, Any] | None = None, request_id: str | int | None = None) -> dict[str, Any]:
    """Generates a JSONRPC 2.0 request dictionary."""
    if request_id is None:
        request_id = str(uuid.uuid4())
    return {
        "jsonrpc": "2.0",
        "method": method,
        "params": params if params is not None else {},
        "id": request_id,
    }

class BaseMCPClient(abc.ABC):
    """
    Abstract Base Class for an MCP (Model Context Protocol) client.
    Defines the common interface for interacting with an MCP server,
    regardless of the underlying transport mechanism.
    """

    def __init__(self, service_record: MCPServiceRecord, config: Config, aiohttp_session: aiohttp.ClientSession | None = None):
        self.service_record = service_record
        self.config = config
        self.mcp_client_config: MCPClientConfig = config.mcp_client # Store typed mcp_client config
        self._session = aiohttp_session # For HTTP based transports
        self._current_token: OAuth2Token | None = None # To be managed by auth system

        self.logger = structlog.get_logger(__name__).bind(client_for_server=service_record.name, server_endpoint=str(service_record.endpoint))

        if self.mcp_client_config.enable_circuit_breaker:
            self._circuit_breaker: CircuitBreaker | None = CircuitBreaker(
                failure_threshold=self.mcp_client_config.cb_failure_threshold,
                recovery_timeout_seconds=self.mcp_client_config.cb_recovery_timeout_seconds,
                half_open_max_successes=self.mcp_client_config.cb_half_open_max_successes,
                name=f"CB-{service_record.name.replace('.', '-')}-{service_record.id}"[:50] # Short unique name
            )
            self.logger.info("Circuit breaker enabled for this client.")
        else:
            self._circuit_breaker = None
            self.logger.info("Circuit breaker is disabled for this client.")


    async def set_auth_token(self, token: OAuth2Token | None):
        """Sets the OAuth2 token to be used for requests."""
        self._current_token = token

    @abc.abstractmethod
    async def connect(self) -> None:
        """
        Establishes a connection to the MCP server.
        Specific implementation depends on the transport (HTTP, WebSocket, STDIO, SSE).
        For HTTP, this might be a no-op if sessions are managed per request,
        or it could establish a persistent session.
        """
        pass

    @abc.abstractmethod
    async def disconnect(self) -> None:
        """
        Closes the connection to the MCP server.
        """
        pass

    @abc.abstractmethod
    async def is_connected(self) -> bool:
        """
        Checks if the client is currently connected to the server.
        """
        pass

    @abc.abstractmethod
    async def _send_request_raw(self, request_payload: dict[str, Any], is_idempotent: bool) -> dict[str, Any]:
        """
        Sends a raw JSONRPC request payload and returns the raw JSONRPC response.
        This is the core method that transport-specific clients must implement.
        It should handle serialization, deserialization, and transport-level communication.
        It should also raise MCPTimeoutError on transport timeouts.
        Args:
            request_payload: The JSON-RPC request payload.
            is_idempotent: Whether the operation is idempotent. This can influence retry behavior
                           at the transport layer if it has its own retries, though the primary
                           retry logic here uses this flag.
        """
        pass

    async def send_request(self, method: str, params: dict[str, Any] | None = None, request_id: str | int | None = None, is_idempotent: bool = True) -> Any:
        """
        Constructs a JSONRPC request, sends it, and processes the response.
        Handles retries (if applicable) and JSONRPC error checking.
        Args:
            method: The JSON-RPC method name.
            params: Optional parameters for the method.
            request_id: Optional custom request ID.
            is_idempotent: Whether the operation is idempotent. Non-idempotent operations
                           will not be retried by this client's retry logic.
        """
        # HTTP is often connectionless per request, so is_connected might be less relevant before the actual attempt.
        # For other transport types, a persistent connection is usually expected.
        from ..models.common import TransportType  # Import for enum comparison
        if not await self.is_connected() and self.service_record.transport_type != TransportType.HTTP: # HTTP is often connectionless per request
            # Attempt to reconnect or raise error, depending on strategy
            # For now, let's assume connect() should be called explicitly by managing code if needed.
             raise MCPConnectionError(f"Not connected to MCP server: {self.service_record.name} for non-HTTP transport.")

        req_payload = generate_jsonrpc_request(method, params, request_id)

        max_attempts = self.mcp_client_config.max_retries
        initial_backoff = self.mcp_client_config.initial_backoff_seconds
        max_backoff = self.mcp_client_config.max_backoff_seconds

        last_exception: Exception | None = None

        for attempt in range(max_attempts):
            log_attempt = self.logger.bind(attempt=attempt + 1, max_attempts=max_attempts, method=method, request_id=req_payload["id"])
            try:
                log_attempt.debug("Attempting to send request.")

                response_payload: dict[str, Any]
                if self._circuit_breaker:
                    response_payload = await self._circuit_breaker.call(self._send_request_raw, req_payload, is_idempotent)
                else:
                    response_payload = await self._send_request_raw(req_payload, is_idempotent)

                log_attempt.debug("Received raw response payload.", response_id=response_payload.get("id"), result_present="result" in response_payload, error_present="error" in response_payload)

                # Process JSONRPC response (same as before)
                if response_payload.get("id") != req_payload.get("id"):
                    log_attempt.error("JSONRPC response ID mismatch", expected_id=req_payload.get("id"), received_id=response_payload.get("id"))
                    raise MCPProtocolError(f"JSONRPC response ID mismatch. Expected {req_payload.get('id')}, got {response_payload.get('id')}")

                if "error" in response_payload:
                    err = response_payload["error"]
                    err_msg = err.get("message", "Unknown MCP error")
                    err_code = err.get("code")
                    err_data = err.get("data")
                    log_attempt.warning("JSONRPC error response received.", code=err_code, msg=err_msg, data=err_data)
                    if method.startswith("tool/"):
                        raise MCPToolInvocationError(tool_name=method, message=err_msg, error_code=err_code, error_data=err_data)
                    else:
                        raise MCPProtocolError(message=err_msg, error_code=err_code, error_data=err_data)

                if "result" not in response_payload:
                    log_attempt.error("Invalid JSONRPC response: missing 'result' field.", response_snippet=str(response_payload)[:200])
                    raise MCPProtocolError("Invalid JSONRPC response: missing 'result' field.")

                return response_payload["result"]

            except CircuitBreakerOpenError as cboe:
                last_exception = cboe
                log_attempt.warning("Circuit breaker is OPEN. Request rejected.", remaining_time=cboe.remaining_time)
                # If CB is open, no point in retrying immediately. Re-raise to fail fast for this call.
                raise MCPConnectionError(f"Circuit breaker for {self.service_record.name} is open. Try again in {cboe.remaining_time:.1f}s.") from cboe

            except (MCPConnectionError, MCPTimeoutError, aiohttp.ClientError) as e:
                # These are errors that the circuit breaker will count as failures if it wraps _send_request_raw.
                # The retry loop here provides an additional layer of retries if the CB is CLOSED/HALF_OPEN.
                last_exception = e
                if is_idempotent and attempt < max_attempts - 1: # Only retry if idempotent
                    # Standard exponential backoff with full jitter: random delay between 0 and capped backoff
                    capped_backoff = min(initial_backoff * (2 ** attempt), max_backoff)
                    backoff_time = random.uniform(0, capped_backoff)
                    log_attempt.warning(f"Connection error encountered. Retrying in {backoff_time:.2f}s...", error_message=str(e), error_type=type(e).__name__)
                    await asyncio.sleep(backoff_time)
                else:
                    log_attempt.error(f"Failed request after {max_attempts} attempts or because non-idempotent.", last_error=str(e), is_idempotent=is_idempotent)
                    if isinstance(e, MCPConnectionError | MCPTimeoutError):
                        raise
                    else: # Wrap other ClientErrors
                        raise MCPConnectionError(f"Failed request '{method}' (idempotent={is_idempotent}) after {attempt + 1} attempts: {e}") from e

            except MCPClientError: # Non-retryable application-level MCP errors (Protocol, ToolInvocation)
                log_attempt.warning("Non-retryable MCPClientError encountered.")
                raise # Re-raise immediately, do not retry these.

            except Exception as e: # Catch any other unexpected errors
                last_exception = e
                log_attempt.exception("Unexpected error during request.", error_type=type(e).__name__)
                if is_idempotent and attempt < max_attempts - 1: # Only retry if idempotent
                    backoff_time = min(initial_backoff * (2 ** attempt) + random.uniform(0, 0.1 * initial_backoff), max_backoff)
                    await asyncio.sleep(backoff_time)
                else:
                    raise MCPClientError(f"Unexpected error during request '{method}' (idempotent={is_idempotent}) after {attempt+1} attempts: {e}") from e

        # Fallback if loop finishes without returning or raising (should not happen with max_attempts >=1 for idempotent calls)
        if last_exception:
            self.logger.error("Request failed after all retries (or was non-idempotent), re-raising last known exception.", method=method, last_exception_type=type(last_exception).__name__)
            if isinstance(last_exception, MCPClientError):
                raise last_exception
            else:
                raise MCPClientError(f"Request '{method}' failed due to: {last_exception}") from last_exception

        raise MCPClientError(f"Request '{method}' failed after exhausting retries (or was non-idempotent), but no specific exception was properly propagated.")


    async def get_server_capabilities(self) -> dict[str, Any]:
        """
        Retrieves the server's capabilities. Standard method name: "mcp.capabilities".
        This is an idempotent operation.
        """
        return await self.send_request(method="mcp.capabilities", is_idempotent=True)

    async def list_tools(self) -> List[dict[str, Any]]:
        """
        Lists all tools available on the MCP server. Standard method name: "mcp.listTools".
        This is an idempotent operation.
        The result should be a list of objects that can be parsed into MCPTool models.
        """
        raw_tools_data = await self.send_request(method="mcp.listTools", is_idempotent=True)
        # TODO: Add Pydantic parsing here: [MCPTool.model_validate(t) for t in raw_tools_data]
        return raw_tools_data

    async def get_tool_schema(self, tool_name: str) -> dict[str, Any]:
        """
        Retrieves the detailed schema for a specific tool. Standard method name: "mcp.getToolSchema".
        This is an idempotent operation.
        The result should be an object parsable into an MCPTool model.
        """
        tool_schema_data = await self.send_request(method="mcp.getToolSchema", params={"tool_name": tool_name}, is_idempotent=True)
        # TODO: Add Pydantic parsing here: MCPTool.model_validate(tool_schema_data)
        return tool_schema_data

    async def invoke_tool(
        self,
        tool_name: str,
        parameters: dict[str, Any],
        is_idempotent: bool = False # Tool invocations are often NOT idempotent by default
    ) -> Any:
        """
        Invokes a specific tool on the MCP server. Tool methods are typically prefixed, e.g., "tool/calculator.add".
        Client-side validation of parameters against the tool's inputSchema should be performed
        by the calling agent/service before invoking this method.
        Args:
            tool_name: The name of the tool to invoke.
            parameters: The parameters for the tool.
            is_idempotent: Specify if this particular tool invocation is idempotent. Defaults to False.
        """
        return await self.send_request(method=f"tool/{tool_name}", params=parameters, is_idempotent=is_idempotent)

    async def subscribe_to_event(self, event_name: str) -> AsyncGenerator[dict[str, Any], None]:
        """
        Subscribes to a server-side event stream (if transport supports it, e.g., SSE, WebSockets).
        """
        raise NotImplementedError(f"Event subscription via 'subscribe_to_event' is not implemented for {self.service_record.transport_type.value} transport.")

    def get_session(self) -> aiohttp.ClientSession | None:
        """Returns the aiohttp session if used by the client (primarily for HTTP-based transports)."""
        return self._session

    async def close_session(self) -> None:
        """Closes the aiohttp session if it's managed by this client instance and not closed."""
        if self._session and not self._session.closed:
            # self.logger.info("Closing aiohttp session.")
            await self._session.close()
        self._session = None # Clear it regardless, if this method is called.

    async def __aenter__(self):
        # self.logger.debug("Entering client context, connecting...")
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        # self.logger.debug("Exiting client context, disconnecting...", exc_type=exc_type)
        await self.disconnect()
        # Session closure should be handled by disconnect or explicitly by the session owner.
        # If the session was created by this client instance and not passed in, disconnect might close it.
        pass

# TODO: Add MCPClientConfig to the main Config model in config.py
# class MCPClientConfig(BaseModel):
#     max_retries: int = Field(default=3, ge=0, description="Maximum number of retries for failed requests.")
#     initial_backoff_seconds: float = Field(default=1.0, ge=0.1, description="Initial backoff delay for retries.")
#     max_backoff_seconds: float = Field(default=30.0, ge=1.0, description="Maximum backoff delay for retries.")
#     request_timeout_seconds: float = Field(default=60.0, ge=5.0, description="Default timeout for individual requests.")
#     # This request_timeout_seconds would be used by _send_request_raw implementations.

# The BaseMCPClient provides a common structure.
# Specific transport clients (HTTP, WS, SSE, STDIO) will inherit from this
# and implement the abstract methods, particularly _send_request_raw.
# Logging with structlog should be integrated throughout.
# The actual JSONRPC method names ("mcp.capabilities", "mcp.listTools", etc.)
# are based on the research documentation and common sense; they must match the MCP server spec.
# Client-side Pydantic validation of responses (e.g., parsing list_tools output into List[MCPTool])
# should be added once the models are stable and server responses are known.
# The handling of aiohttp.ClientSession needs to be robust:
#  - It can be passed in (shared session).
#  - If not passed, an HTTP-based client might create its own.
#  - Lifecycle (creation, closing) must be clear. `close_session` and `__aexit__` help.
#  - The `aiohttp_session` parameter in `__init__` facilitates sharing.
#  - Connection pooling is managed by `aiohttp.TCPConnector` configured for the `ClientSession`.
#    The `DiscoveryClient` in docs had `TCPConnector(limit=100, limit_per_host=30)`.
#    This should be configured when the shared session is created.
# The check `if not await self.is_connected() and not self.service_record.transport_type == "http":`
# in `send_request` is a pragmatic way to handle HTTP's often "connectionless" nature at this level.
# For other transports like WebSocket or STDIO, `is_connected` is crucial.
# The retry logic is now slightly more robust with jitter and uses `getattr` for config access
# pending formal addition of `MCPClientConfig` to `Config`.
# Error handling distinguishes between connection errors (retryable) and protocol/tool errors (non-retryable by this layer).
# Import of `HttpUrl` from `pydantic` is now included.
# Added TODOs for logger initialization and Pydantic model validation on responses.
