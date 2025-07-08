"""
MCP Protocol Client Implementation.

This module provides the JSONRPC 2.0 client for interacting with MCP servers
over various transports (HTTP, WebSocket, SSE, STDIO).
"""

from .base_client import BaseMCPClient
from .exceptions import (
    MCPClientError,
    MCPConnectionError,
    MCPProtocolError,
    MCPTimeoutError,
    MCPToolInvocationError,
)

# Will add specific transport clients here later
# from .http_client import HTTPMCPClient
# from .ws_client import WebSocketMCPClient
# from .sse_client import SSEMCPClient
# from .stdio_client import STDIOMCPClient

__all__ = [
    "BaseMCPClient",
    "MCPClientError",
    "MCPConnectionError",
    "MCPProtocolError",
    "MCPTimeoutError",
    "MCPToolInvocationError",
    # "HTTPMCPClient",
    # "WebSocketMCPClient",
    # "SSEMCPClient",
    # "STDIOMCPClient",
]
