"""
Custom exceptions for the MCP client.
"""
from typing import Any, Dict, Optional

class MCPClientError(Exception):
    """Base class for all MCP client errors."""
    pass

class MCPConnectionError(MCPClientError):
    """Raised when there's an issue connecting to the MCP server."""
    pass

class MCPTimeoutError(MCPConnectionError):
    """Raised when a connection or request times out."""
    pass

class MCPProtocolError(MCPClientError):
    """Raised for errors related to the JSONRPC protocol itself
    (e.g., malformed responses, unexpected message format)."""
    def __init__(self, message: str, error_code: Optional[int] = None, error_data: Optional[Dict] = None):
        super().__init__(message)
        self.error_code = error_code
        self.error_data = error_data

class MCPToolInvocationError(MCPClientError):
    """Raised when invoking a tool on the MCP server results in an error
    reported by the server's JSONRPC error response for that tool call."""
    def __init__(self, tool_name: str, message: str, error_code: Optional[int] = None, error_data: Optional[Dict] = None):
        full_message = f"Error invoking tool '{tool_name}': {message}"
        super().__init__(full_message)
        self.tool_name = tool_name
        self.original_message = message
        self.error_code = error_code
        self.error_data = error_data

class MCPAuthError(MCPClientError):
    """Raised for authentication specific errors during MCP communication."""
    def __init__(self, message: str, server_error: Optional[Any] = None, requires_reauth: bool = False):
        super().__init__(message)
        self.server_error = server_error
        self.requires_reauth = requires_reauth
