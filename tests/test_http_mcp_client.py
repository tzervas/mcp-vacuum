"""
Unit tests for HTTPMCPClient.
"""
import json
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from mcp_vacuum.config import Config, MCPClientConfig
from mcp_vacuum.mcp_client.exceptions import (
    MCPAuthError,
    MCPConnectionError,
    MCPProtocolError,
    MCPTimeoutError,
)
from mcp_vacuum.mcp_client.http_client import HTTPMCPClient
from mcp_vacuum.models.auth import OAuth2Token
from mcp_vacuum.models.common import TransportType
from mcp_vacuum.models.mcp import MCPServiceRecord


@pytest.fixture
def app_config():
    # Ensure MCPClientConfig has connection pool settings for TCPConnector mock later
    mcp_client_cfg = MCPClientConfig(
        connection_pool_total_limit=50,
        connection_pool_per_host_limit=10,
        connection_pool_dns_cache_ttl_seconds=120,
        ssl_verify=True # Default, can be overridden in specific tests
    )
    return Config(mcp_client=mcp_client_cfg)

@pytest.fixture
def service_record():
    return MCPServiceRecord(
        id="http_server_1",
        name="TestHTTPServer",
        endpoint="http://fake-server.example.com:8080/mcp",
        transport_type=TransportType.HTTP, # Ensure this is set correctly
        discovery_method="test"
    )

@pytest.fixture
def mock_aiohttp_session_post():
    """Fixture to provide a mock for aiohttp.ClientSession.post method."""
    mock_post = AsyncMock()
    # Default successful response
    mock_response = AsyncMock()
    mock_response.status = 200
    mock_response.text = AsyncMock(return_value=json.dumps({"jsonrpc": "2.0", "id": "1", "result": "success"}))
    mock_response.json = AsyncMock(return_value={"jsonrpc": "2.0", "id": "1", "result": "success"}) # If client uses .json()
    mock_post.return_value.__aenter__.return_value = mock_response
    return mock_post

@pytest.fixture
async def http_client(app_config, service_record, mock_aiohttp_session_post):
    """Creates an HTTPMCPClient with a mocked session for most tests."""
    # Mock the aiohttp.ClientSession that HTTPMCPClient might create internally
    # or one that could be passed to it.
    mock_session = AsyncMock(spec=aiohttp.ClientSession)
    mock_session.closed = False
    mock_session.post = mock_aiohttp_session_post # Use the more specific post mock

    # Patch TCPConnector to avoid real network/DNS lookups during session creation by client
    with patch('aiohttp.TCPConnector', MagicMock()):
        client = HTTPMCPClient(service_record, app_config, aiohttp_session=mock_session)
        # If client creates its own session, _get_session would be called.
        # If session is passed in, it's used directly.
        # For these tests, we are passing a mock_session.
        client._session = mock_session # Ensure our mock session is used
        yield client # Use yield to ensure cleanup if client had __aexit__
        await client.disconnect() # Ensure session is cleaned up if client owns it (not in this mock setup)

@pytest.mark.asyncio
async def test_http_client_send_request_raw_success(http_client, mock_aiohttp_session_post, service_record):
    """Test _send_request_raw successfully sends and receives a JSONRPC response."""
    request_payload = {"jsonrpc": "2.0", "method": "test.method", "id": "1", "params": {}}
    expected_response_data = {"jsonrpc": "2.0", "id": "1", "result": "success"}

    # Configure the mock_aiohttp_session_post for this specific test if defaults aren't enough
    mock_response = mock_aiohttp_session_post.return_value.__aenter__.return_value
    mock_response.status = 200
    mock_response.text = AsyncMock(return_value=json.dumps(expected_response_data))

    response = await http_client._send_request_raw(request_payload)

    assert response == expected_response_data
    mock_aiohttp_session_post.assert_called_once()
    call_args = mock_aiohttp_session_post.call_args
    assert call_args[0][0] == str(service_record.endpoint) # URL
    assert call_args[1]['json'] == request_payload # Data
    assert "application/json" in call_args[1]['headers']['Content-Type']
    assert "MCPVacuumAgent" in call_args[1]['headers']['User-Agent']


@pytest.mark.asyncio
async def test_http_client_send_request_raw_auth_header(http_client, mock_aiohttp_session_post):
    """Test that Authorization header is added if token is present."""
    token = OAuth2Token(access_token="test_bearer_token", expires_in=3600)
    await http_client.set_auth_token(token)

    request_payload = {"jsonrpc": "2.0", "method": "auth.test", "id": "2"}
    await http_client._send_request_raw(request_payload) # We only care about the call args here

    mock_aiohttp_session_post.assert_called_once()
    headers = mock_aiohttp_session_post.call_args[1]['headers']
    assert headers["Authorization"] == "Bearer test_bearer_token"

@pytest.mark.asyncio
async def test_http_client_send_request_raw_http_error_401(http_client, mock_aiohttp_session_post):
    """Test handling of HTTP 401 Unauthorized error."""
    mock_response = mock_aiohttp_session_post.return_value.__aenter__.return_value
    mock_response.status = 401
    mock_response.text = AsyncMock(return_value="Unauthorized access")

    with pytest.raises(MCPAuthError, match="Authentication failed (401)"):
        await http_client._send_request_raw({"id": "3"})

@pytest.mark.asyncio
async def test_http_client_send_request_raw_http_error_500(http_client, mock_aiohttp_session_post, service_record):
    """Test handling of generic HTTP 500 Server Error."""
    mock_response = mock_aiohttp_session_post.return_value.__aenter__.return_value
    mock_response.status = 500
    mock_response.reason = "Internal Server Error"
    mock_response.text = AsyncMock(return_value="Server exploded")

    with pytest.raises(MCPConnectionError, match=f"HTTP error 500 Internal Server Error from {service_record.endpoint}"):
        await http_client._send_request_raw({"id": "4"})


@pytest.mark.asyncio
async def test_http_client_send_request_raw_timeout(http_client, mock_aiohttp_session_post):
    """Test handling of asyncio.TimeoutError (simulating request timeout)."""
    mock_aiohttp_session_post.side_effect = TimeoutError("Request timed out")

    with pytest.raises(MCPTimeoutError, match="timed out"):
        await http_client._send_request_raw({"id": "5"})

@pytest.mark.asyncio
async def test_http_client_send_request_raw_connection_error(http_client, mock_aiohttp_session_post, service_record):
    """Test handling of aiohttp.ClientConnectorError."""
    # Simulate a connection error (e.g., DNS resolution failure, host unreachable)
    # The OSError usually contains more specific info.
    mock_aiohttp_session_post.side_effect = aiohttp.ClientConnectorError(MagicMock(), OSError("Name or service not known"))

    with pytest.raises(MCPConnectionError, match=f"Connection failed to {service_record.endpoint}: Name or service not known"):
        await http_client._send_request_raw({"id": "6"})


@pytest.mark.asyncio
async def test_http_client_send_request_raw_invalid_json_response(http_client, mock_aiohttp_session_post):
    """Test handling of response that is not valid JSON."""
    mock_response = mock_aiohttp_session_post.return_value.__aenter__.return_value
    mock_response.status = 200
    mock_response.text = AsyncMock(return_value="<not_json>this is not json</not_json>")

    with pytest.raises(MCPProtocolError, match="Failed to decode JSON response from server"):
        await http_client._send_request_raw({"id": "7"})

@pytest.mark.asyncio
async def test_http_client_connect_disconnect_session_management(app_config, service_record):
    """Test client creating and closing its own session if none is provided."""

    # Patch TCPConnector to avoid real network activity during ClientSession creation
    with patch('aiohttp.TCPConnector', MagicMock()) as MockTCPConnectorInstance:
        client = HTTPMCPClient(service_record, app_config, aiohttp_session=None) # No session provided
        assert client._session is None # Initially no session

        await client.connect() # Should create a session
        assert client._session is not None
        assert not client._session.closed
        MockTCPConnectorInstance.assert_called_once() # TCPConnector should have been instantiated

        session_instance = client._session # Keep a reference

        await client.disconnect() # Should close the session it created
        assert client._session is None # Session should be cleared from client
        assert session_instance.closed # The actual session object should be closed

@pytest.mark.asyncio
async def test_http_client_get_http_capabilities_success(http_client, mock_aiohttp_session_post, service_record):
    """Test fetching capabilities via HTTP GET successfully."""
    # This method is separate from JSONRPC, uses session.get
    # Need to mock session.get for this client instance
    mock_get_response = AsyncMock()
    mock_get_response.status = 200
    capabilities_data = {"version": "1.0", "tools": ["toolA", "toolB"]}
    mock_get_response.text = AsyncMock(return_value=json.dumps(capabilities_data))

    # Replace the client's session's get method with a new AsyncMock for this test
    http_client._session.get = AsyncMock()
    http_client._session.get.return_value.__aenter__.return_value = mock_get_response

    result = await http_client.get_http_capabilities()
    assert result == capabilities_data

    expected_url = str(service_record.endpoint).rstrip('/') + "/capabilities"
    http_client._session.get.assert_called_once()
    assert http_client._session.get.call_args[0][0] == expected_url


# BaseClient's send_request (which uses _send_request_raw) tests (error handling, retries)
# would be more complex to unit test here without also testing BaseClient heavily.
# For P1, focusing on _send_request_raw of HTTPMCPClient is key.
# Tests for BaseClient's retry logic could be separate or integration tests.
# Testing SSL verification logic in _get_session for HTTPMCPClient would require
# more intricate mocking of aiohttp.TCPConnector's ssl parameter or actual SSL contexts.
# For P1, we assume the ssl=True/False/ssl.SSLContext() path in TCPConnector works as expected.
