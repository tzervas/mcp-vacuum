"""
Tests for HTTP client timeout handling.
"""
import asyncio
import pytest
from aiohttp import ClientSession, ClientTimeout
from unittest.mock import Mock, patch, AsyncMock

from mcp_vacuum.mcp_client.http_client import HTTPMCPClient
from mcp_vacuum.mcp_client.exceptions import MCPTimeoutError
from mcp_vacuum.models.mcp import MCPServiceRecord
from mcp_vacuum.config import Config


@pytest.fixture
def config():
    """Create a test configuration."""
    mcp_client_config = Mock()
    mcp_client_config.request_timeout_seconds = 1.0
    mcp_client_config.connect_timeout_seconds = 1.0
    mcp_client_config.enable_circuit_breaker = True
    mcp_client_config.cb_failure_threshold = 5
    mcp_client_config.cb_recovery_timeout_seconds = 30.0
    mcp_client_config.cb_half_open_max_successes = 2
    mcp_client_config.max_retries = 3
    mcp_client_config.initial_backoff_seconds = 1.0
    mcp_client_config.max_backoff_seconds = 30.0
    
    config_mock = Mock(spec=Config)
    config_mock.mcp_client = mcp_client_config
    config_mock.agent_name = "test-agent"
    return config_mock


@pytest.fixture
def service_record():
    """Create a test service record."""
    return MCPServiceRecord(
        id="test-service",
        name="Test Service",
        endpoint="http://localhost:8080",
        transport_type="http",
        version="1.0",
        auth_method="none",
        discovery_method="test",
    )


async def test_http_client_request_timeout(config, service_record):
    """Test that the HTTP client properly handles request timeouts."""
    client = HTTPMCPClient(service_record, config)

    # Mock session to simulate a timeout
    async def mock_post(*args, **kwargs):
        await asyncio.sleep(2)  # Sleep longer than the timeout
        return Mock()

    # Create response mock
    mock_response = AsyncMock()
    mock_response.status = 408  # Request Timeout
    mock_response.text = AsyncMock(return_value="Request timed out")
    
    # Create session mock
    mock_session = AsyncMock(spec=ClientSession)
    mock_session.post.return_value.__aenter__.return_value = mock_response
    mock_session.post.return_value.__aexit__.return_value = None
    mock_session.closed = False

    client._session = mock_session

    # Test timeout during request
    with pytest.raises(MCPTimeoutError) as exc_info:
        await client._send_request_raw({"method": "test", "params": {}})

    assert "timed out" in str(exc_info.value)


async def test_http_client_capabilities_timeout(config, service_record):
    """Test that the HTTP client properly handles timeouts during capabilities request."""
    client = HTTPMCPClient(service_record, config)

    # Mock session to simulate a timeout
    async def mock_get(*args, **kwargs):
        await asyncio.sleep(2)  # Sleep longer than the timeout
        return Mock()

    # Create response mock
    mock_response = AsyncMock()
    mock_response.status = 408  # Request Timeout
    mock_response.text = AsyncMock(return_value="Request timed out")
    
    # Create session mock
    mock_session = AsyncMock(spec=ClientSession)
    mock_session.get.return_value.__aenter__.return_value = mock_response
    mock_session.get.return_value.__aexit__.return_value = None
    mock_session.closed = False

    client._session = mock_session

    # Test timeout during capabilities request
    with pytest.raises(MCPTimeoutError) as exc_info:
        await client.get_http_capabilities()

    assert "timed out" in str(exc_info.value)
