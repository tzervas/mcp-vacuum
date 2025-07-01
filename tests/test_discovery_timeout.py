"""
Tests for discovery service timeout handling.
"""
import asyncio
import pytest
from unittest.mock import Mock, patch

from mcp_vacuum.discovery.discovery_service import MCPDiscoveryService
from mcp_vacuum.config import Config, DiscoveryConfig


@pytest.fixture
def config():
    """Create a test configuration."""
    config_mock = Mock(spec=Config)
    discovery_config = Mock(spec=DiscoveryConfig)
    discovery_config.enable_mdns = True
    discovery_config.mdns_service_types = ["_mcp._tcp.local."]
    discovery_config.timeout_seconds = 1
    discovery_config.scan_timeout_seconds = 1
    discovery_config.cache_ttl_seconds = 60
    discovery_config.allowed_networks = None
    config_mock.discovery = discovery_config
    return config_mock


async def test_mdns_discovery_timeout_handling(config):
    """Test that mDNS discovery properly handles timeouts."""
    service = MCPDiscoveryService(config)

    # Test normal timeout during discovery
    records = []
    async for record in service.discover_servers_mdns(timeout=1):
        records.append(record)
    
    assert len(records) == 0  # No records due to short timeout


async def test_mdns_service_info_request_timeout(config):
    """Test that mDNS service info request properly handles timeouts."""
    service = MCPDiscoveryService(config)
    
    # Create a mock Zeroconf instance
    mock_zc = Mock()
    mock_service_info = Mock()
    
    # Mock async_request to simulate a timeout
    async def mock_async_request(*args, **kwargs):
        await asyncio.sleep(4)  # Sleep longer than the request timeout (3s)
        return False
    
    mock_service_info.async_request = mock_async_request
    
    # Test service info request timeout
    with patch("zeroconf.asyncio.AsyncServiceInfo", return_value=mock_service_info):
        # The service info processing should handle the timeout gracefully
        await service._process_mdns_service_info(
            mock_zc,
            "_mcp._tcp.local.",
            "test-service._mcp._tcp.local.",
            set()
        )
        # No exception should be raised, and no service should be added to the queue
