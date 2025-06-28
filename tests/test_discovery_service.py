"""
Unit tests for MCPDiscoveryService.
"""
import pytest
import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch, call

from zeroconf import ServiceStateChange, Zeroconf # For type hints and constants
# from zeroconf.asyncio import AsyncServiceInfo as RealAsyncServiceInfo # For isinstance checks if needed

from mcp_vacuum.config import Config, DiscoveryConfig
from mcp_vacuum.discovery.discovery_service import MCPDiscoveryService
from mcp_vacuum.models.mcp import MCPServiceRecord
from mcp_vacuum.models.common import AuthMethod

@pytest.fixture
def app_config_mdns_enabled():
    discovery_cfg = DiscoveryConfig(
        enable_mdns=True,
        mdns_service_types=["_mcp._tcp.local."],
        cache_ttl_seconds=60,
        allowed_networks=[] # Allow all for basic tests
    )
    return Config(discovery=discovery_cfg)

@pytest.fixture
def discovery_service(app_config_mdns_enabled):
    return MCPDiscoveryService(app_config=app_config_mdns_enabled)

# --- Mock zeroconf components ---
@pytest.fixture
def MockAsyncServiceInfo():
    """Mocks zeroconf.asyncio.AsyncServiceInfo."""
    class MockInfo:
        def __init__(self, type_: str, name: str):
            self.type = type_
            self.name = name
            self.server = f"{name.split('.')[0]}.local." # e.g. "myserver.local."
            self.port = 8080
            self.properties = {b"version": b"1.1", b"name": name.split('.')[0].encode()}
            self.addresses = [b"\xc0\xa8\x01\x64"] # 192.168.1.100
            self._ipv4_addresses = ["192.168.1.100"]
            self._ipv6_addresses = []

        async def async_request(self, zc: Zeroconf, timeout_ms: int) -> bool:
            # Simulate successful resolution
            return True

        def parsed_addresses(self, version=None) -> List[str]:
            if version == socket.AF_INET6: return self._ipv6_addresses
            return self._ipv4_addresses

        def parsed_addresses_by_version(self, version: int) -> List[str]:
            if version == socket.AF_INET: return self._ipv4_addresses
            if version == socket.AF_INET6: return self._ipv6_addresses
            return []


    return MockInfo

@pytest.fixture
def MockAsyncServiceBrowser():
    """Mocks zeroconf.asyncio.AsyncServiceBrowser."""
    class Browser:
        def __init__(self, aiozc_zeroconf, service_types, handlers):
            self.aiozc_zeroconf = aiozc_zeroconf
            self.service_types = service_types
            self.handlers = handlers
            self.running = True # Simulate browser running state
            self.logger = MagicMock() # Add a logger if methods inside use it

        async def async_cancel(self):
            self.running = False
            self.logger.debug("AsyncServiceBrowser mock cancelled.")

        # Method to simulate a service being added by the browser
        async def simulate_service_add(self, service_type, name):
            # Call the registered handler
            # The handler itself is synchronous in zeroconf, but it schedules async tasks.
            # We need to ensure our test can await those tasks if necessary.
            # The handler in MCPDiscoveryService is `on_service_state_change`
            # which calls `_process_mdns_service_info` as a new task.
            for handler in self.handlers:
                # Mimic how the handler is called by the actual browser
                 handler(self.aiozc_zeroconf, service_type, name, ServiceStateChange.Added)

    return Browser

@pytest.fixture
def MockAsyncZeroconf():
    """Mocks zeroconf.asyncio.AsyncZeroconf."""
    class AioZC:
        def __init__(self):
            self.zeroconf = MagicMock(spec=Zeroconf) # Mock the underlying Zeroconf instance
            # self.zeroconf.get_service_info = MagicMock() # if used directly
            self.logger = MagicMock()

        async def async_close(self):
            self.logger.debug("AsyncZeroconf mock closed.")

    return AioZC
# --- End Mock zeroconf components ---

@pytest.mark.asyncio
@patch('mcp_vacuum.discovery.discovery_service.AsyncServiceInfo') # Patch where it's used
@patch('mcp_vacuum.discovery.discovery_service.AsyncServiceBrowser')
@patch('mcp_vacuum.discovery.discovery_service.AsyncZeroconf')
async def test_discover_servers_mdns_single_service(
    MockAsyncZcCls, MockAsyncBrowserCls, MockAsyncInfoCls,
    discovery_service, app_config_mdns_enabled
):
    """Test mDNS discovery yields a single service."""
    # Setup mocks
    mock_aiozc_instance = MockAsyncZcCls()
    MockAsyncZcCls.return_value = mock_aiozc_instance

    mock_browser_instance = MockAsyncBrowserCls(mock_aiozc_instance.zeroconf, ["_mcp._tcp.local."], [])
    MockAsyncBrowserCls.return_value = mock_browser_instance

    # Configure MockAsyncServiceInfo to be returned when instantiated
    mock_service_info_instance = MockAsyncInfoCls("_mcp._tcp.local.", "MyMCPService._mcp._tcp.local.")
    mock_service_info_instance.properties = {b"name": b"MyFriendlyMCP", b"version": b"1.0", b"auth": b"none"}
    mock_service_info_instance.port = 8888
    mock_service_info_instance._ipv4_addresses = ["192.168.1.50"]
    MockAsyncInfoCls.return_value = mock_service_info_instance

    # This is tricky: the browser's handler is called, which then creates a task
    # for _process_mdns_service_info. We need that task to run and put item on queue.

    results = []
    # Shorten timeout for test
    discovery_timeout = 1.5 # Slightly longer than the internal queue poll (0.5s * 2 + buffer)

    # The discover_servers_mdns itself is an async generator.
    # We need to simulate the browser finding a service *while* we iterate this generator.
    async def discovery_task_runner():
        async for service in discovery_service.discover_servers_mdns(timeout=discovery_timeout):
            results.append(service)

    # Simulate service add *after* starting the discovery loop, but before it times out
    async def simulate_browser_action_after_delay():
        await asyncio.sleep(0.1) # Let discover_servers_mdns start and enter its loop
        # Simulate the browser finding the service
        # This will call on_service_state_change, which schedules _process_mdns_service_info
        await mock_browser_instance.simulate_service_add("_mcp._tcp.local.", "MyMCPService._mcp._tcp.local.")
        # _process_mdns_service_info will then put item on discovery_service._mdns_internal_queue
        # The main loop in discover_servers_mdns should pick it up.

    # Run discovery and simulation concurrently
    main_discovery_task = asyncio.create_task(discovery_task_runner())
    simulation_task = asyncio.create_task(simulate_browser_action_after_delay())

    await asyncio.gather(main_discovery_task, simulation_task)

    assert len(results) == 1
    service: MCPServiceRecord = results[0]
    assert service.name == "MyFriendlyMCP" # From TXT record
    assert service.id == "mdns-MyMCPService.local.-8888"
    assert service.endpoint.host == "192.168.1.50"
    assert service.endpoint.port == 8888
    assert service.version == "1.0"
    assert service.auth_method == AuthMethod.NONE
    assert service.discovery_method == "mdns"
    assert "name" in service.metadata # Check some metadata from TXT

@pytest.mark.asyncio
async def test_discovery_service_cache_ttl(discovery_service, app_config_mdns_enabled):
    """Test cache TTL functionality."""
    app_config_mdns_enabled.discovery.cache_ttl_seconds = 1 # Short TTL for test

    record1 = MCPServiceRecord(id="ttl_server1", name="TTLServer", endpoint="http://1.2.3.4:80", discovery_method="test")

    # Manually add to cache for testing get_cached_server
    discovery_service._discovered_services_cache[record1.id] = (record1, time.time() - 2) # 2 seconds ago, expired

    assert discovery_service.get_cached_server(record1.id) is None # Should be expired and removed
    assert record1.id not in discovery_service._discovered_services_cache # Check removed

    record2 = MCPServiceRecord(id="ttl_server2", name="TTLServer2", endpoint="http://1.2.3.5:80", discovery_method="test")
    discovery_service._discovered_services_cache[record2.id] = (record2, time.time() - 0.5) # 0.5 sec ago, not expired

    assert discovery_service.get_cached_server(record2.id) == record2
    assert record2.id in discovery_service._discovered_services_cache # Still there

@pytest.mark.asyncio
async def test_discovery_service_allowed_networks_filter(discovery_service, app_config_mdns_enabled):
    """Test allowed_networks filtering."""
    app_config_mdns_enabled.discovery.allowed_networks = ["192.168.1.0/24"]

    record_allowed = MCPServiceRecord(id="srv_allow", name="Allowed", endpoint="http://192.168.1.10:8000", discovery_method="test")
    record_denied_subnet = MCPServiceRecord(id="srv_deny_sub", name="DeniedSubnet", endpoint="http://192.168.2.10:8000", discovery_method="test")
    record_denied_external = MCPServiceRecord(id="srv_deny_ext", name="DeniedExternal", endpoint="http://10.0.0.1:8000", discovery_method="test")
    record_invalid_ip = MCPServiceRecord(id="srv_invalid", name="InvalidIP", endpoint="http://notanip:8000", discovery_method="test")

    assert discovery_service._is_service_allowed(record_allowed) is True
    assert discovery_service._is_service_allowed(record_denied_subnet) is False
    assert discovery_service._is_service_allowed(record_denied_external) is False
    assert discovery_service._is_service_allowed(record_invalid_ip) is False # Should fail parsing

    # Test with no filter (all allowed)
    app_config_mdns_enabled.discovery.allowed_networks = []
    assert discovery_service._is_service_allowed(record_denied_external) is True


# Test for SSDP (discover_servers_ssdp) would be similar if a mockable async SSDP client/protocol were used.
# For P1, SSDP in service is a no-op, so test might just confirm it runs and yields nothing.
@pytest.mark.asyncio
async def test_discover_servers_ssdp_runs_and_completes(discovery_service, app_config_mdns_enabled):
    app_config_mdns_enabled.discovery.enable_ssdp = True # Ensure it's enabled
    results = []
    async for service in discovery_service.discover_servers_ssdp(timeout=0.1):
        results.append(service)
    assert len(results) == 0 # Expecting no results from P0 skeleton

# More tests:
# - Clear cache functionality
# - Stop discovery (cancelling tasks) - requires more setup of running tasks.
# - Interaction of mDNS re-discovery with cache and TTL (partially covered in mDNS test logic)
# - Error handling within _process_mdns_service_info (e.g. if info.async_request fails)

# Need to import socket for AF_INET, AF_INET6 constants in MockAsyncServiceInfo
import socket
