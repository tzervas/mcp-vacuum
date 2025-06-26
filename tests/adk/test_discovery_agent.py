"""
Unit tests for DiscoveryAgent.
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from mcp_vacuum.config import Config, DiscoveryConfig
from mcp_vacuum.adk.discovery_agent import DiscoveryAgent, DiscoveredServerEvent
from mcp_vacuum.discovery.discovery_service import MCPDiscoveryService # To mock its methods
from mcp_vacuum.models.mcp import MCPServiceRecord
from mcp_vacuum.models.common import TransportType

@pytest.fixture
def app_config_adk():
    # Basic config for agent tests
    return Config(discovery=DiscoveryConfig(enable_mdns=True, enable_ssdp=False)) # MDNS on, SSDP off for specific test cases

@pytest.fixture
def mock_parent_logger():
    return MagicMock(spec=structlog.BoundLogger) # Using MagicMock for simplicity

@pytest.fixture
def output_queue():
    return asyncio.Queue()

@pytest.fixture
def mock_discovery_service():
    service = AsyncMock(spec=MCPDiscoveryService)
    # Setup default async generator behavior for discovery methods
    async def mock_discover_mdns(*args, **kwargs):
        yield # Default: yields nothing
    async def mock_discover_ssdp(*args, **kwargs):
        yield # Default: yields nothing

    service.discover_servers_mdns = AsyncMock(side_effect=mock_discover_mdns)
    service.discover_servers_ssdp = AsyncMock(side_effect=mock_discover_ssdp)
    service.stop_discovery = AsyncMock()
    return service

@pytest.fixture
@patch('mcp_vacuum.adk.discovery_agent.MCPDiscoveryService') # Patch where it's instantiated
def discovery_agent(MockDiscoveryServiceCls, app_config_adk, mock_parent_logger, output_queue, mock_discovery_service):
    MockDiscoveryServiceCls.return_value = mock_discovery_service # Ensure our mock instance is used
    agent = DiscoveryAgent(
        app_config=app_config_adk,
        parent_logger=mock_parent_logger,
        output_queue=output_queue
    )
    return agent

@pytest.mark.asyncio
async def test_discovery_agent_init(discovery_agent, mock_discovery_service):
    """Test DiscoveryAgent initialization."""
    assert discovery_agent.discovery_service == mock_discovery_service
    assert discovery_agent.app_config is not None
    assert discovery_agent.output_queue is not None
    discovery_agent.logger.info.assert_called_with("DiscoveryAgent initialized.") # From base or agent init

@pytest.mark.asyncio
async def test_discover_servers_command_mdns_only(discovery_agent, mock_discovery_service, app_config_adk):
    """Test discover_servers_command when only mDNS is enabled."""
    app_config_adk.discovery.enable_mdns = True
    app_config_adk.discovery.enable_ssdp = False # Explicitly disable SSDP for this test

    await discovery_agent.discover_servers_command()

    # Check that _run_mdns_discovery was scheduled (indirectly via create_task)
    # and _run_ssdp_discovery was not.
    # We can check if the service methods were called.
    # The agent creates tasks, so direct call count on _run_mdns_discovery is hard.
    # Instead, check if the underlying service's discover_servers_mdns was awaited.

    # This requires careful mocking of how tasks are created and awaited or checking calls on service.
    # For now, let's assume the tasks are created. The actual test of yielding is separate.
    assert len(discovery_agent._discovery_tasks) == 1
    # To verify which one: could check task names if set, or mock create_task.
    # Or, more simply, check which service methods are eventually called by those tasks.

    # To test if the correct discovery method on the service is triggered by the task:
    # We need to let the event loop run briefly for the task to start.
    await asyncio.sleep(0.01) # Allow tasks to start
    mock_discovery_service.discover_servers_mdns.assert_called_once()
    mock_discovery_service.discover_servers_ssdp.assert_not_called()

    await discovery_agent.stop_current_discovery() # Cleanup tasks

@pytest.mark.asyncio
async def test_run_mdns_discovery_yields_event(discovery_agent, mock_discovery_service, output_queue):
    """Test _run_mdns_discovery gets a service and puts event on queue."""
    sample_record = MCPServiceRecord(id="mdns1", name="MDNSService", endpoint="http://localhost:1234", transport_type=TransportType.HTTP, discovery_method="mdns")

    # Configure mock service to yield this record
    async def specific_mdns_discover(*args, **kwargs):
        yield sample_record
    mock_discovery_service.discover_servers_mdns.side_effect = specific_mdns_discover

    # Run the discovery method (which is usually started as a task)
    # We need to manage its lifecycle for the test if it's a long-running task.
    mdns_task = asyncio.create_task(discovery_agent._run_mdns_discovery())

    try:
        event = await asyncio.wait_for(output_queue.get(), timeout=1.0)
        assert isinstance(event, DiscoveredServerEvent)
        assert event.server_info == sample_record
        output_queue.task_done()
    finally:
        mdns_task.cancel() # Ensure task is cleaned up
        with pytest.raises(asyncio.CancelledError): # Expected
            await mdns_task


@pytest.mark.asyncio
async def test_discover_servers_command_no_methods_enabled(discovery_agent, app_config_adk, mock_discovery_service):
    """Test command when no discovery methods are enabled."""
    app_config_adk.discovery.enable_mdns = False
    app_config_adk.discovery.enable_ssdp = False

    await discovery_agent.discover_servers_command()

    assert len(discovery_agent._discovery_tasks) == 0
    mock_discovery_service.discover_servers_mdns.assert_not_called()
    mock_discovery_service.discover_servers_ssdp.assert_not_called()
    # Check for logged warning (requires log capture setup)
    # discovery_agent.logger.warning.assert_called_with("No discovery methods are enabled. No discovery will run.")


@pytest.mark.asyncio
async def test_stop_current_discovery(discovery_agent, mock_discovery_service):
    """Test stopping ongoing discovery tasks."""
    # Simulate tasks being created
    task1 = AsyncMock(spec=asyncio.Task)
    task1.done.return_value = False
    task2 = AsyncMock(spec=asyncio.Task)
    task2.done.return_value = False
    discovery_agent._discovery_tasks = [task1, task2]

    await discovery_agent.stop_current_discovery()

    task1.cancel.assert_called_once()
    task2.cancel.assert_called_once()
    assert len(discovery_agent._discovery_tasks) == 0
    mock_discovery_service.stop_discovery.assert_called_once()


# ADK lifecycle methods (start, stop) are simple calls to super and specific cleanup.
@pytest.mark.asyncio
async def test_discovery_agent_start_stop_lifecycle(discovery_agent, mock_parent_logger):
    """Test ADK start and stop lifecycle methods."""
    # Mock super().start() and super().stop() if they are stateful or have side effects
    with patch.object(MCPVacuumBaseAgent, 'start', new_callable=AsyncMock) as mock_super_start, \
         patch.object(MCPVacuumBaseAgent, 'stop', new_callable=AsyncMock) as mock_super_stop:

        await discovery_agent.start()
        mock_super_start.assert_called_once()
        discovery_agent.logger.info.assert_any_call("DiscoveryAgent started (ADK lifecycle).")

        # Simulate some tasks to test stop cleanup
        mock_task = AsyncMock(spec=asyncio.Task); mock_task.done.return_value = False
        discovery_agent._discovery_tasks = [mock_task]

        await discovery_agent.stop()
        mock_super_stop.assert_called_once()
        mock_task.cancel.assert_called_once() # From stop_current_discovery
        discovery_agent.logger.info.assert_any_call("DiscoveryAgent stopping (ADK lifecycle)...")
        discovery_agent.logger.info.assert_any_call("DiscoveryAgent stopped (ADK lifecycle).")

from mcp_vacuum.adk.base import MCPVacuumBaseAgent # Ensure this is available for patching super
import structlog # For spec of mock_parent_logger
import socket # For socket.AF_INET in discovery_service via config if it were more detailed. Not directly here.
