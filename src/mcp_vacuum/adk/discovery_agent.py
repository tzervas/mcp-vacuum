"""
DiscoveryAgent: Responsible for discovering MCP servers on the network.
"""
import asyncio
from typing import List, Optional, Any
import structlog

from ..config import Config
from .base import MCPVacuumBaseAgent # Corrected path
from ..discovery.discovery_service import MCPDiscoveryService
from ..models.mcp import MCPServiceRecord # For the event payload

# Define an event model for discovered servers
class DiscoveredServerEvent:
    def __init__(self, server_info: MCPServiceRecord):
        self.server_info = server_info # This is the MCPServerInfo model from Pydantic

    def __repr__(self):
        return f"<DiscoveredServerEvent server_name='{self.server_info.name}' id='{self.server_info.id}'>"

class DiscoveryAgent(MCPVacuumBaseAgent):
    """
    ADK Agent that wraps MCPDiscoveryService to find servers and emit events.
    """

    def __init__(self, app_config: Config, parent_logger: structlog.BoundLogger, output_queue: asyncio.Queue):
        super().__init__(agent_name="DiscoveryAgent", app_config=app_config, parent_logger=parent_logger)
        self.discovery_service = MCPDiscoveryService(app_config=app_config)
        self.output_queue = output_queue # Queue to send DiscoveredServerEvent to Orchestrator
        self._discovery_tasks: List[asyncio.Task] = []
        self.logger.info("DiscoveryAgent initialized.")

    async def discover_servers_command(self, target_networks: Optional[List[str]] = None):
        """
        Command to start server discovery.
        This method is called by the OrchestrationAgent.
        `target_networks` is currently not used by mDNS/SSDP implementations in MCPDiscoveryService,
        but kept for future use (e.g. targeted scans, ARP).
        """
        self.logger.info("Received command to discover servers.", target_networks=target_networks)

        # Allow overlapping discovery operations by not stopping current discovery tasks.
        # Each discovery command will start new discovery tasks and track them.

        # mDNS Discovery Task
        if self.app_config.discovery.enable_mdns:
            mdns_task = asyncio.create_task(self._run_mdns_discovery())
            self._discovery_tasks.append(mdns_task)
            self.logger.debug("mDNS discovery task created.")

        # SSDP Discovery Task (currently a no-op in service, but structure is here)
        if self.app_config.discovery.enable_ssdp:
            ssdp_task = asyncio.create_task(self._run_ssdp_discovery())
            self._discovery_tasks.append(ssdp_task)
            self.logger.debug("SSDP discovery task created.")

        # Optionally, wait for tasks here or let them run in background and emit events.
        # The orchestrator will listen on the output_queue.
        if not self._discovery_tasks:
            self.logger.warning("No discovery methods are enabled. No discovery will run.")
            # Potentially emit a "discovery_complete" or similar event if needed.

    async def _run_mdns_discovery(self):
        self.logger.info("Starting mDNS discovery loop.")
        try:
            async for server_record in self.discovery_service.discover_servers_mdns():
                self.logger.info("mDNS discovered server", server_name=server_record.name, server_id=server_record.id)
                event = DiscoveredServerEvent(server_info=server_record)
                await self.output_queue.put(event)
            self.logger.info("mDNS discovery loop finished.")
        except asyncio.CancelledError:
            self.logger.info("mDNS discovery task was cancelled.")
        except Exception as e:
            self.logger.exception("Error during mDNS discovery", error=str(e))
        finally:
            self.logger.debug("mDNS discovery task ended.")


    async def _run_ssdp_discovery(self):
        self.logger.info("Starting SSDP discovery loop.")
        try:
            async for server_record in self.discovery_service.discover_servers_ssdp():
                self.logger.info("SSDP discovered server", server_name=server_record.name, server_id=server_record.id)
                event = DiscoveredServerEvent(server_info=server_record)
                await self.output_queue.put(event)
            self.logger.info("SSDP discovery loop finished (or was a no-op).")
        except asyncio.CancelledError:
            self.logger.info("SSDP discovery task was cancelled.")
        except Exception as e:
            self.logger.exception("Error during SSDP discovery", error=str(e))
        finally:
            self.logger.debug("SSDP discovery task ended.")

    async def stop_current_discovery(self):
        """Stops all current discovery tasks."""
        if not self._discovery_tasks:
            return

        self.logger.info("Stopping current discovery tasks.", count=len(self._discovery_tasks))
        for task in self._discovery_tasks:
            if not task.done():
                task.cancel()

        results = await asyncio.gather(*self._discovery_tasks, return_exceptions=True)
        for i, result in enumerate(results):
            if isinstance(result, Exception) and not isinstance(result, asyncio.CancelledError) :
                self.logger.error("Exception in discovery task during stop", task_index=i, error=str(result))

        self._discovery_tasks = []
        # Also tell the service to stop its internal processes if any
        await self.discovery_service.stop_discovery()
        self.logger.info("Current discovery tasks stopped and cleared.")

    async def start(self) -> None: # ADK lifecycle
        await super().start()
        # DiscoveryAgent might not need to do anything on start unless commanded.
        # Or it could start a default discovery if configured.
        self.logger.info("DiscoveryAgent started (ADK lifecycle).")

    async def stop(self) -> None: # ADK lifecycle
        self.logger.info("DiscoveryAgent stopping (ADK lifecycle)...")
        await self.stop_current_discovery()
        await super().stop()
        self.logger.info("DiscoveryAgent stopped (ADK lifecycle).")

# Note: The `target_networks` parameter in `discover_servers_command` is not yet fully utilized
# by the underlying `MCPDiscoveryService`'s mDNS/SSDP methods, which are typically broadcast/multicast based.
# It would be more relevant for future direct scanning or ARP features.
# The agent uses an `output_queue` to send `DiscoveredServerEvent` objects to its parent (OrchestrationAgent).
# Error handling within the discovery loops ensures the agent doesn't crash on single discovery errors.
# The ADK `start` and `stop` methods are implemented.
# Corrected import path for MCPVacuumBaseAgent.
