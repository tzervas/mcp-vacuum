"""
OrchestrationAgent: Manages the overall workflow of MCP server discovery,
authentication, and schema conversion by coordinating child agents.
"""
from typing import Dict, List, Optional, Any
import asyncio
import structlog

from ..config import Config
from .auth_agent import AuthenticationAgent, AuthResultEvent
from .base import MCPVacuumBaseAgent
from .conversion_agent import ConversionAgent, SchemaConversionResultEvent

# Child agent types (to be created)
from .discovery_agent import DiscoveredServerEvent, DiscoveryAgent
from .mcp_client_agent import MCPClientAgent  # Manages communication with specific MCP servers

# Event processors
from .discovery_handler import DiscoveryEventProcessor
from .auth_handler import AuthEventProcessor
from .conversion_handler import ConversionEventProcessor

# Event/Data models for inter-agent communication (examples)
# These might be more formally defined Pydantic models.
# For now, using Dicts or simple classes.

class OrchestrationEvent: # Base class for events if using a custom event system
    pass

class StartDiscoveryCommand(OrchestrationEvent):
    def __init__(self, target_networks: Optional[List[str]] = None):
        self.target_networks = target_networks

class ServerDiscoveredEvent(OrchestrationEvent): # This is defined in discovery_agent, re-used here for clarity
    pass # Placeholder, actual event comes from discovery_agent

class AuthenticationRequest(OrchestrationEvent): # Example, might be a direct method call/command
    def __init__(self, server_id: str, server_info: Dict[str, Any]): # server_info is MCPServerInfo model
        self.server_id = server_id
        self.server_info = server_info

class AuthenticationSuccessEvent(OrchestrationEvent): # This is AuthResultEvent from auth_agent
    pass # Placeholder

class SchemaConversionRequest(OrchestrationEvent): # Example, might be a direct method call/command
    def __init__(self, server_id: str, mcp_tools_data: List[Dict[str, Any]]): # mcp_tools_data is List[MCPTool]
        self.server_id = server_id
        self.mcp_tools_data = mcp_tools_data


class OrchestrationAgent(MCPVacuumBaseAgent):
    """
    The main coordinating agent in the MCP Vacuum system.
    Follows a hierarchical agent architecture.
    """

    def __init__(self, app_config: Config, **kwargs: Any):
        super().__init__(agent_name="OrchestrationAgent", app_config=app_config, parent_logger=None, **kwargs) # No parent logger for the top agent
        self._setup_global_logging() # Orchestrator sets up logging for all

        # Child agents
        self.discovery_agent: Optional[DiscoveryAgent] = None
        self.auth_agent: Optional[AuthenticationAgent] = None
        self.conversion_agent: Optional[ConversionAgent] = None
        self.mcp_client_agent: Optional[MCPClientAgent] = None

        # State tracking
        self.discovered_servers_info: Dict[str, Any] = {} # server_id -> MCPServerInfo model
        self.authenticated_server_details: Dict[str, Any] = {} # server_id -> auth details (e.g. token or client_id)
        self.server_kagent_schemas: Dict[str, Any] = {} # server_id -> KagentTool schema (dict or model)

        # Communication queues for event-driven inter-agent comms
        self.discovery_event_queue = asyncio.Queue()
        self.auth_event_queue = asyncio.Queue()
        self.conversion_event_queue = asyncio.Queue()

        # Event processors
        self.discovery_processor: Optional[DiscoveryEventProcessor] = None
        self.auth_processor: Optional[AuthEventProcessor] = None
        self.conversion_processor: Optional[ConversionEventProcessor] = None

        self.logger.info("OrchestrationAgent initialized.")

    def _setup_global_logging(self) -> None:
        import logging as py_logging

        py_logging.basicConfig(
            level=getattr(py_logging, self.app_config.logging.level.upper()),
            format="%(message)s",
            force=True
        )

        structlog.configure(
            processors=[
                structlog.stdlib.add_log_level,
                structlog.stdlib.add_logger_name,
                structlog.processors.StackInfoRenderer(),
                structlog.dev.set_exc_info,
                structlog.processors.format_exc_info,
                structlog.processors.TimeStamper(fmt="iso", utc=True),
                structlog.dev.ConsoleRenderer(colors=True) if self.app_config.logging.format.lower() == "console"
                else structlog.processors.JSONRenderer(sort_keys=True)
            ],
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )
        self.logger = structlog.get_logger(self.__class__.__name__).bind(agent_name=self.agent_name)
        self.logger.info("Global logging configured.", logging_level=self.app_config.logging.level, logging_format=self.app_config.logging.format)

    async def _initialize_child_agents(self):
        self.logger.info("Initializing child agents...")

        # Discovery Agent
        self.discovery_agent = DiscoveryAgent(
            app_config=self.app_config,
            parent_logger=self.logger,
            output_queue=self.discovery_event_queue
        )
        # Authentication Agent
        self.auth_agent = AuthenticationAgent(
            app_config=self.app_config,
            parent_logger=self.logger,
            output_queue=self.auth_event_queue
            # TokenManager will be initialized inside AuthAgent
        )
        # MCP Client Agent (manages actual MCP server communication)
        self.mcp_client_agent = MCPClientAgent(
            app_config=self.app_config,
            parent_logger=self.logger,
            auth_agent_ref=self.auth_agent # MCPClientAgent needs to get tokens from AuthAgent
        )
        # Conversion Agent
        self.conversion_agent = ConversionAgent(
            app_config=self.app_config,
            parent_logger=self.logger,
            output_queue=self.conversion_event_queue
        )
        self.logger.info("Child agents initialized.")
        # Initialize event processors
        self.discovery_processor = DiscoveryEventProcessor(
            queue=self.discovery_event_queue,
            auth_agent=self.auth_agent,
            discovered_servers_info=self.discovered_servers_info,
            logger=self.logger
        )

        self.auth_processor = AuthEventProcessor(
            queue=self.auth_event_queue,
            mcp_client_agent=self.mcp_client_agent,
            conversion_agent=self.conversion_agent,
            discovered_servers_info=self.discovered_servers_info,
            authenticated_server_details=self.authenticated_server_details,
            logger=self.logger
        )

        self.conversion_processor = ConversionEventProcessor(
            queue=self.conversion_event_queue,
            server_kagent_schemas=self.server_kagent_schemas,
            logger=self.logger
        )

        # ADK might have its own agent starting mechanism, e.g., await agent.start()
        # For now, assume they are ready after instantiation.

    # Event processing has been moved to dedicated handler classes:
    # - DiscoveryEventProcessor in discovery_handler.py
    # - AuthEventProcessor in auth_handler.py
    # - ConversionEventProcessor in conversion_handler.py

    async def run_main_workflow(self, target_networks: Optional[List[str]] = None) -> Dict[str, Any]:
        self.logger.info("Starting main MCP Vacuum workflow (ADK Orchestration).")
        self._stop_event.clear()

        await self._initialize_child_agents()

        # Start event processors
        await self.discovery_processor.start()
        await self.auth_processor.start()
        await self.conversion_processor.start()

        if self.discovery_agent:
            self.logger.info("Sending initial discovery command.", target_networks=target_networks)
            await self.discovery_agent.discover_servers_command(target_networks)
        else:
            self.logger.error("DiscoveryAgent not initialized. Workflow cannot start.")
            return {}

        # This is a simplified completion check.
        # A robust system would monitor agent states or specific completion events.
        # For example, wait for all initial discovery tasks to be processed,
        # then for all resulting auth tasks, then all conversion tasks.
        # Or, have a timeout for the entire operation.

        # --- Main Workflow Phases ---

        # 1. Discovery Phase
        # Discovery agent will run its methods (mDNS, SSDP) for a configured duration.
        discovery_duration = self.app_config.discovery.timeout_seconds
        self.logger.info(f"Discovery phase started. Will run for {discovery_duration} seconds.")

        # Let discovery run for the specified duration.
        # The discovery_agent.discover_servers_command itself doesn't block indefinitely here;
        # it starts tasks within the DiscoveryAgent.
        await asyncio.sleep(discovery_duration)

        if self.discovery_agent:
            self.logger.info("Discovery window elapsed. Stopping active discovery processes in DiscoveryAgent.")
            await self.discovery_agent.stop_current_discovery()
            # This should cause the discovery tasks in DiscoveryAgent to finish,
            # and no more items will be added to self.discovery_event_queue by them.

        self.logger.info("Waiting for all queued DiscoveredServerEvents to be processed...")
        await self.discovery_event_queue.join()
        self.logger.info("Initial discovery phase complete: all found servers processed by orchestrator.")

        # 2. Authentication Phase
        # All authentication requests triggered by the above discovery events should now be in auth_event_queue (or processed).
        self.logger.info("Waiting for all authentication tasks to complete...")
        await self.auth_event_queue.join()
        self.logger.info("Authentication phase complete: all triggered authentications processed.")

        # 3. Schema Conversion Phase
        # All conversion requests triggered by successful authentications should now be in conversion_event_queue (or processed).
        self.logger.info("Waiting for all schema conversion tasks to complete...")
        await self.conversion_event_queue.join()
        self.logger.info("Schema conversion phase complete: all triggered conversions processed.")

        self.logger.info("All main workflow phases (discovery, auth, conversion) are complete.")

        # Stop the orchestrator's own event processor loops.
        await self.stop_workflow_processing()

        final_summary = self.get_summary()
        self.logger.info("Orchestration workflow finished.", **final_summary)
        return self.server_kagent_schemas

    async def stop_workflow_processing(self):
        self.logger.info("Stopping event processors...")
        self._stop_event.set()
        for _ in self._processor_tasks:
            # Stop all event processors
            if self.discovery_processor:
                await self.discovery_processor.stop()
            if self.auth_processor:
                await self.auth_processor.stop()
            if self.conversion_processor:
                await self.conversion_processor.stop()
        self.logger.info("Event processors stopped.")

    def get_summary(self) -> Dict[str, int]:
        return {
            "discovered_servers": len(self.discovered_servers_info),
            "authenticated_servers": len(self.authenticated_server_details),
            "schemas_generated": len(self.server_kagent_schemas),
        }

    async def start(self) -> None: # ADK lifecycle method
        await super().start()
        # If OrchestrationAgent is meant to run continuously or manage a long-lived process:
        # await self.run_main_workflow() # Or trigger it via an external command/event
        # For now, assume run_main_workflow is called explicitly.
        self.logger.info("OrchestrationAgent started (ADK lifecycle).")


    async def stop(self) -> None: # ADK lifecycle method
        self.logger.info("OrchestrationAgent stopping (ADK lifecycle)...")
        await self.stop_workflow_processing() # Ensure our loops are stopped

        # Stop child agents if they have an ADK stop method
        child_agents = [self.discovery_agent, self.auth_agent, self.conversion_agent, self.mcp_client_agent]
        for agent in child_agents:
            if agent and hasattr(agent, 'stop') and asyncio.iscoroutinefunction(agent.stop):
                try:
                    await agent.stop()
                except Exception as e:
                    self.logger.error(f"Error stopping child agent {type(agent).__name__}", error=str(e))

        await super().stop()
        self.logger.info("OrchestrationAgent stopped (ADK lifecycle).")

# This file would replace the old `src/mcp_vacuum/agent.py`.
# The child agent classes (DiscoveryAgent, AuthenticationAgent, ConversionAgent, MCPClientAgent)
# and their specific event/command models (DiscoveredServerEvent, AuthResultEvent, etc.)
# still need to be created in separate files within the `adk` package.
