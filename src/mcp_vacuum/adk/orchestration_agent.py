"""
OrchestrationAgent: Manages the overall workflow of MCP server discovery,
authentication, and schema conversion by coordinating child agents.
"""
import asyncio
import logging as py_logging
from typing import Any

import structlog

from ..config import Config
from .auth_agent import AuthenticationAgent, AuthResultEvent
from .base import MCPVacuumBaseAgent
from .conversion_agent import ConversionAgent, SchemaConversionResultEvent

# Child agent types (to be created)
from .discovery_agent import DiscoveredServerEvent, DiscoveryAgent
from .mcp_client_agent import (
    MCPClientAgent,  # Manages communication with specific MCP servers
)

# Event/Data models for inter-agent communication (examples)
# These might be more formally defined Pydantic models.
# For now, using Dicts or simple classes.

class OrchestrationEvent: # Base class for events if using a custom event system
    pass

class StartDiscoveryCommand(OrchestrationEvent):
    def __init__(self, target_networks: list[str] | None = None):
        self.target_networks = target_networks

class ServerDiscoveredEvent(
    OrchestrationEvent
):  # This is defined in discovery_agent, re-used here for clarity
    pass  # Placeholder, actual event comes from discovery_agent

class AuthenticationRequest(
    OrchestrationEvent
):  # Example, might be a direct method call/command
    def __init__(
        self, server_id: str, server_info: dict[str, Any]
    ):  # server_info is MCPServerInfo model
        self.server_id = server_id
        self.server_info = server_info

class AuthenticationSuccessEvent(
    OrchestrationEvent
):  # This is AuthResultEvent from auth_agent
    pass  # Placeholder

class SchemaConversionRequest(
    OrchestrationEvent
):  # Example, might be a direct method call/command
    def __init__(
        self, server_id: str, mcp_tools_data: list[dict[str, Any]]
    ):  # mcp_tools_data is List[MCPTool]
        self.server_id = server_id
        self.mcp_tools_data = mcp_tools_data


class OrchestrationAgent(MCPVacuumBaseAgent):
    """
    The main coordinating agent in the MCP Vacuum system.
    Follows a hierarchical agent architecture.
    """

    def __init__(self, app_config: Config, **kwargs: Any):
        super().__init__(
            agent_name="OrchestrationAgent",
            app_config=app_config,
            parent_logger=None,  # No parent logger for the top agent
            **kwargs,
        )
        self._setup_global_logging()  # Orchestrator sets up logging for all

        # Child agents
        self.discovery_agent: DiscoveryAgent | None = None
        self.auth_agent: AuthenticationAgent | None = None
        self.conversion_agent: ConversionAgent | None = None
        self.mcp_client_agent: MCPClientAgent | None = None

        # State tracking
        # server_id -> MCPServerInfo model
        self.discovered_servers_info: dict[str, Any] = {}
        # server_id -> auth details (e.g. token or client_id)
        self.authenticated_server_details: dict[str, Any] = {}
        # server_id -> KagentTool schema (dict or model)
        self.server_kagent_schemas: dict[str, Any] = {}

        # Communication queues for event-driven inter-agent comms
        self.discovery_event_queue = asyncio.Queue()
        self.auth_event_queue = asyncio.Queue()
        self.conversion_event_queue = asyncio.Queue()

        self._stop_event = asyncio.Event() # For gracefully stopping processor loops
        self._processor_tasks: list[asyncio.Task] = []

        self.logger.info("OrchestrationAgent initialized.")

    def _setup_global_logging(self) -> None:
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
                (
                    structlog.dev.ConsoleRenderer(colors=True)
                    if self.app_config.logging.format.lower() == "console"
                    else structlog.processors.JSONRenderer(sort_keys=True)
                ),
            ],
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )
        self.logger = structlog.get_logger(self.__class__.__name__).bind(
            agent_name=self.agent_name
        )
        self.logger.info(
            "Global logging configured.",
            logging_level=self.app_config.logging.level,
            logging_format=self.app_config.logging.format,
        )

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
            # MCPClientAgent needs to get tokens from AuthAgent
            auth_agent_ref=self.auth_agent,
        )
        # Conversion Agent
        self.conversion_agent = ConversionAgent(
            app_config=self.app_config,
            parent_logger=self.logger,
            output_queue=self.conversion_event_queue
        )
        self.logger.info("Child agents initialized.")
        # ADK might have its own agent starting mechanism, e.g., await agent.start()
        # For now, assume they are ready after instantiation.

    async def _process_discovery_events(self):
        self.logger.info("Discovery event processor started.")
        while not self._stop_event.is_set():
            try:
                event = await asyncio.wait_for(
                    self.discovery_event_queue.get(), timeout=1.0
                )
                if isinstance(event, DiscoveredServerEvent):
                    log = self.logger.bind(
                        server_id=event.server_info.id,
                        server_name=event.server_info.name,
                    )
                    log.info("Received DiscoveredServerEvent.")
                    self.discovered_servers_info[
                        event.server_info.id
                    ] = event.server_info

                    if self.auth_agent:
                        # Command AuthAgent to authenticate this server
                        log.debug(
                            "Requesting authentication for discovered server."
                        )
                        await self.auth_agent.authenticate_server_command(
                            event.server_info
                        )
                    else:
                        log.error(
                            "AuthAgent not available to process discovered server."
                        )
                else:
                    log.warning(
                        "Received unknown event on discovery_event_queue",
                        event_type=type(event).__name__,
                    )
                self.discovery_event_queue.task_done()
            except TimeoutError:
                continue  # Allow checking self._stop_event
            except asyncio.CancelledError:
                self.logger.info("Discovery event processor cancelled.")
                break
            except Exception as e:
                self.logger.exception("Error in discovery event processor", error=str(e))

    async def _process_auth_events(self):
        self.logger.info("Authentication event processor started.")
        while not self._stop_event.is_set():
            try:
                event = await asyncio.wait_for(
                    self.auth_event_queue.get(), timeout=1.0
                )
                if isinstance(event, AuthResultEvent):
                    log = self.logger.bind(
                        server_id=event.server_id, success=event.success
                    )
                    log.info("Received AuthResultEvent.")
                    # auth_data could be client_id or token placeholder
                    if event.success and event.auth_data:
                        self.authenticated_server_details[
                            event.server_id
                        ] = event.auth_data
                        server_info = self.discovered_servers_info.get(
                            event.server_id
                        )
                        if (
                            server_info
                            and self.mcp_client_agent
                            and self.conversion_agent
                        ):
                            log.debug("Requesting tool list from MCPClientAgent.")
                            # MCPClientAgent fetches tools, then might directly
                            # trigger ConversionAgent or send another event
                            # back to Orchestrator.
                            # For simplicity, let's assume MCPClientAgent can
                            # call ConversionAgent or emit its own event.
                            # This part needs careful design of inter-agent
                            # communication flow.
                            # Option 1: Orchestrator tells MCPClientAgent, gets
                            # tools, then tells ConversionAgent
                            # Option 2: MCPClientAgent directly tells
                            # ConversionAgent after getting tools
                            # Option 3: MCPClientAgent emits "ToolsFetchedEvent",
                            # Orchestrator handles it.

                            # Let's go with Option 1 for more central control
                            # initially:
                            tools_list = (
                                await self.mcp_client_agent.get_tools_for_server(
                                    server_info
                                )
                            )
                            if tools_list:
                                log.debug(
                                    "Tools fetched, requesting schema conversion.",
                                    num_tools=len(tools_list),
                                )
                                await self.conversion_agent.convert_schemas_command(
                                    server_info, tools_list
                                )
                            else:
                                log.warning(
                                    "No tools fetched for authenticated server."
                                )
                        else:
                            if not server_info:
                                log.warning(
                                    "Server info not found for authenticated server."
                                )
                            if not self.mcp_client_agent:
                                log.error("MCPClientAgent not available.")
                            if not self.conversion_agent:
                                log.error("ConversionAgent not available.")
                    else:
                        # Remove if auth failed
                        self.authenticated_server_details.pop(event.server_id, None)
                else:
                    log.warning(
                        "Received unknown event on auth_event_queue",
                        event_type=type(event).__name__,
                    )
                self.auth_event_queue.task_done()
            except TimeoutError:
                continue
            except asyncio.CancelledError:
                self.logger.info("Authentication event processor cancelled.")
                break
            except Exception as e:
                self.logger.exception("Error in authentication event processor", error=str(e))

    async def _process_conversion_events(self):
        self.logger.info("Schema conversion event processor started.")
        while not self._stop_event.is_set():
            try:
                event = await asyncio.wait_for(
                    self.conversion_event_queue.get(), timeout=1.0
                )
                if isinstance(event, SchemaConversionResultEvent):
                    log = self.logger.bind(
                        server_id=event.server_id, success=event.success
                    )
                    log.info("Received SchemaConversionResultEvent.")
                    if event.success and event.kagent_tools_schemas:
                        self.server_kagent_schemas[
                            event.server_id
                        ] = event.kagent_tools_schemas
                    # Handle failure if necessary
                else:
                    log.warning(
                        "Received unknown event on conversion_event_queue",
                        event_type=type(event).__name__,
                    )
                self.conversion_event_queue.task_done()
            except TimeoutError:
                continue
            except asyncio.CancelledError:
                self.logger.info("Schema conversion event processor cancelled.")
                break
            except Exception as e:
                self.logger.exception("Error in schema conversion event processor", error=str(e))

    async def run_main_workflow(self, target_networks: list[str] | None = None) -> dict[str, Any]:
        self.logger.info("Starting main MCP Vacuum workflow (ADK Orchestration).")
        self._stop_event.clear()

        await self._initialize_child_agents()

        self._processor_tasks = [
            asyncio.create_task(self._process_discovery_events()),
            asyncio.create_task(self._process_auth_events()),
            asyncio.create_task(self._process_conversion_events()),
        ]

        if self.discovery_agent:
            self.logger.info(
                "Sending initial discovery command.",
                target_networks=target_networks,
            )
            await self.discovery_agent.discover_servers_command(target_networks)
        else:
            self.logger.error(
                "DiscoveryAgent not initialized. Workflow cannot start."
            )
            return {}

        # This is a simplified completion check.
        # A robust system would monitor agent states or specific completion events.
        # For example, wait for all initial discovery tasks to be processed,
        # then for all resulting auth tasks, then all conversion tasks.
        # Or, have a timeout for the entire operation.

        # --- Main Workflow Phases ---

        # 1. Discovery Phase
        # Discovery agent will run its methods (mDNS, SSDP) for a configured
        # duration.
        discovery_duration = self.app_config.discovery.timeout_seconds
        self.logger.info(
            f"Discovery phase started. Will run for {discovery_duration} seconds."
        )

        # Let discovery run for the specified duration.
        # The discovery_agent.discover_servers_command itself doesn't block
        # indefinitely here; it starts tasks within the DiscoveryAgent.
        await asyncio.sleep(discovery_duration)

        if self.discovery_agent:
            self.logger.info(
                "Discovery window elapsed. Stopping active discovery processes "
                "in DiscoveryAgent."
            )
            await self.discovery_agent.stop_current_discovery()
            # This should cause the discovery tasks in DiscoveryAgent to finish,
            # and no more items will be added to self.discovery_event_queue
            # by them.

        self.logger.info(
            "Waiting for all queued DiscoveredServerEvents to be processed..."
        )
        await self.discovery_event_queue.join()
        self.logger.info(
            "Initial discovery phase complete: all found servers processed by "
            "orchestrator."
        )

        # 2. Authentication Phase
        # All authentication requests triggered by the above discovery events
        # should now be in auth_event_queue (or processed).
        self.logger.info("Waiting for all authentication tasks to complete...")
        await self.auth_event_queue.join()
        self.logger.info(
            "Authentication phase complete: all triggered authentications processed."
        )

        # 3. Schema Conversion Phase
        # All conversion requests triggered by successful authentications should
        # now be in conversion_event_queue (or processed).
        self.logger.info(
            "Waiting for all schema conversion tasks to complete..."
        )
        await self.conversion_event_queue.join()
        self.logger.info(
            "Schema conversion phase complete: all triggered conversions processed."
        )

        self.logger.info(
            "All main workflow phases (discovery, auth, conversion) are complete."
        )

        # Stop the orchestrator's own event processor loops.
        await self.stop_workflow_processing()

        final_summary = self.get_summary()
        self.logger.info("Orchestration workflow finished.", **final_summary)
        return self.server_kagent_schemas

    async def stop_workflow_processing(self):
        self.logger.info("Stopping event processors...")
        self._stop_event.set()
        for task in self._processor_tasks:
            if not task.done():
                try:
                    task.cancel()
                    await task
                except asyncio.CancelledError:
                    self.logger.debug("Processor task cancelled successfully.")
                except Exception as e:
                    self.logger.error(
                        "Error cancelling processor task",
                        task_name=task.get_name(),
                        error=str(e),
                    )
        self._processor_tasks = []
        self.logger.info("Event processors stopped.")

    def get_summary(self) -> dict[str, int]:
        return {
            "discovered_servers": len(self.discovered_servers_info),
            "authenticated_servers": len(self.authenticated_server_details),
            "schemas_generated": len(self.server_kagent_schemas),
        }

    async def start(self) -> None: # ADK lifecycle method
        await super().start()
        # If OrchestrationAgent is meant to run continuously or manage a
        # long-lived process:
        # await self.run_main_workflow() # Or trigger it via an external command/event
        # For now, assume run_main_workflow is called explicitly.
        self.logger.info("OrchestrationAgent started (ADK lifecycle).")

    async def stop(self) -> None:  # ADK lifecycle method
        self.logger.info("OrchestrationAgent stopping (ADK lifecycle)...")
        await self.stop_workflow_processing()  # Ensure our loops are stopped

        # Stop child agents if they have an ADK stop method
        child_agents = [
            self.discovery_agent,
            self.auth_agent,
            self.conversion_agent,
            self.mcp_client_agent,
        ]
        for agent in child_agents:
            if agent and hasattr(agent, "stop") and asyncio.iscoroutinefunction(
                agent.stop
            ):
                try:
                    await agent.stop()
                except Exception as e:
                    self.logger.error(
                        f"Error stopping child agent {type(agent).__name__}",
                        error=str(e),
                    )

        await super().stop()
        self.logger.info("OrchestrationAgent stopped (ADK lifecycle).")

# This file would replace the old `src/mcp_vacuum/agent.py`.
# The child agent classes (DiscoveryAgent, AuthenticationAgent, ConversionAgent,
# MCPClientAgent) and their specific event/command models (DiscoveredServerEvent,
# AuthResultEvent, etc.) still need to be created in separate files within the
# `adk` package.
