"""
Base class for all MCP Vacuum agents using the Google ADK.
"""

from typing import Any, Dict, Optional
import structlog  # type: ignore[import-not-found]
from google_adk import BaseAgent  # type: ignore[import-not-found]

# Or: from adk import BaseAgent if adk is top-level
from ..config import Config


class MCPVacuumBaseAgent(BaseAgent):
    """
    Project-specific base agent providing common functionalities like
    configuration and logging.
    """

    def __init__(
        self,
        agent_name: str,
        app_config: Config,
        parent_logger: structlog.BoundLogger | None = None,
        **kwargs: Any,
    ):
        """
        Args:
            agent_name: A unique name for this agent instance.
            app_config: The global application configuration.
            parent_logger: Optional logger from a parent agent for hierarchical
                           logging.
            **kwargs: Additional arguments for the underlying ADK BaseAgent.
        """
        super().__init__(**kwargs)  # Pass ADK specific args if any
        self.agent_name = agent_name
        self.app_config = app_config

        if parent_logger:
            self.logger = parent_logger.bind(agent_name=self.agent_name)
        else:
            # Basic structlog setup if no parent logger (e.g., for OrchestrationAgent)
            # This might be redundant if OrchestrationAgent sets up global logging.
            # Consider a shared logging setup utility.
            # For now, assume OrchestrationAgent handles initial setup.
            self.logger = structlog.get_logger(
                self.__class__.__name__
            ).bind(agent_name=self.agent_name)

        self.logger.info("Agent initialized.")

    async def start(self) -> None:
        """
        Called when the agent is started.
        Child agents can override this to perform setup tasks.
        """
        self.logger.info("Agent starting.")
        await super().start()  # Call ADK BaseAgent's start if it has one

    async def stop(self) -> None:
        """
        Called when the agent is stopped.
        Child agents can override this to perform cleanup tasks.
        """
        self.logger.info("Agent stopping.")
        await super().stop()  # Call ADK BaseAgent's stop if it has one

    # Example of an event handling method (to be defined by ADK or custom event
    # system)
    # async def handle_event(self, event_name: str, data: Dict[str, Any]) -> None:
    #     self.logger.debug(
    #         "Received event",
    #         event_name=event_name,
    #         data_keys=list(data.keys()) if data else []
    #     )
    #     pass

    # Example of sending an event
    # async def send_event_to_parent(
    #     self, event_name: str, data: Dict[str, Any]
    # ) -> None:
    #     # Logic to send event to parent or event bus
    #     self.logger.debug("Sending event to parent", event_name=event_name)
    #     if hasattr(self, 'parent_agent_ref') and self.parent_agent_ref:
    #          await self.parent_agent_ref.handle_event(event_name, data)
    #     pass

    # async def send_event_to_child(
    #     self, child_name: str, event_name: str, data: Dict[str, Any]
    # ) -> None:
    #     # Logic to send event to a specific child
    #     pass


# Note: The actual methods like `start`, `stop`, `handle_event`, `send_event`
# will depend heavily on the Google ADK's API.
# This `MCPVacuumBaseAgent` is a placeholder for common structure.
# If ADK's `BaseAgent` already provides good logging/config patterns, this
# might be simpler.
# The `google_adk` import might need adjustment based on actual library
# structure. (e.g., `from adk.agent import BaseAgent` or similar)
# For now, `from google_adk import BaseAgent` is an assumption.
