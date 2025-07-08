"""Authentication event processor for handling server authentication events.

This module contains the AuthEventProcessor class which is responsible for
processing authentication-related events from a queue in an asynchronous manner.
"""
from __future__ import annotations

import asyncio
from typing import Any, Dict, Optional
from types import TracebackType
import structlog

from .auth_agent import AuthResultEvent
from ..models.common import ServerInfo


class AuthEventProcessor:
    """Handles processing of authentication events from a dedicated queue.
    
    This processor is responsible for consuming and processing authentication events
    in an asynchronous manner, with start/stop control over the processing loop.
    
    Attributes:
        queue: Queue containing authentication events to process
        running: Boolean flag indicating if the processor is running
        dependencies: Additional dependencies needed for processing events
    """

    def __init__(
        self,
        queue: asyncio.Queue,
        mcp_client_agent: Any,  # MCPClientAgent
        conversion_agent: Any,  # ConversionAgent
        discovered_servers_info: Dict[str, Any],
        authenticated_server_details: Dict[str, Any],
        logger: Optional[structlog.BoundLogger] = None,
        **dependencies: Any
    ) -> None:
        """Initialize the AuthEventProcessor.
        
        Args:
            queue: Queue containing authentication events to process
            mcp_client_agent: Reference to the MCP client agent
            conversion_agent: Reference to the conversion agent
            discovered_servers_info: Dict of discovered server information
            authenticated_server_details: Dict to track authenticated servers
            logger: Optional logger instance
            **dependencies: Additional dependencies required for processing
        """
        self.queue = queue
        self.mcp_client_agent = mcp_client_agent
        self.conversion_agent = conversion_agent
        self.discovered_servers_info = discovered_servers_info
        self.authenticated_server_details = authenticated_server_details
        self.logger = logger or structlog.get_logger(__name__)
        self.dependencies = dependencies
        
        self._stop_event = asyncio.Event()
        self._processor_task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        """Start processing authentication events from the queue."""
        self.logger.info("Authentication event processor starting...")
        self._stop_event.clear()
        if not self._processor_task or self._processor_task.done():
            self._processor_task = asyncio.create_task(self._process_auth_events())

    async def stop(self) -> None:
        """Stop processing authentication events."""
        if self._processor_task:
            self.logger.info("Authentication event processor stopping...")
            self._stop_event.set()
            try:
                await self._processor_task
            except asyncio.CancelledError:
                pass
            self._processor_task = None
            self.logger.info("Authentication event processor stopped.")

    async def _process_auth_events(self) -> None:
        """Main processing loop for authentication events.
        
        Processes events from the queue until stopped. Each event is handled
        according to the authentication event handling logic.
        """
        await self._start_processing()
        await self._process_events_until_stopped()

    async def _start_processing(self) -> None:
        """Initialize the event processing state."""
        self.logger.info("Authentication event processor started.")

    async def _process_events_until_stopped(self) -> None:
        """Process events in a loop until the stop event is set."""
        while not await self._should_stop():
            try:
                await self._process_single_event()
            except asyncio.CancelledError:
                await self._handle_cancellation()
                break
            except Exception as e:
                self._handle_processing_error(e)

    async def _should_stop(self) -> bool:
        """Check if processing should stop.

        Returns:
            bool: True if processing should stop, False otherwise.
        """
        return self._stop_event.is_set()

    async def _process_single_event(self) -> None:
        """Process a single event from the queue."""
        event = await self._get_next_event()
        if event is None:  # Timeout occurred
            return

        await self._handle_event(event)

    async def _handle_cancellation(self) -> None:
        """Handle cancellation of the event processor."""
        self.logger.info("Authentication event processor cancelled.")

    def _handle_processing_error(self, error: Exception) -> None:
        """Handle any processing errors that occur.

        Args:
            error: The exception that occurred during processing.
        """
        self.logger.exception(
            "Error in authentication event processor",
            error=str(error)
        )
    
    async def _get_next_event(self) -> Optional[Any]:
        """Get the next event from the queue with timeout.
        
        Returns:
            Optional[Any]: The event if one was received, None on timeout.
        """
        try:
            return await asyncio.wait_for(self.queue.get(), timeout=1.0)
        except asyncio.TimeoutError:
            return None
            
    async def _handle_event(self, event: Any) -> None:
        """Process a single authentication event.
        
        Args:
            event: The event to process.
        """
        if not isinstance(event, AuthResultEvent):
            self.logger.warning(
                "Received unknown event on auth_event_queue",
                event_type=type(event).__name__,
            )
            self.queue.task_done()
            return

        log = self.logger.bind(server_id=event.server_id, success=event.success)
        log.info("Received AuthResultEvent.")

        if event.success and event.auth_data:
            await self._handle_successful_auth(event, log)
        else:
            self.authenticated_server_details.pop(event.server_id, None)

        self.queue.task_done()

    async def _handle_successful_auth(self, event: AuthResultEvent, log: structlog.BoundLogger) -> None:
        self.authenticated_server_details[event.server_id] = event.auth_data

        if self._validate_agents(log, server_info := self.discovered_servers_info.get(event.server_id)):
            log.debug("Requesting tool list from MCPClientAgent.")
            tools_list = await self.mcp_client_agent.get_tools_for_server(server_info)

            if tools_list:
                log.debug("Tools fetched, requesting schema conversion.", num_tools=len(tools_list))
                await self.conversion_agent.convert_schemas_command(server_info, tools_list)
            else:
                log.warning("No tools fetched for authenticated server.")

    def _validate_agents(self, log: structlog.BoundLogger, server_info: Optional[ServerInfo]) -> bool:
        if not server_info:
            log.warning("Server info not found for authenticated server.")
            return False

        if not self.mcp_client_agent:
            log.error("MCPClientAgent not available.")
            return False

        if not self.conversion_agent:
            log.error("ConversionAgent not available.")
            return False

        return True
