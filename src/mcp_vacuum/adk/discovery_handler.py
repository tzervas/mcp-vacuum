"""Discovery event processor for handling service discovery events.

This module contains the DiscoveryEventProcessor class which is responsible for
processing discovery-related events from a queue in an asynchronous manner.
"""
from __future__ import annotations

import asyncio
from typing import Any, Dict, Optional
import structlog

from .discovery_agent import DiscoveredServerEvent


class DiscoveryEventProcessor:
    """Handles processing of discovery events from a dedicated queue.
    
    This processor is responsible for consuming and processing discovery events
    in an asynchronous manner, with start/stop control over the processing loop.
    
    Attributes:
        queue: Queue containing discovery events to process
        running: Boolean flag indicating if the processor is running
        dependencies: Additional dependencies needed for processing events
    """

    def __init__(
        self, 
        queue: asyncio.Queue,
        auth_agent: Any,  # AuthenticationAgent
        discovered_servers_info: Dict[str, Any],
        logger: Optional[structlog.BoundLogger] = None,
        **dependencies: Any
    ) -> None:
        """Initialize the DiscoveryEventProcessor.
        
        Args:
            queue: Queue containing discovery events to process
            auth_agent: Reference to the authentication agent for delegating auth
            discovered_servers_info: Dict to track discovered server information
            logger: Optional logger instance
            **dependencies: Additional dependencies required for processing
        """
        self.queue = queue
        self.auth_agent = auth_agent
        self.discovered_servers_info = discovered_servers_info
        self.logger = logger or structlog.get_logger(__name__)
        self.dependencies = dependencies
        
        self._stop_event = asyncio.Event()
        self._processor_task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        """Start processing discovery events from the queue."""
        self.logger.info("Discovery event processor starting...")
        self._stop_event.clear()
        if not self._processor_task or self._processor_task.done():
            self._processor_task = asyncio.create_task(self._process_discovery_events())

    async def stop(self) -> None:
        """Stop processing discovery events."""
        if self._processor_task:
            self.logger.info("Discovery event processor stopping...")
            self._stop_event.set()
            try:
                await self._processor_task
            except asyncio.CancelledError:
                pass
            self._processor_task = None
            self.logger.info("Discovery event processor stopped.")

    async def _process_discovery_events(self) -> None:
        """Main processing loop for discovery events.
        
        Continuously processes events from the queue while running flag is True.
        Each event is processed according to discovery event handling logic.
        """
        self.logger.info("Discovery event processor started.")
        
        while not self._stop_event.is_set():
            try:
                event = await asyncio.wait_for(self.queue.get(), timeout=1.0)
                
                if isinstance(event, DiscoveredServerEvent):
                    log = self.logger.bind(
                        server_id=event.server_info.id,
                        server_name=event.server_info.name
                    )
                    log.info("Received DiscoveredServerEvent.")
                    self.discovered_servers_info[event.server_info.id] = event.server_info

                    if self.auth_agent:
                        # Command AuthAgent to authenticate this server
                        log.debug("Requesting authentication for discovered server.")
                        await self.auth_agent.authenticate_server_command(event.server_info)
                    else:
                        log.error("AuthAgent not available to process discovered server.")
                else:
                    self.logger.warning(
                        "Received unknown event on discovery_event_queue",
                        event_type=type(event).__name__
                    )
                    
                self.queue.task_done()
                
            except asyncio.TimeoutError:
                continue  # Allow checking self._stop_event
            except asyncio.CancelledError:
                self.logger.info("Discovery event processor cancelled.")
                break
            except Exception as e:
                self.logger.exception("Error in discovery event processor", error=str(e))
