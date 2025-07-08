"""Schema conversion event processor for handling tool schema conversion events.

This module contains the ConversionEventProcessor class which is responsible for
processing schema conversion events from a queue in an asynchronous manner.
"""
from __future__ import annotations

import asyncio
from typing import Any, Dict, Optional
import structlog

from .conversion_agent import SchemaConversionResultEvent


class ConversionEventProcessor:
    """Handles processing of schema conversion events from a dedicated queue.
    
    This processor is responsible for consuming and processing schema conversion events
    in an asynchronous manner, with start/stop control over the processing loop.
    
    Attributes:
        queue: Queue containing schema conversion events to process
        running: Boolean flag indicating if the processor is running
        dependencies: Additional dependencies needed for processing events
    """

    def __init__(
        self,
        queue: asyncio.Queue,
        server_kagent_schemas: Dict[str, Any],
        logger: Optional[structlog.BoundLogger] = None,
        **dependencies: Any
    ) -> None:
        """Initialize the ConversionEventProcessor.
        
        Args:
            queue: Queue containing schema conversion events to process
            server_kagent_schemas: Dict to store converted schemas by server ID
            logger: Optional logger instance
            **dependencies: Additional dependencies required for processing
        """
        self.queue = queue
        self.server_kagent_schemas = server_kagent_schemas
        self.logger = logger or structlog.get_logger(__name__)
        self.dependencies = dependencies
        
        self._stop_event = asyncio.Event()
        self._processor_task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        """Start processing schema conversion events from the queue."""
        self.logger.info("Schema conversion event processor starting...")
        self._stop_event.clear()
        if not self._processor_task or self._processor_task.done():
            self._processor_task = asyncio.create_task(self._process_conversion_events())

    async def stop(self) -> None:
        """Stop processing schema conversion events."""
        if self._processor_task:
            self.logger.info("Schema conversion event processor stopping...")
            self._stop_event.set()
            try:
                await self._processor_task
            except asyncio.CancelledError:
                pass
            self._processor_task = None
            self.logger.info("Schema conversion event processor stopped.")

    async def _process_conversion_events(self) -> None:
        """Main processing loop for schema conversion events.
        
        Continuously processes events from the queue while running flag is True.
        Each event is processed according to schema conversion event handling logic.
        """
        self.logger.info("Schema conversion event processor started.")
        
        while not self._stop_event.is_set():
            try:
                event = await asyncio.wait_for(self.queue.get(), timeout=1.0)
                
                if isinstance(event, SchemaConversionResultEvent):
                    log = self.logger.bind(
                        server_id=event.server_id,
                        success=event.success
                    )
                    log.info("Received SchemaConversionResultEvent.")
                    
                    if event.success and event.kagent_tools_schemas:
                        self.server_kagent_schemas[event.server_id] = event.kagent_tools_schemas
                        log.debug("Schema conversion successful and stored.",
                                num_schemas=len(event.kagent_tools_schemas))
                    else:
                        log.warning("Schema conversion failed or produced no schemas.")
                else:
                    self.logger.warning(
                        "Received unknown event on conversion_event_queue",
                        event_type=type(event).__name__
                    )
                    
                self.queue.task_done()
                
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                self.logger.info("Schema conversion event processor cancelled.")
                break
            except Exception as e:
                self.logger.exception("Error in schema conversion event processor", error=str(e))
