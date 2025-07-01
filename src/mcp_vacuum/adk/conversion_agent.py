"""
ConversionAgent: Handles schema conversion from MCP format to Kagent format.
"""
import asyncio
from typing import List, Optional, Any, Dict
import structlog

from ..config import Config
from ..adk.base import MCPVacuumBaseAgent
from ..models.mcp import MCPServerInfo, MCPTool # Input types
from ..models.kagent import KagentTool # Output type
from ..schema_gen.schema_converter_service import SchemaConverterService # To be created

# Define an event model for schema conversion results
class SchemaConversionResultEvent:
    def __init__(self, server_id: str, success: bool, kagent_tools_schemas: Optional[List[KagentTool]] = None, original_tool_count: Optional[int] = 0, error_message: Optional[str] = None):
        self.server_id = server_id
        self.success = success
        self.kagent_tools_schemas = kagent_tools_schemas # List of converted KagentTool models
        self.original_tool_count = original_tool_count
        self.error_message = error_message

    def __repr__(self):
        return f"<SchemaConversionResultEvent server_id='{self.server_id}' success={self.success} num_schemas={len(self.kagent_tools_schemas) if self.kagent_tools_schemas else 0}>"


class ConversionAgent(MCPVacuumBaseAgent):
    """
    ADK Agent responsible for converting MCP tool schemas to Kagent CRD format.
    """

    def __init__(self, app_config: Config, parent_logger: structlog.BoundLogger, output_queue: asyncio.Queue):
        super().__init__(agent_name="ConversionAgent", app_config=app_config, parent_logger=parent_logger)
        self.converter_service = SchemaConverterService(app_config=app_config) # Service doing the actual work
        self.output_queue = output_queue # Queue to send SchemaConversionResultEvent to Orchestrator
        
        # Safe retrieval of fail_fast_conversion setting with bool type checking
        fail_fast = getattr(app_config.agent_settings, "fail_fast_conversion", False)
        self.fail_fast_conversion = isinstance(fail_fast, bool) and fail_fast
        
        self.logger.info("ConversionAgent initialized.", fail_fast_conversion=self.fail_fast_conversion)
        # self._conversion_tasks: Dict[str, asyncio.Task] = {} # server_id -> task, if managing ongoing conversions

    async def convert_schemas_command(self, server_info: MCPServerInfo, mcp_tools: List[MCPTool]):
        """
        Command to convert a list of MCPTools for a given server.
        Called by OrchestrationAgent after tools are fetched for an authenticated server.
        """
        log = self.logger.bind(server_id=server_info.id, server_name=server_info.name, num_tools=len(mcp_tools))
        log.info("Received command to convert schemas.")

        if not mcp_tools:
            log.warning("No MCP tools provided for conversion.")
            event = SchemaConversionResultEvent(server_id=server_info.id, success=True, kagent_tools_schemas=[], original_tool_count=0)
            await self.output_queue.put(event)
            return

        converted_kagent_tools: List[KagentTool] = []
        conversion_errors: List[str] = []
        # success_overall = True # Removed

        try:
            # The SchemaConverterService might convert one tool at a time or a batch.
            # Assuming a method that takes all tools and returns all converted KagentTools or errors.
            # Or, iterate and call service per tool.

            # Example: Iterating and converting one by one
            for mcp_tool in mcp_tools:
                tool_log = log.bind(tool_name=mcp_tool.name)
                try:
                    # SchemaConverterService.convert_mcp_tool_to_kagent should return a KagentTool
                    # and potentially validation results.
                    kagent_tool_result = await self.converter_service.convert_mcp_tool_to_kagent(mcp_tool, server_info)

                    if kagent_tool_result and kagent_tool_result.kagent_tool: # Assuming result is an object with .kagent_tool and .validation_issues
                        converted_kagent_tools.append(kagent_tool_result.kagent_tool)
                        if kagent_tool_result.validation_issues and any(i.severity == "error" for i in kagent_tool_result.validation_issues):
                            tool_log.warning("Conversion succeeded with validation errors.", issues=[i.model_dump() for i in kagent_tool_result.validation_issues])
                            # Mark overall success based on policy, e.g. if any error, overall might not be success.
                        else:
                            tool_log.debug("Tool converted successfully.")
                    else:
                        # Conversion failed for this tool
                        tool_log.error("Failed to convert MCP tool to Kagent format.", error_details=kagent_tool_result.error_message if kagent_tool_result else "Unknown service error")
                        conversion_errors.append(f"Tool '{mcp_tool.name}': {kagent_tool_result.error_message if kagent_tool_result else 'Failed'}")
                        # success_overall = False # Removed
                except Exception as tool_e:
                    tool_log.exception("Unexpected error converting tool.", error=str(tool_e))
                    conversion_errors.append(f"Tool '{mcp_tool.name}': Unexpected error - {str(tool_e)}")
                    # success_overall = False # Removed

            if not conversion_errors:
                log.info("All tools converted successfully.")
            else:
                log.warning("Some tools failed conversion.", num_failed=len(conversion_errors), errors=conversion_errors)
                # success_overall might already be False # Comment no longer relevant

            final_error_message = "; ".join(conversion_errors) if conversion_errors else None
            event = SchemaConversionResultEvent(
                server_id=server_info.id,
                success=not conversion_errors, # Success if there are no entries in conversion_errors.
                kagent_tools_schemas=converted_kagent_tools,
                original_tool_count=len(mcp_tools),
                error_message=final_error_message
            )
            await self.output_queue.put(event)
            log.debug("SchemaConversionResultEvent emitted.", success=event.success, num_converted=len(converted_kagent_tools))

        except Exception as e:
            log.exception("Critical error during schema conversion process.", error=str(e))
            error_event = SchemaConversionResultEvent(
                server_id=server_info.id,
                success=False,
                kagent_tools_schemas=[],
                original_tool_count=len(mcp_tools),
                error_message=f"Overall conversion process failed: {str(e)}"
            )
            await self.output_queue.put(error_event)


    async def start(self) -> None: # ADK lifecycle
        await super().start()
        self.logger.info("ConversionAgent started (ADK lifecycle).")

    async def stop(self) -> None: # ADK lifecycle
        self.logger.info("ConversionAgent stopping (ADK lifecycle)...")
        # If there were any long-running conversion tasks, cancel them here.
        # For now, convert_schemas_command is assumed to be relatively short-lived per call.
        await super().stop()
        self.logger.info("ConversionAgent stopped (ADK lifecycle).")

# The SchemaConverterService class needs to be created in src/mcp_vacuum/schema_gen/schema_converter_service.py
# It will contain the actual logic from "Schema Conversion & Mapping Guide".
# The result from converter_service.convert_mcp_tool_to_kagent is assumed to be an object
# that contains the converted KagentTool and any validation issues or error messages.
# For example:
# class ConversionServiceResult:
#   kagent_tool: Optional[KagentTool]
#   validation_issues: List[ValidationIssue]
#   error_message: Optional[str]
# This agent is fairly simple: receives a command, uses a service, emits a result.
