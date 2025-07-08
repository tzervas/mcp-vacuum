"""
ConversionAgent: Handles schema conversion from MCP format to Kagent format.
"""
import asyncio

import structlog  # type: ignore[import-not-found]

from ..adk.base import MCPVacuumBaseAgent
from ..config import Config
from ..models.kagent import KagentTool  # Output type
from ..models.mcp import MCPServerInfo, MCPTool  # Input types
from ..schema_gen.schema_converter_service import (
    SchemaConverterService,  # To be created
)


# Define an event model for schema conversion results
class SchemaConversionResultEvent:
    def __init__(
        self,
        server_id: str,
        success: bool,
        kagent_tools_schemas: list[KagentTool] | None = None,
        original_tool_count: int | None = 0,
        error_message: str | None = None,
    ):
        self.server_id = server_id
        self.success = success
        # List of converted KagentTool models
        self.kagent_tools_schemas = kagent_tools_schemas
        self.original_tool_count = original_tool_count
        self.error_message = error_message

    def __repr__(self):
        num_schemas = (
            len(self.kagent_tools_schemas) if self.kagent_tools_schemas else 0
        )
        return (
            f"<SchemaConversionResultEvent server_id='{self.server_id}' "
            f"success={self.success} num_schemas={num_schemas}>"
        )


class ConversionAgent(MCPVacuumBaseAgent):
    """
    ADK Agent responsible for converting MCP tool schemas to Kagent CRD format.
    """
    def __init__(
        self,
        app_config: Config,
        parent_logger: structlog.BoundLogger,
        output_queue: asyncio.Queue,
    ):
        super().__init__(
            agent_name="ConversionAgent",
            app_config=app_config,
            parent_logger=parent_logger,
        )
        # Service doing the actual work
        self.converter_service = SchemaConverterService(app_config=app_config)
        # Queue to send SchemaConversionResultEvent to Orchestrator
        self.output_queue = output_queue
        
        # Safe retrieval of fail_fast_conversion setting with bool type checking
        fail_fast = getattr(app_config.agent_settings, "fail_fast_conversion", False)
        self.fail_fast_conversion = isinstance(fail_fast, bool) and fail_fast
        
        self.logger.info("ConversionAgent initialized.", fail_fast_conversion=self.fail_fast_conversion)
        # self._conversion_tasks: Dict[str, asyncio.Task] = {} # server_id -> task, if managing ongoing conversions

    async def convert_schemas_command(
        self,
        server_info: MCPServerInfo,
        mcp_tools: list[MCPTool],
        fail_fast: bool | None = None,
    ):
        """
        Command to convert a list of MCPTools for a given server.
        Called by OrchestrationAgent after tools are fetched for an authenticated
        server.
        Args:
            server_info: Information about the server whose tools are being converted.
            mcp_tools: The list of MCPTool objects to convert.
            fail_fast: If True, stops conversion on the first tool that fails.
                       Overrides instance-level fail_fast_conversion if provided.
        """
        current_fail_fast = (
            fail_fast if fail_fast is not None else self.fail_fast_conversion
        )
        log = self.logger.bind(
            server_id=server_info.id,
            server_name=server_info.name,
            num_tools=len(mcp_tools),
            fail_fast=current_fail_fast,
        )
        log.info("Received command to convert schemas.")

        if not mcp_tools:
            log.warning("No MCP tools provided for conversion.")
            event = SchemaConversionResultEvent(
                server_id=server_info.id,
                success=True,
                kagent_tools_schemas=[],
                original_tool_count=0,
            )
            await self.output_queue.put(event)
            return

        converted_kagent_tools: list[KagentTool] = []
        conversion_errors: list[str] = []

        try:
            # The SchemaConverterService might convert one tool at a time or a
            # batch. Assuming a method that takes all tools and returns all
            # converted KagentTools or errors.
            # Or, iterate and call service per tool.

            # Example: Iterating and converting one by one
            for mcp_tool in mcp_tools:
                tool_log = log.bind(tool_name=mcp_tool.name)
                try:
                    # SchemaConverterService.convert_mcp_tool_to_kagent should
                    # return a KagentTool and potentially validation results.
                    kagent_tool_result = (
                        await self.converter_service.convert_mcp_tool_to_kagent(
                            mcp_tool, server_info
                        )
                    )

                    if kagent_tool_result and kagent_tool_result.kagent_tool:
                        converted_kagent_tools.append(
                            kagent_tool_result.kagent_tool
                        )
                        if kagent_tool_result.validation_issues and any(
                            i.severity == "error"
                            for i in kagent_tool_result.validation_issues
                        ):
                            validation_error_details = [
                                i.model_dump()
                                for i in kagent_tool_result.validation_issues
                                if i.severity == "error"
                            ]
                            tool_log.warning(
                                "Conversion succeeded with validation errors.",
                                issues=validation_error_details,
                            )
                            conversion_errors.append(
                                f"Tool '{mcp_tool.name}': Succeeded with "
                                f"validation errors: {validation_error_details}"
                            )
                            if current_fail_fast:
                                log.warning(
                                    "Fail-fast enabled and validation errors "
                                    "occurred. Stopping conversion."
                                )
                                raise RuntimeError(
                                    f"Conversion failed for tool {mcp_tool.name} "
                                    f"due to validation errors: "
                                    f"{validation_error_details}"
                                )
                        else:
                            tool_log.debug("Tool converted successfully.")
                    else:
                        err_msg = (
                            kagent_tool_result.error_message
                            if kagent_tool_result
                            and kagent_tool_result.error_message
                            else "Unknown conversion service error"
                        )
                        tool_log.error(
                            "Failed to convert MCP tool to Kagent format.",
                            error_details=err_msg,
                        )
                        conversion_errors.append(
                            f"Tool '{mcp_tool.name}': {err_msg}"
                        )
                        if current_fail_fast:
                            log.warning(
                                "Fail-fast enabled and conversion error "
                                "occurred. Stopping conversion."
                            )
                            raise RuntimeError(
                                f"Conversion failed for tool {mcp_tool.name}: "
                                f"{err_msg}"
                            )
                except Exception as tool_e:
                    tool_log.exception(
                        "Unexpected error converting tool.", error=str(tool_e)
                    )
                    conversion_errors.append(
                        f"Tool '{mcp_tool.name}': Unexpected error - {tool_e!s}"
                    )
                    if current_fail_fast:
                        log.warning(
                            "Fail-fast enabled and unexpected error occurred "
                            "during tool conversion. Stopping conversion."
                        )
                        raise  # Re-raise the original exception to stop processing

            if not conversion_errors:
                log.info("All tools converted successfully.")
            else:
                log.warning(
                    "Some tools failed conversion.",
                    num_failed=len(conversion_errors),
                    errors=conversion_errors,
                )

            final_error_message = (
                "; ".join(conversion_errors) if conversion_errors else None
            )
            event = SchemaConversionResultEvent(
                server_id=server_info.id,
                success=not conversion_errors,  # Success if no conversion_errors
                kagent_tools_schemas=converted_kagent_tools,
                original_tool_count=len(mcp_tools),
                error_message=final_error_message,
            )
            await self.output_queue.put(event)
            log.debug(
                "SchemaConversionResultEvent emitted.",
                success=event.success,
                num_converted=len(converted_kagent_tools),
            )

        except Exception as e:
            log.exception(
                "Critical error during schema conversion process.", error=str(e)
            )
            error_event = SchemaConversionResultEvent(
                server_id=server_info.id,
                success=False,
                kagent_tools_schemas=[],
                original_tool_count=len(mcp_tools),
                error_message=f"Overall conversion process failed: {e!s}",
            )
            await self.output_queue.put(error_event)

    async def start(self) -> None:  # ADK lifecycle
        await super().start()
        self.logger.info("ConversionAgent started (ADK lifecycle).")

    async def stop(self) -> None:  # ADK lifecycle
        self.logger.info("ConversionAgent stopping (ADK lifecycle)...")
        # If there were any long-running conversion tasks, cancel them here.
        # For now, convert_schemas_command is assumed to be relatively
        # short-lived per call.
        await super().stop()
        self.logger.info("ConversionAgent stopped (ADK lifecycle).")

# The SchemaConverterService class needs to be created in
# src/mcp_vacuum/schema_gen/schema_converter_service.py
# It will contain the actual logic from "Schema Conversion & Mapping Guide".
# The result from converter_service.convert_mcp_tool_to_kagent is assumed to
# be an object that contains the converted KagentTool and any validation
# issues or error messages.
# For example:
# class ConversionServiceResult:
#   kagent_tool: Optional[KagentTool]
#   validation_issues: List[ValidationIssue]
#   error_message: Optional[str]
# This agent is fairly simple: receives a command, uses a service, emits a result.
