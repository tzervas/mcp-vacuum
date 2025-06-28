"""
MCPClientAgent: Manages communication with individual MCP servers.
"""
import asyncio
from typing import Optional, Any, Dict, List

import structlog
import aiohttp # For shared ClientSession

from ..config import Config
from ..adk.base import MCPVacuumBaseAgent
from ..mcp_client import BaseMCPClient, HTTPMCPClient # Add other client types (WS, SSE, STDIO) as implemented
from ..mcp_client.exceptions import MCPClientError, MCPAuthError
from ..models.mcp import MCPServerInfo, MCPTool # MCPTool for return types
from ..models.auth import OAuth2Token
from .auth_agent import AuthenticationAgent # To request tokens

# Event if this agent were to emit results asynchronously (e.g. ToolsListEvent)
# class ToolsListEvent:
#     def __init__(self, server_id: str, tools: List[MCPTool], error: Optional[str]=None):
#         self.server_id = server_id
#         self.tools = tools
#         self.error = error

class MCPClientAgent(MCPVacuumBaseAgent):
    """
    ADK Agent responsible for managing client instances and communicating
    with specific MCP servers (e.g., listing tools, invoking tools).
    """

    def __init__(self, app_config: Config, parent_logger: structlog.BoundLogger, auth_agent_ref: AuthenticationAgent):
        super().__init__(agent_name="MCPClientAgent", app_config=app_config, parent_logger=parent_logger)
        self.auth_agent = auth_agent_ref # Reference to AuthAgent to get tokens

        # Shared aiohttp ClientSession for all HTTP-based MCP clients this agent manages.
        # This session should be created with appropriate pooling from app_config.mcp_client.
        self._shared_aiohttp_session: Optional[aiohttp.ClientSession] = None

        # Cache for active MCP client instances to avoid re-creation
        self._active_mcp_clients: Dict[str, BaseMCPClient] = {} # server_id -> client_instance
        self.logger.info("MCPClientAgent initialized.")

    async def _get_shared_aiohttp_session(self) -> aiohttp.ClientSession:
        """Creates or returns the shared aiohttp ClientSession."""
        if self._shared_aiohttp_session is None or self._shared_aiohttp_session.closed:
            self.logger.info("Creating shared aiohttp session for MCPClientAgent.")
            client_cfg = self.app_config.mcp_client
            ssl_context = None
            if client_cfg.ssl_verify: # General SSL verification setting
                pass # Default aiohttp handling
            else:
                self.logger.warning("SSL verification is DISABLED for shared aiohttp session. This is insecure.")
                ssl_context = False

            connector = aiohttp.TCPConnector(
                limit=client_cfg.connection_pool_total_limit,
                limit_per_host=client_cfg.connection_pool_per_host_limit,
                ttl_dns_cache=client_cfg.connection_pool_dns_cache_ttl_seconds,
                ssl=ssl_context
            )
            self._shared_aiohttp_session = aiohttp.ClientSession(connector=connector)
        return self._shared_aiohttp_session

    async def _get_mcp_client(self, server_info: MCPServerInfo) -> Optional[BaseMCPClient]:
        """
        Gets or creates an MCP client instance for the given server.
        Handles token acquisition for the client.
        """
        log = self.logger.bind(server_id=server_info.id, server_name=server_info.name)

        if server_info.id in self._active_mcp_clients:
            client = self._active_mcp_clients[server_info.id]
            if await client.is_connected() or server_info.transport_type == "http": # HTTP is often connectionless
                 # For non-HTTP, if not connected, may need re-authentication or re-connect
                pass # TODO: Add logic to re-auth/re-connect if needed for stateful transports
            log.debug("Reusing active MCP client instance.")
        else:
            log.debug("Creating new MCP client instance.")
            # Determine transport and instantiate appropriate client
            # For P0, primarily supporting HTTP
            if server_info.transport_type == "http": # Assuming MCPServerInfo has transport_type
                shared_session = await self._get_shared_aiohttp_session()
                client = HTTPMCPClient(
                    service_record=server_info, # HTTPMCPClient expects MCPServiceRecord, ensure types match
                    config=self.app_config,
                    aiohttp_session=shared_session
                )
            # elif server_info.transport_type == "websocket":
            #     client = WebSocketMCPClient(...)
            else:
                log.error("Unsupported transport type for MCP client", transport=server_info.transport_type)
                return None

            try:
                await client.connect() # Establish connection (for stateful transports, or session prep for HTTP)
                self._active_mcp_clients[server_info.id] = client
            except MCPClientError as e:
                log.error("Failed to connect MCP client", error=str(e))
                await client.disconnect() # Ensure cleanup
                return None

        # Acquire and set token for this client instance before returning
        log.debug("Requesting token for MCP client from AuthenticationAgent.")
        # MCPServiceRecord (used by HTTP client) and MCPServerInfo (used by AuthAgent) are compatible enough here.
        token: Optional[OAuth2Token] = await self.auth_agent.get_token_for_server_command(server_info.id, server_info)

        if not token:
            log.warning("No token available from AuthenticationAgent. MCP client calls may fail.")
            # Depending on server auth requirements, this might be acceptable (e.g. public tools)
            # or it might mean all subsequent calls will fail.
            await client.set_auth_token(None) # Explicitly clear any old token
            # Optionally, we could raise an error here if token is strictly required.
            # raise MCPAuthError(f"Failed to get token for server {server_info.id}")
        else:
            log.debug("Token obtained, setting on MCP client.")
            await client.set_auth_token(token)

        return client

    async def get_tools_for_server(self, server_info: MCPServerInfo) -> Optional[List[MCPTool]]:
        """
        Retrieves the list of tools from the specified MCP server.
        """
        log = self.logger.bind(server_id=server_info.id, server_name=server_info.name)
        log.info("Attempting to list tools for server.")

        client = await self._get_mcp_client(server_info)
        if not client:
            log.error("Failed to get MCP client instance for listing tools.")
            return None

        try:
            # BaseMCPClient.list_tools() returns List[Dict[str, Any]]
            # We need to parse these into MCPTool Pydantic models.
            raw_tools_data = await client.list_tools()
            tools = [MCPTool.model_validate(tool_data) for tool_data in raw_tools_data]
            log.info("Successfully listed tools.", num_tools=len(tools))
            return tools
        except MCPAuthError as e: # Token might have expired between _get_mcp_client and actual call
            log.warning("Authentication error while listing tools. Token might be stale.", error=str(e))
            # Optionally, try to refresh token and retry once here, or rely on next call to re-auth.
            # For now, just let it fail to Orchestrator or caller.
            return None
        except MCPClientError as e:
            log.error("MCPClientError while listing tools.", error=str(e))
            return None
        except Exception as e:
            log.exception("Unexpected error listing tools.", error_type=type(e).__name__)
            return None

    async def get_tool_schema_for_server(self, server_info: MCPServerInfo, tool_name: str) -> Optional[MCPTool]:
        """Retrieves the schema for a specific tool from an MCP server."""
        log = self.logger.bind(server_id=server_info.id, tool_name=tool_name)
        log.info("Attempting to get tool schema.")

        client = await self._get_mcp_client(server_info)
        if not client:
            log.error("Failed to get MCP client instance for getting tool schema.")
            return None

        try:
            raw_schema_data = await client.get_tool_schema(tool_name)
            tool_schema = MCPTool.model_validate(raw_schema_data)
            log.info("Successfully retrieved tool schema.")
            return tool_schema
        except MCPAuthError as e:
            log.warning("Authentication error while getting tool schema.", error=str(e))
            return None
        except MCPClientError as e:
            log.error("MCPClientError while getting tool schema.", error=str(e))
            return None
        except Exception as e:
            log.exception("Unexpected error getting tool schema.", error_type=type(e).__name__)
            return None

    async def invoke_tool_on_server(self, server_info: MCPServerInfo, tool_name: str, parameters: Dict[str, Any]) -> Optional[Any]:
        """Invokes a tool on a specific MCP server."""
        log = self.logger.bind(server_id=server_info.id, tool_name=tool_name)
        log.info("Attempting to invoke tool.")

        client = await self._get_mcp_client(server_info)
        if not client:
            log.error("Failed to get MCP client instance for invoking tool.")
            return None

        try:
            # TODO: Client-side validation of `parameters` against tool's inputSchema?
            # The BaseMCPClient.invoke_tool expects this to be done by caller.
            result = await client.invoke_tool(tool_name, parameters)
            log.info("Successfully invoked tool.")
            # TODO: Parse `result` against tool's outputSchema?
            return result
        except MCPAuthError as e:
            log.warning("Authentication error while invoking tool.", error=str(e))
            return None
        except MCPClientError as e: # Includes MCPToolInvocationError
            log.error("MCPClientError while invoking tool.", error=str(e))
            return None
        except Exception as e:
            log.exception("Unexpected error invoking tool.", error_type=type(e).__name__)
            return None

    async def start(self) -> None: # ADK lifecycle
        await super().start()
        await self._get_shared_aiohttp_session() # Initialize shared session on start
        self.logger.info("MCPClientAgent started (ADK lifecycle). Shared HTTP session prepared.")

    async def stop(self) -> None: # ADK lifecycle
        self.logger.info("MCPClientAgent stopping (ADK lifecycle)...")
        # Close all active MCP client connections
        for server_id, client_instance in list(self._active_mcp_clients.items()):
            try:
                self.logger.debug(f"Disconnecting client for server {server_id}")
                await client_instance.disconnect()
            except Exception as e:
                self.logger.error(f"Error disconnecting client for server {server_id}", error=str(e))
        self._active_mcp_clients.clear()

        # Close the shared aiohttp session
        if self._shared_aiohttp_session and not self._shared_aiohttp_session.closed:
            self.logger.info("Closing shared aiohttp session.")
            await self._shared_aiohttp_session.close()
        self._shared_aiohttp_session = None

        await super().stop()
        self.logger.info("MCPClientAgent stopped (ADK lifecycle).")


# Ensure MCPServerInfo (passed around) is compatible with MCPServiceRecord (used by HTTPMCPClient).
# They should ideally be the same model or MCPServerInfo should contain an MCPServiceRecord.
# For now, assuming MCPServerInfo has .id, .name, .transport_type, .endpoint, .auth_metadata.
# The Pydantic parsing (model_validate) for MCPTool in list_tools/get_tool_schema is important.
# Error handling for token expiry during a call (after _get_mcp_client got a token) is noted.
# A retry mechanism within these methods (e.g., one retry after token refresh) could be added.
# For P0, this agent provides the core functionalities.
