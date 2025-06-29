"""
AuthenticationAgent: Handles authentication with MCP servers.
"""
import asyncio
from typing import Any

import structlog

from ..auth.token_manager import TokenManager
from ..config import Config
from ..models.auth import (  # For event payload and internal use
    OAuth2Token,
)
from ..models.mcp import MCPServerInfo  # Used as input type for commands
from .base import MCPVacuumBaseAgent  # Corrected path


# Define an event model for authentication results
class AuthResultEvent:
    def __init__(
        self,
        server_id: str,
        success: bool,
        auth_data: dict[str, Any] | None = None,
        error_message: str | None = None,
    ):
        self.server_id = server_id
        self.success = success
        # e.g., {'client_id': 'xxx'} or {'token_type': 'Bearer'}
        self.auth_data = auth_data
        self.error_message = error_message

    def __repr__(self):
        return f"<AuthResultEvent server_id='{self.server_id}' success={self.success}>"

class AuthenticationAgent(MCPVacuumBaseAgent):
    """
    ADK Agent responsible for authenticating with MCP servers.
    Uses TokenManager to get valid tokens and can initiate OAuth flows.
    """

    def __init__(
        self,
        app_config: Config,
        parent_logger: structlog.BoundLogger,
        output_queue: asyncio.Queue,
    ):
        super().__init__(
            agent_name="AuthenticationAgent",
            app_config=app_config,
            parent_logger=parent_logger,
        )
        # TokenManager uses configured storage
        self.token_manager = TokenManager(app_config=app_config)
        # Queue to send AuthResultEvent to Orchestrator
        self.output_queue = output_queue
        self.logger.info("AuthenticationAgent initialized.")
        # Store active authentication tasks if needed:
        # self._auth_tasks = {} server_id -> Task

    async def authenticate_server_command(self, server_info: MCPServerInfo):
        """
        Command to authenticate with a specific server.
        Tries to get a valid token using TokenManager (which handles cache, storage, refresh).
        If TokenManager cannot provide a token automatically, this agent might (in future)
        initiate a new interactive OAuth flow. For P0, it will report failure if not automatic.
        """
        log = self.logger.bind(server_id=server_info.id, server_name=server_info.name)
        log.info("Received command to authenticate server.")

        token: OAuth2Token | None = None
        error_msg: str | None = None
        success: bool = False
        auth_details: dict[str, Any] | None = None

        try:
            # TokenManager's get_valid_oauth_token tries cache, storage, and
            # refresh. It needs server_info to construct OAuth2ClientConfig
            # if needed for refresh/registration.
            token = await self.token_manager.get_valid_oauth_token(
                server_id=server_info.id, server_info=server_info
            )

            if token:
                log.info(
                    "Successfully obtained/validated OAuth token via TokenManager."
                )
                success = True
                # For the event, we might not want to send the full token.
                # Perhaps just confirmation or client_id if that's what other
                # agents need. For now, let's include a placeholder.
                auth_details = {
                    "token_type": token.token_type,
                    "access_token_present": bool(token.access_token),
                }
                # If client_id was part of this server's auth config, include it.
                # client_cfg = await self.token_manager._get_oauth_client_config(
                # server_info.id, server_info, log
                # )
                # if client_cfg: auth_details["client_id"] = client_cfg.client_id
            else:
                # If token is None, it means automated retrieval/refresh failed.
                # This is where a full, interactive OAuth flow would be initiated.
                # For P0, we'll consider this a failure for non-interactive agent.
                log.warning(
                    "Could not automatically obtain a valid token "
                    "(cache/storage/refresh failed)."
                )
                error_msg = (
                    "Automated token retrieval/refresh failed. "
                    "Interactive authentication may be required."
                )

                # Conceptual: Initiate interactive flow if possible/configured
                # if self.app_config.auth.allow_interactive_auth:
                #     token = await self._initiate_interactive_oauth_flow(server_info, log)
                #     if token: ... (update success, auth_details)

        except Exception as e:
            log.exception("Error during authentication process.", error=str(e))
            error_msg = f"Authentication process failed: {e!s}"

        # Emit result event
        event = AuthResultEvent(
            server_id=server_info.id,
            success=success,
            auth_data=auth_details,
            error_message=error_msg
        )
        await self.output_queue.put(event)
        log.debug("AuthResultEvent emitted.", success=success)

    async def _initiate_interactive_oauth_flow(
        self, server_info: MCPServerInfo, log_context: structlog.BoundLogger
    ) -> OAuth2Token | None:
        """
        (Conceptual for P0 - complex to fully implement without UI/user
        interaction strategy)
        Initiates a new OAuth 2.1 Authorization Code Grant flow with PKCE.
        This would typically involve:
        1. Generating PKCE challenge.
        2. Building authorization URL.
        3. Presenting URL to user (e.g., print to console, open browser).
        4. Starting a local HTTP server to listen for the callback to `redirect_uri`.
        5. User authenticates, auth server redirects to local server.
        6. Local server captures auth code and state.
        7. Exchange code for token using OAuth2Client.
        8. Store the new token using TokenManager.
        """
        log_context.info("Placeholder: Interactive OAuth flow initiation started.")

        oauth_client_cfg = (
            await self.token_manager._get_oauth_client_config(
                server_info.id, server_info, log_context
            )
        )
        if not oauth_client_cfg:
            log_context.error(
                "Cannot initiate OAuth flow: failed to get client configuration."
            )
            return None

        # This part is highly dependent on how user interaction is handled.
        # For a CLI, it might print a URL and ask user to paste the redirect.
        # For a server agent, it might require a web frontend component.
        log_context.warning(
            "Interactive OAuth flow is conceptual for P0 and not fully implemented."
        )
        # pkce = generate_pkce_challenge_pair()
        # async with OAuth2Client(
        # client_config=oauth_client_cfg, app_config=self.app_config
        # ) as client:
        #     auth_url, state, verifier = client.create_authorization_url(
        # "random_state_value", pkce
        # )
        #     log_context.info(f"Please visit this URL to authorize: {auth_url}")
        #     # ... logic to get code from redirect ...
        #     # code = ...
        #     # received_state = ...
        #     # token = await client.exchange_code_for_token(
        # code, verifier, received_state, state
        # )
        #     # await self.token_manager.store_new_token(
        # server_info.id, token, log_context
        # )
        #     # return token
        return None

    async def get_token_for_server_command(
        self, server_id: str, server_info: MCPServerInfo
    ) -> OAuth2Token | None:
        """
        Direct command for other agents (like MCPClientAgent) to request a token.
        This bypasses the event queue for a direct request-response if needed by
        ADK patterns. This is still non-interactive for token *retrieval*.
        """
        log = self.logger.bind(
            server_id=server_id,
            server_name=server_info.name,
            command="get_token_for_server",
        )
        log.info("Received direct command to get token for server.")
        try:
            token = await self.token_manager.get_valid_oauth_token(
                server_id=server_id, server_info=server_info
            )
            if token:
                log.debug("Successfully provided token via direct command.")
                return token
            else:
                log.warning(
                    "Could not provide token via direct command "
                    "(automated retrieval failed)."
                )
                return None
        except Exception as e:
            log.exception(
                "Error during direct token retrieval command.", error=str(e)
            )
            return None

    async def start(self) -> None:  # ADK lifecycle
        await super().start()
        self.logger.info("AuthenticationAgent started (ADK lifecycle).")

    async def stop(self) -> None:  # ADK lifecycle
        self.logger.info("AuthenticationAgent stopping (ADK lifecycle)...")
        # Clean up token manager if it holds resources (e.g. sessions,
        # though unlikely for manager itself)
        if self.token_manager and hasattr(
            self.token_manager, "close"
        ):  # If TokenManager needs cleanup
            # await self.token_manager.close()
            pass
        await super().stop()
        self.logger.info("AuthenticationAgent stopped (ADK lifecycle).")

# MCPServerInfo model needs to be updated to ensure it has:
# - server_info.registration_endpoint: Optional[HttpUrl]
# - server_info.auth_metadata.authorization_endpoint: Optional[HttpUrl]
# - server_info.auth_metadata.token_endpoint: Optional[HttpUrl]
# These would be populated by the DiscoveryAgent or from configuration.
# The `_initiate_interactive_oauth_flow` is a placeholder for P0.
# A real agent system might need a separate UI/UX component or CLI interaction
# for this.
# The `auth_details` in `AuthResultEvent` is simplified; it might need to
# carry more specific info like the actual client_id used, or even the token
# if the consumer needs it directly (though less secure).
# The `get_token_for_server_command` provides a direct way for another agent
# (e.g. MCPClientAgent) to request a token without going through the main
# event loop, if that pattern is more suitable.
