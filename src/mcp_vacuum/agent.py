"""Main MCP Vacuum Agent implementation."""

import asyncio
import logging
from typing import Dict, List, Optional

import structlog

from .auth import AuthManager
from .config import Config
from .discovery import MCPDiscovery
from .schema_gen import SchemaGenerator
from .server import MCPServer


class MCPVacuumAgent:
    """Main MCP Vacuum Agent class.
    
    This agent discovers, authenticates with, and integrates MCP Servers.
    """

    def __init__(self, config: Optional[Config] = None) -> None:
        """Initialize the MCP Vacuum Agent.
        
        Args:
            config: Configuration object. If None, will be loaded from environment.
        """
        self.config = config or Config.from_env()
        self.logger = self._setup_logging()
        
        # Initialize components
        self.auth_manager = AuthManager(self.config.auth)
        self.discovery = MCPDiscovery(self.config.discovery, self.logger)
        self.schema_generator = SchemaGenerator(self.logger)
        
        # State tracking
        self.discovered_servers: Dict[str, MCPServer] = {}
        self.authenticated_servers: Dict[str, MCPServer] = {}
        
    def _setup_logging(self) -> structlog.BoundLogger:
        """Set up structured logging."""
        logging.basicConfig(
            level=getattr(logging, self.config.logging.level.upper()),
            format="%(message)s"
        )
        
        structlog.configure(
            processors=[
                structlog.processors.add_log_level,
                structlog.processors.add_logger_name,
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.dev.ConsoleRenderer() if self.config.logging.format == "console"
                else structlog.processors.JSONRenderer()
            ],
            wrapper_class=structlog.make_filtering_bound_logger(
                getattr(logging, self.config.logging.level.upper())
            ),
            logger_factory=structlog.PrintLoggerFactory(),
            cache_logger_on_first_use=True,
        )
        
        return structlog.get_logger("mcp_vacuum.agent")
    
    async def discover_servers(
        self, 
        target_networks: Optional[List[str]] = None
    ) -> Dict[str, MCPServer]:
        """Discover MCP servers in the target environment.
        
        Args:
            target_networks: List of network ranges to scan. If None, uses auto-discovery.
            
        Returns:
            Dictionary of discovered servers keyed by server ID.
        """
        self.logger.info("Starting MCP server discovery", target_networks=target_networks)
        
        try:
            discovered = await self.discovery.discover_servers(target_networks)
            self.discovered_servers.update(discovered)
            
            self.logger.info(
                "Discovery completed", 
                discovered_count=len(discovered),
                total_discovered=len(self.discovered_servers)
            )
            
            return discovered
            
        except Exception as e:
            self.logger.error("Discovery failed", error=str(e), exc_info=True)
            raise
    
    async def authenticate_server(self, server: MCPServer) -> bool:
        """Authenticate with a specific MCP server.
        
        Args:
            server: The MCP server to authenticate with.
            
        Returns:
            True if authentication succeeded, False otherwise.
        """
        self.logger.info("Attempting authentication", server_id=server.id, endpoint=server.endpoint)
        
        try:
            success = await self.auth_manager.authenticate(server)
            
            if success:
                self.authenticated_servers[server.id] = server
                self.logger.info("Authentication successful", server_id=server.id)
            else:
                self.logger.warning("Authentication failed", server_id=server.id)
                
            return success
            
        except Exception as e:
            self.logger.error(
                "Authentication error", 
                server_id=server.id, 
                error=str(e), 
                exc_info=True
            )
            return False
    
    async def authenticate_all_servers(self) -> Dict[str, bool]:
        """Authenticate with all discovered servers.
        
        Returns:
            Dictionary mapping server IDs to authentication success status.
        """
        self.logger.info("Starting bulk authentication", server_count=len(self.discovered_servers))
        
        auth_tasks = []
        for server in self.discovered_servers.values():
            task = asyncio.create_task(self.authenticate_server(server))
            auth_tasks.append((server.id, task))
        
        results = {}
        for server_id, task in auth_tasks:
            try:
                results[server_id] = await task
            except Exception as e:
                self.logger.error(
                    "Authentication task failed", 
                    server_id=server_id, 
                    error=str(e)
                )
                results[server_id] = False
        
        successful_auths = sum(1 for success in results.values() if success)
        self.logger.info(
            "Bulk authentication completed", 
            successful=successful_auths,
            total=len(results)
        )
        
        return results
    
    async def generate_schemas(self) -> Dict[str, dict]:
        """Generate Kagent-compliant schemas for authenticated servers.
        
        Returns:
            Dictionary mapping server IDs to their generated schemas.
        """
        self.logger.info(
            "Starting schema generation", 
            server_count=len(self.authenticated_servers)
        )
        
        schemas = {}
        for server_id, server in self.authenticated_servers.items():
            try:
                schema = await self.schema_generator.generate_schema(server)
                schemas[server_id] = schema
                self.logger.info("Schema generated", server_id=server_id)
                
            except Exception as e:
                self.logger.error(
                    "Schema generation failed", 
                    server_id=server_id, 
                    error=str(e),
                    exc_info=True
                )
        
        self.logger.info("Schema generation completed", generated_count=len(schemas))
        return schemas
    
    async def run_full_discovery(
        self, 
        target_networks: Optional[List[str]] = None
    ) -> Dict[str, dict]:
        """Run the complete discovery, authentication, and schema generation process.
        
        Args:
            target_networks: List of network ranges to scan.
            
        Returns:
            Dictionary mapping server IDs to their generated schemas.
        """
        self.logger.info("Starting full MCP discovery process")
        
        try:
            # Step 1: Discovery
            await self.discover_servers(target_networks)
            
            # Step 2: Authentication
            await self.authenticate_all_servers()
            
            # Step 3: Schema generation
            schemas = await self.generate_schemas()
            
            self.logger.info(
                "Full discovery process completed",
                discovered=len(self.discovered_servers),
                authenticated=len(self.authenticated_servers),
                schemas_generated=len(schemas)
            )
            
            return schemas
            
        except Exception as e:
            self.logger.error(
                "Full discovery process failed", 
                error=str(e), 
                exc_info=True
            )
            raise
    
    def get_discovery_summary(self) -> Dict[str, int]:
        """Get a summary of the discovery process.
        
        Returns:
            Dictionary with counts of discovered, authenticated, and schema-generated servers.
        """
        return {
            "discovered": len(self.discovered_servers),
            "authenticated": len(self.authenticated_servers),
            "with_schemas": len([
                server for server in self.authenticated_servers.values()
                if hasattr(server, 'schema') and server.schema
            ])
        }
