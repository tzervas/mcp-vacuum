from typing import Any

from pydantic import Field, HttpUrl

from .common import (
    AuthenticationMetadata,
    AuthMethod,
    BasePydanticModel,
    MCPAnnotations,
    MCPCapability,
    TransportType,
)


class MCPServiceRecord(BasePydanticModel):
    id: str # Unique identifier for the service, e.g., "mdns-myserver" or "ssdp-uuid-xyz"
    name: str # User-friendly name of the server
    endpoint: HttpUrl # Primary endpoint URL for the MCP server
    transport_type: TransportType = TransportType.HTTP # Default, can be overridden
    version: str = "1.0" # MCP protocol version
    capabilities: list[MCPCapability] = Field(default_factory=list)
    auth_method: AuthMethod = AuthMethod.NONE
    auth_metadata: AuthenticationMetadata | None = None # Detailed auth info if not 'none'
    discovery_method: str # e.g., "mdns", "ssdp", "arp", "manual"
    health_check_url: HttpUrl | None = None
    # Additional metadata discovered or configured
    metadata: dict[str, Any] | None = None

class MCPTool(BasePydanticModel):
    name: str = Field(..., description="Name of the tool, unique within the MCP server.")
    description: str = Field(..., description="Detailed description of what the tool does.")
    input_schema: dict[str, Any] = Field(..., description="JSON Schema Draft 7 for the tool's input parameters.")
    output_schema: dict[str, Any] | None = Field(None, description="JSON Schema Draft 7 for the tool's output. Optional.")
    annotations: MCPAnnotations | None = None
    # Server-specific information, useful when the tool is part of a collection from a server
    server_endpoint: HttpUrl | None = Field(None, description="Endpoint of the MCP server providing this tool.")
    # Additional metadata like categories, risk levels, etc. determined by MCP Vacuum
    vacuum_metadata: dict[str, Any] | None = None

class MCPServerInfo(BasePydanticModel): # Used for dynamic client registration context
    name: str
    # Add other fields that might be relevant for client registration, e.g. server_id
    id: str
    registration_endpoint: HttpUrl | None = None # The specific registration endpoint for this server, if supported
    endpoint: HttpUrl | None = None # Main server endpoint, useful context for registration if needed

class MCPCapabilities(BasePydanticModel): # Response from /capabilities endpoint
    # This model structure depends on how MCP servers expose capabilities.
    # Assuming a simple list of tool names for now.
    tools: list[str] = Field(default_factory=list)
    # Could also include resources, prompts, etc.
    # Example:
    # resources: List[str] = Field(default_factory=list)
    # prompts: List[str] = Field(default_factory=list)
    # supported_auth_methods: List[AuthMethod] = Field(default_factory=list)

    class Config:
        extra = 'ignore' # Changed from 'allow' to 'ignore'
                         # This will ignore any fields not defined in the model,
                         # which is generally safer than 'allow' if the extra fields are not needed.
                         # If specific extra fields become important, they should be added to the model.
