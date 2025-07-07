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

class MCPCapabilities(BasePydanticModel):
    """Response from /capabilities endpoint.
    
    This model includes standard MCP capabilities fields and preserves any unknown
    fields in extra_fields for potential future use or debugging.
    """
    tools: list[str] = Field(default_factory=list, description="List of available tool names")
    resources: list[str] = Field(default_factory=list, description="List of available resource types")
    prompts: list[str] = Field(default_factory=list, description="List of supported prompt types")
    supported_auth_methods: list[AuthMethod] = Field(
        default_factory=list,
        description="List of authentication methods supported by the server"
    )
    # Store any extra fields returned by server for future compatibility
    extra_fields: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional fields returned by the server that aren't part of the standard model"
    )

    def __init__(self, **data):
        # Extract standard fields
        standard_fields = {
            field: data.pop(field)
            for field in ['tools', 'resources', 'prompts', 'supported_auth_methods']
            if field in data
        }
        # Store remaining fields in extra_fields
        standard_fields['extra_fields'] = data
        super().__init__(**standard_fields)

    class Config:
        extra = 'allow'  # Allow extra fields during parsing
