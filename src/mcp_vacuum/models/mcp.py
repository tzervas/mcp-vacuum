from typing import List, Optional, Dict, Any
from pydantic import HttpUrl, Field

from .common import BasePydanticModel, TransportType, AuthMethod, MCPCapability, AuthenticationMetadata, MCPAnnotations

class MCPServiceRecord(BasePydanticModel):
    id: str # Unique identifier for the service, e.g., "mdns-myserver" or "ssdp-uuid-xyz"
    name: str # User-friendly name of the server
    endpoint: HttpUrl # Primary endpoint URL for the MCP server
    transport_type: TransportType = TransportType.HTTP # Default, can be overridden
    version: str = "1.0" # MCP protocol version
    capabilities: List[MCPCapability] = Field(default_factory=list)
    auth_method: AuthMethod = AuthMethod.NONE
    auth_metadata: Optional[AuthenticationMetadata] = None # Detailed auth info if not 'none'
    discovery_method: str # e.g., "mdns", "ssdp", "arp", "manual"
    health_check_url: Optional[HttpUrl] = None
    # Additional metadata discovered or configured
    metadata: Optional[Dict[str, Any]] = None

class MCPTool(BasePydanticModel):
    name: str = Field(..., description="Name of the tool, unique within the MCP server.")
    description: str = Field(..., description="Detailed description of what the tool does.")
    input_schema: Dict[str, Any] = Field(..., description="JSON Schema Draft 7 for the tool's input parameters.")
    output_schema: Optional[Dict[str, Any]] = Field(None, description="JSON Schema Draft 7 for the tool's output. Optional.")
    annotations: Optional[MCPAnnotations] = None
    # Server-specific information, useful when the tool is part of a collection from a server
    server_endpoint: Optional[HttpUrl] = Field(None, description="Endpoint of the MCP server providing this tool.")
    # Additional metadata like categories, risk levels, etc. determined by MCP Vacuum
    vacuum_metadata: Optional[Dict[str, Any]] = None

class MCPServerInfo(BasePydanticModel): # Used for dynamic client registration context
    name: str
    # Add other fields that might be relevant for client registration, e.g. server_id
    id: str
    registration_endpoint: Optional[HttpUrl] = None # The specific registration endpoint for this server, if supported
    endpoint: Optional[HttpUrl] = None # Main server endpoint, useful context for registration if needed

class MCPCapabilities(BasePydanticModel): # Response from /capabilities endpoint
    # This model structure depends on how MCP servers expose capabilities.
    # Assuming a simple list of tool names for now.
    tools: List[str] = Field(default_factory=list)
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
