from enum import Enum
from pydantic import BaseModel, HttpUrl
from typing import List, Optional, Dict, Any, Literal

class BasePydanticModel(BaseModel):
    class Config:
        extra = 'forbid'
        populate_by_name = True
        use_enum_values = True

class TransportType(str, Enum):
    STDIO = "stdio"
    SSE = "sse"
    HTTP = "http"
    WEBSOCKET = "websocket"

class AuthMethod(str, Enum):
    NONE = "none"
    OAUTH2_PKCE = "oauth2_pkce"
    TOKEN = "token"
    MTLS = "mtls" # Mutual TLS
    CUSTOM = "custom"

class ToolCategory(str, Enum):
    FILE_OPERATIONS = "file-operations"
    NETWORK_ACCESS = "network-access"
    SYSTEM_COMMANDS = "system-commands"
    DATA_PROCESSING = "data-processing"
    API_INTEGRATION = "api-integration"
    COMPUTATION = "computation"
    UNKNOWN = "unknown"

class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class MCPCapabilityType(str, Enum):
    TOOLS = "tools"
    RESOURCES = "resources"
    PROMPTS = "prompts"
    SAMPLING = "sampling"

class MCPCapability(BasePydanticModel):
    type: MCPCapabilityType
    # Further details might be needed depending on type
    # For example, a list of tool names if type is TOOLS
    details: Optional[Dict[str, Any]] = None

class AuthenticationMetadata(BasePydanticModel):
    method: AuthMethod
    authorization_endpoint: Optional[HttpUrl] = None
    token_endpoint: Optional[HttpUrl] = None
    registration_endpoint: Optional[HttpUrl] = None # For dynamic client registration
    scopes_supported: Optional[List[str]] = None
    # Other relevant metadata based on auth method
    # e.g., pkce_code_challenge_methods_supported for oauth2_pkce

class MCPAnnotations(BasePydanticModel):
    read_only_hint: Optional[bool] = None
    destructive_hint: Optional[bool] = None
    idempotent_hint: Optional[bool] = None
    # Custom annotations can be added here
    custom_annotations: Optional[Dict[str, Any]] = None

# For Kagent CRD Spec
class KagentCRDSchema(BasePydanticModel):
    type: str = "object" # Default to object, can be other JSON schema types
    properties: Optional[Dict[str, Any]] = None # JSON Schema for parameters
    required: Optional[List[str]] = None
    # Other JSON Schema fields like 'description', 'format', 'enum', etc.
    # For Kubernetes compatibility, some fields might be under 'x-kubernetes-*'

    class Config:
        extra = 'allow' # Allow other JSON schema fields
        populate_by_name = True
        use_enum_values = True
