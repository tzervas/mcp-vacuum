from enum import Enum
from typing import Any

from pydantic import BaseModel, HttpUrl


class BasePydanticModel(BaseModel):
    model_config = {
        "extra": "forbid",
        "populate_by_name": True,
        "use_enum_values": True,
    }

class TransportType(str, Enum):
    STDIO = "stdio"
    SSE = "sse"
    HTTP = "http"
    WEBSOCKET = "websocket"

class AuthMethod(str, Enum):
    NONE = "none"
    OAUTH2_PKCE = "oauth2_pkce"
    TOKEN = "token"
    CERTIFICATE = "certificate"
    USERNAME_PASSWORD = "username_password"
    OAUTH2 = "oauth2"
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
    details: dict[str, Any] | None = None

class AuthenticationMetadata(BasePydanticModel):
    method: AuthMethod
    authorization_endpoint: HttpUrl | None = None
    token_endpoint: HttpUrl | None = None
    registration_endpoint: HttpUrl | None = None # For dynamic client registration
    scopes_supported: list[str] | None = None
    # Other relevant metadata based on auth method
    # e.g., pkce_code_challenge_methods_supported for oauth2_pkce

class MCPAnnotations(BasePydanticModel):
    read_only_hint: bool | None = None
    destructive_hint: bool | None = None
    idempotent_hint: bool | None = None
    # Custom annotations can be added here
    custom_annotations: dict[str, Any] | None = None

# For Kagent CRD Spec
class KagentCRDSchema(BasePydanticModel):
    type: str = "object" # Default to object, can be other JSON schema types
    properties: dict[str, Any] | None = None # JSON Schema for parameters
    required: list[str] | None = None
    # Other JSON Schema fields like 'description', 'format', 'enum', etc.
    # For Kubernetes compatibility, some fields might be under 'x-kubernetes-*'

    model_config = {
        "extra": "allow",  # Allow other JSON schema fields
        "populate_by_name": True,
        "use_enum_values": True,
    }
