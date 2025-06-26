"""
Pydantic models for MCP Vacuum project.
"""
from .common import (
    AuthMethod,
    AuthenticationMetadata,
    BasePydanticModel,
    MCPAnnotations, # Corrected: MCPAnnotation removed
    MCPCapability,
    MCPCapabilityType,
    RiskLevel,
    ToolCategory,
    TransportType,
    KagentCRDSchema,
)
from .mcp import (
    MCPCapabilities,
    MCPServiceRecord,
    MCPServerInfo,
    MCPTool,
)
from .kagent import (
    ConversionMetadataModel,
    ConversionResult,
    KagentCRDSchema, # Re-exporting for clarity if used directly from models
    KagentMetadata,
    KagentTool,
    KagentToolSpec,
    ValidationIssue,
    ValidationResult,
    ValidationSeverity,
)
from .auth import (
    AuthMethod, # Re-exporting
    AuthorizationCodeResponse,
    ClientCredentials,
    OAuth2ClientConfig,
    OAuth2Token,
    OAuthError,
    PKCEChallenge,
    TokenRequest,
)

__all__ = [
    "AuthMethod",
    "AuthenticationMetadata",
    "AuthorizationCodeResponse",
    "BasePydanticModel",
    "ClientCredentials",
    "ConversionMetadataModel",
    "ConversionResult",
    # KagentCRDSchema is already imported from .common and re-exported from .kagent, ensure it's correctly listed once if necessary
    # For now, assuming the re-export from .kagent is primary for this __all__
    "KagentMetadata",
    "KagentTool",
    "KagentToolSpec",
    "MCPAnnotations", # Corrected: MCPAnnotation removed
    "MCPCapabilities",
    "MCPCapability",
    "MCPCapabilityType",
    "MCPServiceRecord",
    "MCPServerInfo",
    "MCPTool",
    "OAuth2ClientConfig",
    "OAuth2Token",
    "OAuthError",
    "PKCEChallenge",
    "RiskLevel",
    "TokenRequest",
    "ToolCategory",
    "TransportType",
    "ValidationIssue",
    "ValidationResult",
    "ValidationSeverity",
]
