"""
Pydantic models for MCP Vacuum project.
"""
# from .kagent import ( # Commented out due to ModuleNotFoundError: No module named 'mcp_vacuum.models.kagent'
#     ConversionMetadataModel,
#     ConversionResult,
#     KagentCRDSchema, # Re-exporting for clarity if used directly from models
#     KagentMetadata,
#     KagentTool,
#     KagentToolSpec,
#     ValidationIssue,
#     ValidationResult,
#     ValidationSeverity,
# )
from .common import AuthMethod, TransportType, ToolCategory, RiskLevel, MCPCapabilityType
from .auth import (
    AuthorizationCodeResponse,
    ClientCredentials,
    OAuth2ClientConfig,
    OAuth2Token,
    OAuthError,
    PKCEChallenge,
    TokenRequest,
)
from .common import (
    AuthenticationMetadata,
    AuthMethod,
    BasePydanticModel,
    KagentCRDSchema,
    MCPAnnotations,  # Corrected: MCPAnnotation removed
    MCPCapability,
    MCPCapabilityType,
    RiskLevel,
    ToolCategory,
    TransportType,
)
from .mcp import (
    MCPCapabilities,
    MCPServerInfo,
    MCPServiceRecord,
    MCPTool,
)

__all__ = [
    "AuthMethod",
    "AuthenticationMetadata",
    "AuthorizationCodeResponse",
    "BasePydanticModel",
    "ClientCredentials",
    # "ConversionMetadataModel", # from kagent
    # "ConversionResult", # from kagent
    # KagentCRDSchema is already imported from .common and re-exported from .kagent, ensure it's correctly listed once if necessary
    # For now, assuming the re-export from .kagent is primary for this __all__
    # "KagentMetadata", # from kagent
    # "KagentTool", # from kagent
    # "KagentToolSpec", # from kagent
    "KagentCRDSchema", # This one is also imported from .common, so might be okay to keep if common is used directly
    "MCPAnnotations", # Corrected: MCPAnnotation removed
    "MCPCapabilities",
    "MCPCapability",
    "MCPCapabilityType",
    "MCPServerInfo",
    "MCPServiceRecord",
    "MCPTool",
    "OAuth2ClientConfig",
    "OAuth2Token",
    "OAuthError",
    "PKCEChallenge",
    "RiskLevel",
    "TokenRequest",
    "ToolCategory",
    "TransportType",
    # "ValidationIssue", # from kagent
    # "ValidationResult", # from kagent
    # "ValidationSeverity", # from kagent
]
