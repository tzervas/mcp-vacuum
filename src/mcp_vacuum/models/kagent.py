"""Module for Kagent-related models and schema validation."""
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator

from .common import ToolCategory, RiskLevel, BasePydanticModel, KagentCRDSchema


class ValidationSeverity(str, Enum):
    """Schema validation issue severity levels."""
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class ValidationIssue(BasePydanticModel):
    """Represents a validation issue found during schema conversion."""
    severity: ValidationSeverity
    message: str
    path: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    field_path: Optional[str] = None  # For backward compatibility


class ValidationResult(BasePydanticModel):
    """Results of schema validation."""
    is_valid: bool
    issues: List[ValidationIssue] = Field(default_factory=list)
    schema_hash: Optional[str] = None

    @property
    def has_errors(self) -> bool:
        """Check if there are any error-level issues."""
        return any(issue.severity == ValidationSeverity.ERROR for issue in self.issues)


class KagentMetadata(BasePydanticModel):
    """Metadata for Kagent tool definitions."""
    name: str
    version: str = "0.1.0"
    category: ToolCategory = ToolCategory.UNKNOWN
    risk_level: RiskLevel = RiskLevel.LOW
    description: Optional[str] = None
    labels: Dict[str, str] = Field(default_factory=dict)
    annotations: Dict[str, str] = Field(default_factory=dict)


class KagentToolSpec(BasePydanticModel):
    """Specification for a Kagent tool."""
    description: str
    parameters: KagentCRDSchema
    type: str = "mcp"
    outputs: Optional[KagentCRDSchema] = None
    output_schema: Optional[KagentCRDSchema] = None
    mcp_config: Optional[Dict[str, Any]] = Field(default=None, alias="mcpConfig")
    examples: List[Dict[str, Any]] = Field(default_factory=list)
    validation_rules: Optional[Dict[str, Any]] = None

    model_config = {
        "extra": "forbid",
        "populate_by_name": True,
        "use_enum_values": True,
    }


class KagentTool(BasePydanticModel):
    """Root model for a Kagent tool definition.
    Based on Kubernetes-style resource definition.
    """
    apiVersion: str = Field(default="kagent.ai/v1alpha1", pattern=r"^kagent\.ai/v1(alpha\d+|beta\d+)?$")
    kind: str = Field(default="Tool")
    metadata: KagentMetadata
    spec: KagentToolSpec

    @field_validator("kind")
    @classmethod
    def validate_kind(cls, v: str) -> str:
        """Validate 'kind' field."""
        if v != "Tool":
            raise ValueError("kind must be 'Tool'")
        return v


class ConversionMetadataModel(BasePydanticModel):
    """Metadata about the conversion process."""
    original_tool_name: str
    conversion_timestamp: datetime
    conversion_version: str
    source_schema_version: str = "mcp/1"
    source_system: str = "mcp-vacuum"
    validation_result: Optional[ValidationResult] = None
    semantic_score: float = Field(default=0.0, ge=0, le=1)
    field_mappings: Dict[str, str] = Field(default_factory=dict)


class ConversionResult(BasePydanticModel):
    """Results of converting an MCP tool to Kagent format."""
    tool: KagentTool
    metadata: ConversionMetadataModel
    original_schema: Dict[str, Any]  # The original MCP schema
