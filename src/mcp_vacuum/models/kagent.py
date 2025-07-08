"""
"""Module for Kagent-related models and schema validation."""
import datetime
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
    path: str | None = None
    details: dict[str, Any] | None = None
    field_path: str | None = None  # For backward compatibility


class ValidationResult(BasePydanticModel):
    """Results of schema validation."""
    is_valid: bool
    issues: list[ValidationIssue] = Field(default_factory=list)

    @property
    def has_errors(self) -> bool:
        """Check if there are any error-level issues."""
        return any(issue.severity == ValidationSeverity.ERROR for issue in self.issues)


class KagentMetadata(BasePydanticModel):
    """Metadata for Kagent tool definitions."""
    name: str
    version: str
    category: ToolCategory
    risk_level: RiskLevel
    description: str | None = None
    labels: dict[str, str] = Field(default_factory=dict)
    annotations: dict[str, str] = Field(default_factory=dict)


class KagentToolSpec(BasePydanticModel):
    """Specification for a Kagent tool."""
    description: str
    parameters: KagentCRDSchema
    outputs: KagentCRDSchema | None = None
    metadata: KagentMetadata
    examples: list[dict[str, Any]] = Field(default_factory=list)
    validation_rules: dict[str, Any] | None = None


class KagentTool(BasePydanticModel):
    """Root model for a Kagent tool definition."""
    apiVersion: str = Field(pattern=r"^kagent\.ai/v1(alpha\d+|beta\d+)?$")
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
    source_schema_version: str
    source_system: str
    conversion_timestamp: str
    validation_result: ValidationResult | None = None
    original_tool_name: str
    conversion_version: str
    semantic_score: float = Field(ge=0, le=1)
    field_mappings: dict[str, str] = Field(default_factory=dict)


class ConversionResult(BasePydanticModel):
    """Results of converting an MCP tool to Kagent format."""
    tool: KagentTool
    metadata: ConversionMetadataModel
    original_schema: dict[str, Any]  # The original MCP schema
    Represents a Kagent tool definition.
    Based on Kubernetes-style resource definition.
    """
    api_version: str = Field(default="tools.kagent.ai/v1")
=======
    parameters: KagentCRDSchema
    outputs: KagentCRDSchema | None = None
    metadata: KagentMetadata
    examples: list[dict[str, Any]] = Field(default_factory=list)
    validation_rules: dict[str, Any] | None = None


class KagentTool(BasePydanticModel):
    """Root model for a Kagent tool definition."""
    apiVersion: str = Field(pattern=r"^kagent\.ai/v1(alpha\d+|beta\d+)?$")
>>>>>>> main
    kind: str = Field(default="Tool")
    metadata: KagentMetadata
    spec: KagentToolSpec

<<<<<<< HEAD

class ConversionMetadataModel(BasePydanticModel):
    """Metadata about the tool conversion process."""
    original_tool_name: str
    conversion_timestamp: datetime.datetime
    conversion_version: str
    semantic_score: float = Field(ge=0, le=1)
    validation_results: ValidationResult
    field_mappings: dict[str, str] = Field(default_factory=dict)
=======
    @field_validator("kind")
    @classmethod
    def validate_kind(cls, v: str) -> str:
        """Validate 'kind' field."""
        if v != "Tool":
            raise ValueError("kind must be 'Tool'")
        return v


class ConversionMetadataModel(BasePydanticModel):
    """Metadata about the conversion process."""
    source_schema_version: str
    source_system: str
    conversion_timestamp: str
    validation_result: ValidationResult | None = None


class ConversionResult(BasePydanticModel):
    """Results of converting an MCP tool to Kagent format."""
    tool: KagentTool
    metadata: ConversionMetadataModel
    original_schema: dict[str, Any]  # The original MCP schema
>>>>>>> main
