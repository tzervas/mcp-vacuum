"""
Kagent model definitions for MCP-Vacuum.
"""
import datetime
from enum import Enum

from pydantic import Field

from .common import BasePydanticModel


class ValidationSeverity(str, Enum):
    """Severity levels for validation issues."""
    ERROR = "error"
    WARNING = "warning"


class ValidationIssue(BasePydanticModel):
    """Represents a single validation issue."""
    severity: ValidationSeverity
    message: str
    field_path: str


class ValidationResult(BasePydanticModel):
    """Result of a validation operation."""
    is_valid: bool
    issues: list[ValidationIssue] = Field(default_factory=list)

    @property
    def has_errors(self) -> bool:
        """Check if there are any error-level issues."""
        return any(issue.severity == ValidationSeverity.ERROR for issue in self.issues)


class KagentMetadata(BasePydanticModel):
    """Metadata for a Kagent tool."""
    name: str
    labels: dict[str, str] = Field(default_factory=dict)


class KagentCRDSchema(BasePydanticModel):
    """
    Schema for Kagent Custom Resource Definition.
    This is a flexible schema that allows additional fields.
    """
    type: str
    properties: dict[str, dict] = Field(default_factory=dict)
    required: list[str] = Field(default_factory=list)

    class Config:
        extra = "allow"  # Allow extra fields for JSON Schema flexibility


class KagentToolSpec(BasePydanticModel):
    """Specification for a Kagent tool."""
    description: str
    parameters: KagentCRDSchema


class KagentTool(BasePydanticModel):
    """
    Represents a Kagent tool definition.
    Based on Kubernetes-style resource definition.
    """
    api_version: str = Field(default="tools.kagent.ai/v1")
    kind: str = Field(default="Tool")
    metadata: KagentMetadata
    spec: KagentToolSpec


class ConversionMetadataModel(BasePydanticModel):
    """Metadata about the tool conversion process."""
    original_tool_name: str
    conversion_timestamp: datetime.datetime
    conversion_version: str
    semantic_score: float = Field(ge=0, le=1)
    validation_results: ValidationResult
    field_mappings: dict[str, str] = Field(default_factory=dict)
