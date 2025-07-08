"""Module for Kagent-related models and schema validation."""
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, validator
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
    description: Optional[str] = None
    labels: Dict[str, str] = Field(default_factory=dict)
    annotations: Dict[str, str] = Field(default_factory=dict)

class KagentToolSpec(BasePydanticModel):
    """Specification for a Kagent tool."""
    description: str
    parameters: KagentCRDSchema
    outputs: Optional[KagentCRDSchema] = None
    metadata: KagentMetadata
    examples: List[Dict[str, Any]] = Field(default_factory=list)
    validation_rules: Optional[Dict[str, Any]] = None

class KagentTool(BasePydanticModel):
    """Root model for a Kagent tool definition.
    Based on Kubernetes-style resource definition.
    """
    apiVersion: str = Field(pattern=r"^kagent\.ai/v1(alpha\d+|beta\d+)?$")
    kind: str = Field(default="Tool")
    metadata: KagentMetadata
    spec: KagentToolSpec

    @validator("kind")
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
    validation_result: Optional[ValidationResult] = None
    original_tool_name: str
    conversion_version: str
    semantic_score: float = Field(ge=0, le=1)
    field_mappings: Dict[str, str] = Field(default_factory=dict)

class ConversionResult(BasePydanticModel):
    """Results of converting an MCP tool to Kagent format."""
    tool: KagentTool
    metadata: ConversionMetadataModel
    original_schema: Dict[str, Any]  # The original MCP schema
