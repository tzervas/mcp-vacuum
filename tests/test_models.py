"""
Unit tests for Pydantic models in src/mcp_vacuum/models/
"""
import time

import pytest
from pydantic import ValidationError

from mcp_vacuum.models.auth import (
    OAuth2Token,
    PKCEChallenge,
)
from mcp_vacuum.models.common import (
    AuthenticationMetadata,
    AuthMethod,
    MCPCapability,
    MCPCapabilityType,
    TransportType,
)
from mcp_vacuum.models.kagent import (
    KagentCRDSchema,
    KagentMetadata,
    KagentTool,
    KagentToolSpec,
    ValidationIssue,
    ValidationResult,
    ValidationSeverity,
)
from mcp_vacuum.models.mcp import (
    MCPAnnotations,
    MCPServiceRecord,
    MCPTool,
)

# --- Auth Models Tests ---

def test_oauth2token_is_expired():
    """Test OAuth2Token.is_expired property."""
    # Token created now, expires in 1 hour (3600s)
    token_valid = OAuth2Token(access_token="valid_token", expires_in=3600)
    assert not token_valid.is_expired

    # Token created 1 hour ago, expires in 1 hour (should be expired due to 60s buffer)
    one_hour_ago = time.time() - 3600
    token_expired_by_buffer = OAuth2Token(access_token="expired_token_buffer", expires_in=3600, created_at=one_hour_ago)
    assert token_expired_by_buffer.is_expired

    # Token created 2 hours ago, expires in 1 hour (definitely expired)
    two_hours_ago = time.time() - 7200
    token_definitely_expired = OAuth2Token(access_token="expired_token_def", expires_in=3600, created_at=two_hours_ago)
    assert token_definitely_expired.is_expired

    # Token with no expires_in (should not be considered expired by this logic)
    token_no_expiry = OAuth2Token(access_token="no_expiry_token", expires_in=None)
    assert not token_no_expiry.is_expired
    assert token_no_expiry.expires_at is None

    # Token that expires exactly now (considering buffer)
    token_expires_now_ish = OAuth2Token(access_token="exp_now", expires_in=60, created_at=time.time() - 59) # Expires in 1s, buffer makes it valid
    assert not token_expires_now_ish.is_expired

    token_expires_past_buffer = OAuth2Token(access_token="exp_now_b", expires_in=30, created_at=time.time() - 29) # Expires in 1s, buffer makes it valid
    assert not token_expires_past_buffer.is_expired

    # expires_at property
    current_time = time.time()
    token_with_expires_at = OAuth2Token(access_token="valid_token", expires_in=1000, created_at=current_time)
    assert token_with_expires_at.expires_at == pytest.approx(current_time + 1000)


def test_pkce_challenge_validation():
    """Test PKCEChallenge model validation (though it's mostly for data holding)."""
    pkce = PKCEChallenge(code_verifier="v", code_challenge="c", code_challenge_method="S256")
    assert pkce.code_verifier == "v" # Pydantic performs basic assignment checks
    with pytest.raises(ValidationError): # min_length validation
        PKCEChallenge(code_verifier="short", code_challenge="c", code_challenge_method="S256")


# --- MCP Models Tests ---

def test_mcp_service_record_creation():
    """Test basic creation and HttpUrl validation for MCPServiceRecord."""
    record = MCPServiceRecord(
        id="server1", name="Test Server", endpoint="http://localhost:8080",
        transport_type=TransportType.HTTP, version="1.1", discovery_method="manual"
    )
    assert record.endpoint.scheme == "http"
    assert record.endpoint.host == "localhost"
    assert record.endpoint.port == 8080

    with pytest.raises(ValidationError):
        MCPServiceRecord(id="s2", name="Bad Endpoint", endpoint="not_a_url", discovery_method="test")

def test_mcp_tool_creation():
    """Test MCPTool creation with required schema fields."""
    tool = MCPTool(
        name="calculator.add",
        description="Adds two numbers.",
        input_schema={"type": "object", "properties": {"a": {"type": "number"}, "b": {"type": "number"}}},
        output_schema={"type": "object", "properties": {"result": {"type": "number"}}}
    )
    assert tool.input_schema["properties"]["a"]["type"] == "number"

    with pytest.raises(ValidationError): # name is required
        MCPTool(description="desc", input_schema={})
    with pytest.raises(ValidationError): # input_schema is required
        MCPTool(name="tool", description="desc")

# --- Kagent Models Tests ---

def test_kagent_tool_creation():
    """Test KagentTool creation with nested models."""
    metadata = KagentMetadata(name="my-kagent-tool", labels={"category": "math"})
    input_params_schema = KagentCRDSchema(type="object", properties={"x": {"type": "integer"}})
    spec = KagentToolSpec(description="A kagent tool", parameters=input_params_schema)
    ktool = KagentTool(metadata=metadata, spec=spec)

    assert ktool.metadata.name == "my-kagent-tool"
    assert ktool.spec.parameters.properties["x"]["type"] == "integer"
    assert ktool.api_version == "tools.kagent.ai/v1" # Default value

def test_kagent_crd_schema_extra_fields():
    """Test KagentCRDSchema allows extra fields (as JSON schema can be flexible)."""
    schema_data = {
        "type": "object",
        "properties": {"name": {"type": "string", "minLength": 3}},
        "required": ["name"],
        "x-kubernetes-preserve-unknown-fields": True # Example of an allowed extra field
    }
    k_schema = KagentCRDSchema.model_validate(schema_data)
    assert k_schema.properties["name"]["minLength"] == 3
    assert k_schema.model_extra is not None
    assert k_schema.model_extra["x-kubernetes-preserve-unknown-fields"] is True

# --- Common Models Tests ---

def test_enum_usage_in_models():
    """Test that enums are correctly used and validated in models."""
    # Example using MCPServiceRecord with AuthMethod enum
    record = MCPServiceRecord(
        id="s_enum", name="Enum Test", endpoint="http://example.com",
        auth_method="oauth2_pkce", # String value that matches enum member
        discovery_method="test"
    )
    assert record.auth_method == AuthMethod.OAUTH2_PKCE # Value is converted to Enum member

    with pytest.raises(ValidationError): # Invalid enum value
         MCPServiceRecord(
            id="s_enum_bad", name="Enum Test Bad", endpoint="http://example.com",
            auth_method="invalid_auth_method", discovery_method="test"
        )

def test_mcp_capability_type():
    cap = MCPCapability(type=MCPCapabilityType.TOOLS, details={"tool_names": ["tool1"]})
    assert cap.type == MCPCapabilityType.TOOLS

# --- Model Field Defaults ---
def test_model_field_defaults():
    """Test default values for various model fields."""
    auth_meta_def = AuthenticationMetadata(method=AuthMethod.NONE) # Only required field
    assert auth_meta_def.scopes_supported is None

    mcp_anno_def = MCPAnnotations()
    assert mcp_anno_def.read_only_hint is None

    # KagentTool defaults were tested in test_kagent_tool_creation
    ktool_def = KagentTool(
        metadata=KagentMetadata(name="def-tool"),
        spec=KagentToolSpec(description="def spec", parameters=KagentCRDSchema(type="object", properties={}))
    )
    assert ktool_def.kind == "Tool"

# --- ValidationResult and ValidationIssue ---
def test_validation_result():
    vr_ok = ValidationResult(is_valid=True, issues=[])
    assert not vr_ok.has_errors

    vr_warn = ValidationResult(is_valid=True, issues=[ValidationIssue(severity=ValidationSeverity.WARNING, message="warn", field_path="f")])
    assert not vr_warn.has_errors

    vr_err = ValidationResult(is_valid=False, issues=[ValidationIssue(severity=ValidationSeverity.ERROR, message="err", field_path="f")])
    assert vr_err.has_errors

# More tests can be added for specific validation rules if models have custom validators,
# or for more complex default factory scenarios.
# Pydantic itself tests most of the basic validation logic (type checks, required fields).
# These tests primarily focus on application-specific logic within models (like is_expired)
# and correct usage of enums/nesting.
