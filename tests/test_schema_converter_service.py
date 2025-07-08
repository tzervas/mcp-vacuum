"""
Unit tests for SchemaConverterService.
"""
from typing import Any, Dict, Optional

import pytest  # type: ignore[import-not-found]

from mcp_vacuum.config import Config
from mcp_vacuum.models.common import RiskLevel, ToolCategory
from mcp_vacuum.models.kagent import KagentTool
from mcp_vacuum.models.mcp import MCPAnnotations, MCPServerInfo, MCPTool

from mcp_vacuum.schema_gen.schema_converter_service import (
    ConversionServiceResult,
    SchemaConverterService,
)


@pytest.fixture
def app_config() -> Config:
    # Add agent_version to config for testing metadata
    return Config(agent_version="test-v0.1")

@pytest.fixture
def converter_service(app_config: Config) -> SchemaConverterService:
    return SchemaConverterService(app_config=app_config)

@pytest.fixture
def sample_mcp_tool() -> MCPTool:
    return MCPTool(
        name="My.Example-Tool_1",
        description="This is a test tool that does amazing things.",
        input_schema={
            "type": "object",
            "properties": {
                "param_one": {"type": "string", "description": "First parameter"},
                "paramTwo": {"type": "integer", "description": "Second parameter (already camel)"},
                "another_long_param_name": {"type": "boolean"}
            },
            "required": ["param_one"]
        },
        output_schema={
            "type": "object",
            "properties": {
                "result_value": {"type": "string"}
            }
        },
        server_endpoint="http://mcp.example.com/server1",
        annotations=MCPAnnotations(destructive_hint=False, read_only_hint=True)
    )

@pytest.fixture
def sample_server_info() -> MCPServerInfo:
    return MCPServerInfo(
        id="server-guid-123",
        name="PrimaryMCP",
        endpoint="http://mcp.example.com/server1", # Ensure this matches tool's server_endpoint or is a fallback
        registration_endpoint="http://mcp.example.com/register" # Not used by converter but part of model
    )

# --- Test Helper Methods ---

def test_sanitize_k8s_name(converter_service: SchemaConverterService) -> None:
    assert converter_service._sanitize_k8s_name("My.Tool_Name!") == "my-tool-name"
    assert converter_service._sanitize_k8s_name("123Tool-Name") == "123tool-name" # Starts with num is ok
    assert converter_service._sanitize_k8s_name("tool-name-") == "tool-name" # Trailing hyphen
    assert converter_service._sanitize_k8s_name("-tool-name") == "tool-name" # Leading hyphen
    assert converter_service._sanitize_k8s_name("a" * 70) == "a" * 63 # Max length
    assert converter_service._sanitize_k8s_name("!@#$%^") == f"sanitized-tool-{abs(hash('!@#$%^')) % 10000}" # All invalid
    assert converter_service._sanitize_k8s_name("") == "unnamed-tool"
    assert converter_service._sanitize_k8s_name("valid-name") == "valid-name"
    assert converter_service._sanitize_k8s_name("tool_with_underscores") == "tool-with-underscores"


def test_to_camel_case(converter_service: SchemaConverterService) -> None:
    assert converter_service._to_camel_case("snake_case_example") == "snakeCaseExample"
    assert converter_service._to_camel_case("kebab-case-example") == "kebabCaseExample"
    assert converter_service._to_camel_case("alreadyCamelCase") == "alreadyCamelCase"
    assert converter_service._to_camel_case("PascalCase") == "PascalCase" # Or convert to "pascalCase" if desired
    assert converter_service._to_camel_case("single") == "single"
    assert converter_service._to_camel_case("_leading_underscore") == "LeadingUnderscore" # or "leadingUnderscore" if preferred
    assert converter_service._to_camel_case("param_one") == "paramOne"
    assert converter_service._to_camel_case("paramTwo") == "paramTwo" # Already camel

# --- Test Categorization and Risk Assessment (Basic) ---

def test_categorize_tool(
    converter_service: SchemaConverterService, sample_mcp_tool: MCPTool
) -> None:
    # Based on current simple logic in service
    assert converter_service._categorize_tool(sample_mcp_tool) == ToolCategory.UNKNOWN # Default fallback

    tool_file = MCPTool(name="ReadFile", description="Reads a file from path.", input_schema={})
    assert converter_service._categorize_tool(tool_file) == ToolCategory.FILE_OPERATIONS

    tool_http = MCPTool(name="GetHttp", description="Makes an HTTP GET request to a URL.", input_schema={})
    assert converter_service._categorize_tool(tool_http) == ToolCategory.NETWORK_ACCESS


def test_assess_risk_level(converter_service: SchemaConverterService) -> None:
    tool_cmd = MCPTool(name="RunCommand", description="Executes a shell command.", input_schema={})
    cat_cmd = converter_service._categorize_tool(tool_cmd) # Expected SYSTEM_COMMANDS
    assert converter_service._assess_risk_level(tool_cmd, cat_cmd) == RiskLevel.CRITICAL

    tool_destructive = MCPTool(name="DeleteFile", description="Deletes a file.", input_schema={}, annotations=MCPAnnotations(destructive_hint=True))
    cat_file = ToolCategory.FILE_OPERATIONS
    assert converter_service._assess_risk_level(tool_destructive, cat_file) == RiskLevel.HIGH

    tool_readonly = MCPTool(name="ReadFile", description="Reads a file.", input_schema={}, annotations=MCPAnnotations(read_only_hint=True))
    assert converter_service._assess_risk_level(tool_readonly, cat_file) == RiskLevel.LOW


# --- Test Schema Transformation (_transform_json_schema_to_k8s_crd) ---

@pytest.mark.parametrize("mcp_schema, expected_k8s_props", [
    ({"type": "object", "properties": {"first_name": {"type": "string"}}}, {"firstName": {"type": "string"}}),
    ({"type": "object", "properties": {"alreadyCamel": {"type": "integer"}}}, {"alreadyCamel": {"type": "integer"}}),
    ({"type": "object", "properties": {"nested_obj": {"type": "object", "properties": {"child_prop": {"type": "boolean"}}}}},
     {"nestedObj": {"type": "object", "properties": {"childProp": {"type": "boolean"}}}}),
    ({"type": "array", "items": {"type": "object", "properties": {"item_id": {"type": "number"}}}},
     None), # This case tests top-level array, _transform ensures input params are object.
    ({"type": "string", "description": "A simple string input"}, None), # Also non-object input.
    ({"type": "object", "properties": {}}, {}), # Empty properties
])
def test_transform_json_schema_to_k8s_crd_input_params(
    converter_service: SchemaConverterService,
    mcp_schema: dict[str, Any],
    expected_k8s_props: dict[str, Any] | None,
    sample_mcp_tool: MCPTool,
) -> None:
    """Test input schema transformation (must result in an object schema for parameters)."""
    kagent_schema = converter_service._transform_json_schema_to_k8s_crd(mcp_schema, is_output_schema=False, mcp_tool_name=sample_mcp_tool.name)

    assert kagent_schema.type == "object" # Input parameters schema must be object
    if expected_k8s_props is not None:
        assert kagent_schema.properties == expected_k8s_props
    else:
        # If original was not object, expect empty properties for Kagent input schema
        assert kagent_schema.properties == {}


def test_transform_json_schema_to_k8s_crd_output_schema(
    converter_service: SchemaConverterService, sample_mcp_tool: MCPTool
) -> None:
    """Test output schema transformation (can be non-object)."""
    mcp_output_string = {"type": "string", "description": "The result is a string."}
    kagent_output_string = converter_service._transform_json_schema_to_k8s_crd(mcp_output_string, is_output_schema=True, mcp_tool_name=sample_mcp_tool.name)
    assert kagent_output_string.type == "string"
    assert kagent_output_string.description == "The result is a string."
    assert kagent_output_string.properties is None

    mcp_output_obj = {"type": "object", "properties": {"data_value": {"type": "number"}}}
    kagent_output_obj = converter_service._transform_json_schema_to_k8s_crd(mcp_output_obj, is_output_schema=True, mcp_tool_name=sample_mcp_tool.name)
    assert kagent_output_obj.type == "object"
    assert kagent_output_obj.properties == {"dataValue": {"type": "number"}}


# --- Test Main Conversion Method (convert_mcp_tool_to_kagent) ---

@pytest.mark.asyncio
async def test_convert_mcp_tool_to_kagent_success(
    converter_service: SchemaConverterService,
    sample_mcp_tool: MCPTool,
    sample_server_info: MCPServerInfo,
) -> None:
    result: ConversionServiceResult = await converter_service.convert_mcp_tool_to_kagent(sample_mcp_tool, sample_server_info)

    assert result.kagent_tool is not None
    assert not result.has_errors
    assert result.error_message is None
    assert len(result.validation_issues) == 0 # Basic P1 validation might not find issues

    ktool: KagentTool = result.kagent_tool

    # Metadata checks
    expected_k8s_name_prefix = f"{converter_service._sanitize_k8s_name(sample_server_info.name, 20)}-{converter_service._sanitize_k8s_name(sample_mcp_tool.name, 40)}"
    assert ktool.metadata.name.startswith(expected_k8s_name_prefix[:63]) # Check sanitized name
    assert ktool.metadata.labels["kagent.dev/category"] == ToolCategory.UNKNOWN.value # Based on simple categorizer
    assert ktool.metadata.labels["kagent.dev/risk-level"] == RiskLevel.LOW.value # Based on simple risk assessment
    assert ktool.metadata.annotations["mcp.vacuum/original-tool-name"] == sample_mcp_tool.name

    # Spec checks
    assert ktool.spec.type == "mcp"
    assert ktool.spec.description == sample_mcp_tool.description
    assert ktool.spec.mcp_config["toolName"] == sample_mcp_tool.name
    assert ktool.spec.mcp_config["serverEndpoint"] == str(sample_mcp_tool.server_endpoint)

    # Input parameters schema checks
    assert ktool.spec.parameters.type == "object"
    assert "paramOne" in ktool.spec.parameters.properties
    assert ktool.spec.parameters.properties["paramOne"]["type"] == "string"
    assert "paramTwo" in ktool.spec.parameters.properties # Already camel
    assert ktool.spec.parameters.properties["paramTwo"]["type"] == "integer"
    assert "anotherLongParamName" in ktool.spec.parameters.properties
    assert ktool.spec.parameters.properties["anotherLongParamName"]["type"] == "boolean"
    # Required fields are not yet transformed/mapped in P1 _transform_json_schema_to_k8s_crd
    # assert "paramOne" in ktool.spec.parameters.required

    # Output schema checks
    assert ktool.spec.output_schema.type == "object"
    assert "resultValue" in ktool.spec.output_schema.properties
    assert ktool.spec.output_schema.properties["resultValue"]["type"] == "string"

    # Conversion Metadata checks
    assert result.conversion_metadata is not None
    assert result.conversion_metadata.original_tool_name == sample_mcp_tool.name
    assert result.conversion_metadata.semantic_score == 0.85 # Placeholder


@pytest.mark.asyncio
async def test_convert_mcp_tool_input_schema_not_object(
    converter_service: SchemaConverterService, sample_server_info: MCPServerInfo
) -> None:
    """Test conversion when MCP input schema is not an object."""
    tool_string_input = MCPTool(
        name="StringTool",
        description="Takes a string.",
        input_schema={"type": "string"}, # Not an object
        output_schema={"type": "string"},
        server_endpoint=sample_server_info.endpoint
    )
    result = await converter_service.convert_mcp_tool_to_kagent(tool_string_input, sample_server_info)

    assert result.kagent_tool is not None
    ktool = result.kagent_tool

    # _transform_json_schema_to_k8s_crd forces input params to be an object schema,
    # potentially empty if original was not suitable.
    assert ktool.spec.parameters.type == "object"
    assert ktool.spec.parameters.properties == {} # Became empty object schema

    # A warning should have been logged by the service, not easily testable here without capturing logs.
    # Validation issues might also reflect this.
    # For P1, we are not populating validation_issues extensively for this specific case in the service.
    # assert any("input schema was not an object" in issue.message for issue in result.validation_issues)


# TODO: Add more tests for SchemaConverterService:
# - Different schema types (array, number, boolean at top level for output).
# - Schemas with no properties.
# - Deeper nesting and arrays of objects in schemas.
# - Validation issue generation for specific scenarios (e.g., if a required field transformation fails).
# - Kagent to MCP conversion (when implemented).
# - More nuanced categorization and risk assessment tests.
