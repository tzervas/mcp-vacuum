"""
Service responsible for converting MCP tool schemas to Kagent CRD format
and vice-versa, including validation and metadata enrichment.
"""
import json
import re
from typing import Any, Dict, List, Optional, Tuple
import datetime # For timestamping in metadata

import structlog
from pydantic import BaseModel, Field

from ..config import Config # For any conversion-related configs if added later
from ..models.mcp import MCPTool, MCPAnnotations, MCPServerInfo
from ..models.kagent import KagentTool, KagentMetadata, KagentToolSpec, KagentCRDSchema, ValidationIssue, ValidationResult, ValidationSeverity, ConversionMetadataModel
from ..models.common import ToolCategory, RiskLevel # Enums for categorization

logger = structlog.get_logger(__name__)

class ConversionServiceResult(BaseModel):
    kagent_tool: Optional[KagentTool] = None
    validation_issues: List[ValidationIssue] = Field(default_factory=list)
    conversion_metadata: Optional[ConversionMetadataModel] = None
    error_message: Optional[str] = None # For critical errors preventing conversion

    @property
    def has_errors(self) -> bool:
        return any(issue.severity == ValidationSeverity.ERROR for issue in self.validation_issues) or self.error_message is not None


class SchemaConverterService:
    """
    Provides functionalities for schema conversion, validation, and analysis
    as outlined in the "Schema Conversion & Mapping Guide".
    """

    def __init__(self, app_config: Config):
        self.app_config = app_config
        self.logger = logger.bind(service="SchemaConverterService")
        # TODO: Load field mappings, type mappings, category keywords, risk indicators if from external config
        # For now, some of these will be implemented directly or with simple defaults.

    def _sanitize_k8s_name(self, name: str, max_length: int = 63) -> str:
        """Sanitizes a string to be a Kubernetes-compliant name."""
        if not name:
            return "unnamed-tool" # Fallback for empty names

        # Convert to lowercase
        sanitized = name.lower()
        # Replace invalid characters (not alphanumeric or hyphen) with a hyphen
        sanitized = re.sub(r'[^a-z0-9-]', '-', sanitized)
        # Ensure it starts and ends with an alphanumeric character
        sanitized = re.sub(r'^[^a-z0-9]+', '', sanitized)
        sanitized = re.sub(r'[^a-z0-9]+$', '', sanitized)
        # Replace multiple consecutive hyphens with a single hyphen
        sanitized = re.sub(r'-+', '-', sanitized)
        # Truncate to max_length
        sanitized = sanitized[:max_length]
        # Final check if it became empty after sanitization (e.g. if original was just "---")
        if not sanitized:
            # Create a fallback name based on a hash or a generic prefix
            # For simplicity, using a generic fallback. A hash of original name might be better.
            return f"sanitized-tool-{abs(hash(name)) % 10000}"[:max_length]
        return sanitized

    def _to_camel_case(self, snake_str: str) -> str:
        """Converts snake_case or kebab-case to camelCase."""
        snake_str = snake_str.replace('-', '_') # Handle kebab-case first
        if '_' not in snake_str: # Already camelCase or flatcase
            if not snake_str or not snake_str[0].islower(): # if empty or starts with Upper (PascalCase)
                 return snake_str # return as is or convert Pascal to camel if desired
            return snake_str

        components = snake_str.split('_')
        # First component lowercase, subsequent capitalized.
        return components[0] + ''.join(x.capitalize() or '_' for x in components[1:])


    def _categorize_tool(self, mcp_tool: MCPTool) -> ToolCategory:
        """Categorizes the tool based on name, description, schema (simplified)."""
        # Simplified categorization logic for P0.
        # A more advanced version would use keywords, schema analysis, etc.
        desc = (mcp_tool.name + " " + mcp_tool.description).lower()
        if "file" in desc or "path" in desc or "directory" in desc:
            return ToolCategory.FILE_OPERATIONS
        if "http" in desc or "url" in desc or "network" in desc or "api" in desc:
            return ToolCategory.NETWORK_ACCESS # Could also be API_INTEGRATION
        if "shell" in desc or "command" in desc or "execute" in desc:
            return ToolCategory.SYSTEM_COMMANDS
        if "compute" in desc or "calculate" in desc:
            return ToolCategory.COMPUTATION
        # TODO: Add more sophisticated categorization logic
        return ToolCategory.UNKNOWN

    def _assess_risk_level(self, mcp_tool: MCPTool, category: ToolCategory) -> RiskLevel:
        """Assesses risk level (simplified)."""
        # Simplified risk assessment for P0.
        if category == ToolCategory.SYSTEM_COMMANDS:
            return RiskLevel.CRITICAL
        if mcp_tool.annotations and mcp_tool.annotations.destructive_hint:
            return RiskLevel.HIGH
        if category == ToolCategory.FILE_OPERATIONS and ("write" in mcp_tool.description.lower() or "delete" in mcp_tool.description.lower()):
            return RiskLevel.HIGH
        if category in [ToolCategory.NETWORK_ACCESS, ToolCategory.API_INTEGRATION]:
            return RiskLevel.MEDIUM
        # TODO: Add more sophisticated risk assessment
        return RiskLevel.LOW

    def _transform_json_schema_to_k8s_crd(self, json_schema: Dict[str, Any], is_output_schema: bool = False, mcp_tool_name: Optional[str] = None) -> KagentCRDSchema:
        """
        Converts a JSON Schema (Draft 7) to a Kubernetes CRD OpenAPI v3 compatible schema structure.
        This is a complex task. This implementation will be a simplified version for P0.
        - Removes unsupported keywords ($schema, $id).
        - Renames fields to camelCase if properties exist.
        - Recursively processes nested schemas (properties, items).
        """
        if not json_schema:
            return KagentCRDSchema(type="object", properties={}) # Kagent requires parameters to be an object

        k8s_schema_dict = json.loads(json.dumps(json_schema)) # Deep copy

        # Keywords to remove from top level and nested schemas
        # For $ref and definitions, we should warn, not just silently remove.
        unsupported_keywords = ["$schema", "$id", "const", "examples"] # examples is valid in openapi but often large

        has_refs_or_definitions = False

        def transform_node(node: Dict[str, Any]) -> Dict[str, Any]:
            nonlocal has_refs_or_definitions
            if not isinstance(node, dict):
                return node

            if "$ref" in node or "definitions" in node:
                has_refs_or_definitions = True
                node.pop("$ref", None)
                node.pop("definitions", None)

            for keyword in unsupported_keywords:
                node.pop(keyword, None)

            if "properties" in node and isinstance(node["properties"], dict):
                new_props = {}
                for name, prop_schema in node["properties"].items():
                    camel_case_name = self._to_camel_case(name)
                    new_props[camel_case_name] = transform_node(prop_schema)
                node["properties"] = new_props

            if "items" in node and isinstance(node["items"], dict): # For array items schema
                node["items"] = transform_node(node["items"])
            elif "items" in node and isinstance(node["items"], list): # For tuple validation (less common in CRDs)
                 node["items"] = [transform_node(item_schema) for item_schema in node["items"]]


            # Ensure 'type' is present if 'properties' or 'items' are, default to 'object' or 'array'
            if "properties" in node and "type" not in node:
                node["type"] = "object"
            if "items" in node and "type" not in node:
                node["type"] = "array"

            # Convert 'enum' for string types to have string values if they are not already
            if node.get("type") == "string" and "enum" in node:
                node["enum"] = [str(val) for val in node["enum"]]

            return node

        transformed_dict = transform_node(k8s_schema_dict)

        # Ensure the top-level schema is an object with properties for Kagent 'parameters'
        # Kagent spec expects 'parameters' (input) to be an object schema.
        # Output schemas can be any valid type.
        if not is_output_schema:
            if transformed_dict.get("type") != "object":
                 # If the input schema is not an object, it's problematic for typical CRD parameters.
                 # Kagent's spec.parameters is usually an object schema.
                 # Option 1: Wrap it (e.g. if string, make it {"type":"object", "properties":{"value":{"type":"string"}}}) - complex
                 # Option 2: Reject or log warning and return empty object schema.
                 # The guide mentioned: "Wrap single-property schemas in object containers"
                 # This suggests Option 1 for simple types.
                 # For now, let's be stricter for input and expect object, or return minimal valid.
                self.logger.warning(
                    "MCP input schema was not an object. Kagent parameters typically require an object schema.",
                    original_schema_type=transformed_dict.get("type"),
                    tool_name=mcp_tool_name or "UnknownTool"
                )
                # Return a minimal valid KagentCRDSchema (empty object) for parameters if original is not object.
                return KagentCRDSchema(type="object", properties={})

            if "properties" not in transformed_dict and transformed_dict.get("type") == "object":
                # Ensure an object schema has a properties field, even if empty
                transformed_dict["properties"] = {}

        # For output schemas, if it's not an object, that's fine.
        # e.g. a tool might output a simple string or number. KagentCRDSchema can represent this.

        if has_refs_or_definitions:
            self.logger.warning(
                "Schema transformation encountered and removed '$ref' or 'definitions' keywords.",
                details="Referenced schemas might be lost, leading to incomplete Kagent CRD. This tool does not currently support resolving external or internal references.",
                tool_name=mcp_tool_name or "UnknownTool",
                schema_context="output_schema" if is_output_schema else "input_schema"
            )

        return KagentCRDSchema.model_validate(transformed_dict)


    async def convert_mcp_tool_to_kagent(self, mcp_tool: MCPTool, server_info: MCPServerInfo) -> ConversionServiceResult:
        """
        Converts a single MCPTool to a KagentTool, including metadata and schema transformation.
        """
        log = self.logger.bind(mcp_tool_name=mcp_tool.name, server_id=server_info.id)
        log.debug("Starting conversion of MCPTool to KagentTool.")

        validation_issues: List[ValidationIssue] = [] # Collect validation issues here

        try:
            # 1. Metadata Conversion
            k8s_name = self._sanitize_k8s_name(f"{self._sanitize_k8s_name(server_info.name, 20)}-{self._sanitize_k8s_name(mcp_tool.name, 40)}", 63)
            category = self._categorize_tool(mcp_tool)
            risk = self._assess_risk_level(mcp_tool, category)

            metadata = KagentMetadata(
                name=k8s_name,
                labels={
                    "mcp.vacuum/source": "mcp-vacuum", # Indicate source
                    "mcp.vacuum/server-id": self._sanitize_k8s_name(server_info.id, 63),
                    "mcp.tool/original-name": self._sanitize_k8s_name(mcp_tool.name, 63), # Original name for reference
                    "kagent.dev/category": category.value,
                    "kagent.dev/risk-level": risk.value,
                },
                annotations={
                    "mcp.vacuum/original-tool-name": mcp_tool.name, # Full original name
                    "mcp.vacuum/server-name": server_info.name,
                    "mcp.vacuum/server-endpoint": str(mcp_tool.server_endpoint or server_info.endpoint),
                    "mcp.vacuum/conversion-timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                    "description": mcp_tool.description[:250] + ("..." if len(mcp_tool.description) > 250 else "") # K8s annotation length limits
                }
            )

            # 2. Schema Transformation
            kagent_input_schema = self._transform_json_schema_to_k8s_crd(
                mcp_tool.input_schema,
                is_output_schema=False,
                mcp_tool_name=mcp_tool.name
            )
            kagent_output_schema: Optional[KagentCRDSchema] = None
            if mcp_tool.output_schema:
                kagent_output_schema = self._transform_json_schema_to_k8s_crd(
                    mcp_tool.output_schema,
                    is_output_schema=True,
                    mcp_tool_name=mcp_tool.name
                )

            # 3. Tool Specification
            tool_spec = KagentToolSpec(
                type="mcp", # Indicating it's an MCP-originated tool
                description=mcp_tool.description,
                parameters=kagent_input_schema,
                output_schema=kagent_output_schema,
                mcpConfig={ # Store original MCP server and tool name for potential reverse conversion or direct invocation
                    "serverEndpoint": str(mcp_tool.server_endpoint or server_info.endpoint),
                    "toolName": mcp_tool.name
                }
            )

            # 4. Assemble KagentTool
            kagent_tool = KagentTool(metadata=metadata, spec=tool_spec)

            # 5. Validation (Simplified for P0)
            #    - Semantic preservation check (e.g., >80% field overlap - complex, deferred)
            #    - Structural validation (Pydantic does this on model creation)
            #    - K8s compatibility (names, lengths - partially handled by sanitization)
            if not kagent_input_schema.properties and mcp_tool.input_schema.get("properties"):
                # Check if the original schema actually had properties. It might have been a non-object schema.
                original_had_properties = isinstance(mcp_tool.input_schema.get("properties"), dict) and mcp_tool.input_schema.get("properties")

                if original_had_properties: # Only issue error if original schema *had* properties and now they are gone.
                    validation_issues.append(
                        ValidationIssue(
                            severity=ValidationSeverity.ERROR, # Changed from WARNING to ERROR
                            message="All input schema properties appear to have been lost during conversion. This could indicate a critical issue.",
                            field_path="spec.parameters"
                        )
                    )
                else:
                    # If original input schema was not an object or had no properties, it's not an error that kagent_input_schema has no properties.
                    # It might have been intentionally converted to an empty object schema if it was, e.g. a string.
                    # The _transform_json_schema_to_k8s_crd method logs a warning for non-object input schemas.
                    pass # No issue here if original didn't have properties

            # TODO: Implement more robust validation steps as per "Validation Pipeline" section of docs.

            log.info("MCPTool converted to KagentTool successfully.")

            # Create ConversionMetadataModel (placeholder for now)
            # This would require more detailed field mapping and semantic score calculation.
            conv_meta = ConversionMetadataModel(
                original_tool_name=mcp_tool.name,
                conversion_timestamp=datetime.datetime.utcnow(),
                conversion_version=self.app_config.agent_version if hasattr(self.app_config, "agent_version") else "0.1.0", # Get version from app_config
                semantic_score=0.85, # Placeholder
                validation_results=ValidationResult(is_valid=not any(i.severity == ValidationSeverity.ERROR for i in validation_issues), issues=validation_issues, schema_hash="placeholder_hash"),
                field_mappings={} # Placeholder for field name mappings
            )


            return ConversionServiceResult(kagent_tool=kagent_tool, validation_issues=validation_issues, conversion_metadata=conv_meta)

        except Exception as e:
            log.exception("Error during MCPTool to KagentTool conversion.", error=str(e))
            return ConversionServiceResult(error_message=f"Conversion failed: {str(e)}", validation_issues=validation_issues)

    async def convert_kagent_to_mcp_tool(self, kagent_tool: KagentTool) -> Optional[MCPTool]:
        """
        Converts a KagentTool back to an MCPTool (Simplified for P0).
        """
        self.logger.warning("KagentTool to MCPTool conversion is not fully implemented for P0.")
        # Basic reverse mapping based on mcpConfig and annotations
        if kagent_tool.spec.type == "mcp" and kagent_tool.spec.mcp_config:
            original_name = kagent_tool.spec.mcp_config.get("toolName")
            server_endpoint = kagent_tool.spec.mcp_config.get("serverEndpoint")
            if not original_name:
                original_name = kagent_tool.metadata.annotations.get("mcp.vacuum/original-tool-name", kagent_tool.metadata.name)

            # TODO: Reverse schema transformation (K8s CRD to JSON Schema Draft 7)
            # This is also complex and involves reversing camelCase, handling k8s specific extensions.
            # For P0, we might just return the name and description.
            return MCPTool(
                name=original_name,
                description=kagent_tool.spec.description,
                input_schema={}, # Placeholder - requires reverse schema transform
                output_schema=None, # Placeholder
                server_endpoint=server_endpoint
            )
        return None

# This service is a work-in-progress for P0.
# Key areas for future development:
# - More sophisticated JSON Schema to K8s CRD transformation (handling all keywords, $refs, definitions).
# - Robust validation pipeline (semantic preservation, detailed K8s compatibility checks).
# - Advanced tool categorization and risk assessment using NLP or more detailed heuristics.
# - Full implementation of Kagent back to MCP conversion.
# - Loading configurations for mappings/keywords externally.
# The `app_config` needs an `agent_version` attribute for ConversionMetadataModel.
# Added `server_info` to `convert_mcp_tool_to_kagent` for context like server name/ID if mcp_tool doesn't have it.
# The `ConversionServiceResult` now includes `conversion_metadata`.
# Sanitized K8s name generation to be more robust for potentially empty or invalid inputs.
# Placeholder for `self.app_config.agent_version`. This needs to be added to `Config` model.
