# MCP Vacuum Project Specification

## Project Overview

MCP Vacuum is a Python 3.12-based AI agent designed to automate the discovery of MCP (Model Context Protocol) servers on a local network, authenticate using OAuth 2.1 with PKCE, retrieve tool schemas, and convert them into Kagent-compliant CRD formats for integration into Kagent workflows. Built with Google Python Agent Development Kit (ADK) principles, it features a hierarchical agent architecture for modularity and scalability.

### Project Goals

- **Primary Objectives**:
  - Automatically discover MCP servers using multiple protocols (mDNS, with SSDP planned).
  - Authenticate securely with discovered servers using OAuth 2.1 + PKCE and dynamic client registration (RFC 7591).
  - Retrieve MCP tool schemas and convert them into Kagent CRD format (Agent, ToolServer, ModelConfig).
  - Deliver a production-ready agent deployable on Google Cloud with Vertex AI integration.
  - Provide comprehensive documentation, testing, and DevOps integration.

## Technical Requirements

### Discovery
- **Protocols**: 
  - Implement mDNS for initial service discovery using `python-zeroconf`.
  - Plan SSDP integration for broader compatibility (e.g., Windows environments).
- **Features**:
  - Cache discovery results with a configurable TTL (default: 600 seconds).
  - Support concurrent scanning with resource limits (e.g., max 50 workers).
  - Filter discovered servers by allowed networks (e.g., "192.168.1.0/24").
  - Async DNS resolution for improved performance.
  - Support for overlapping discovery runs with proper resource management.
- **Output**: List of MCP servers with connection details (e.g., `MCPServiceRecord`).

### Authentication
- **Method**: OAuth 2.1 with PKCE (RFC 7636).
- **Features**:
  - Dynamic client registration per RFC 7591.
  - Secure token storage using system keyring (default) or encrypted file storage with enhanced error handling.
  - Automatic token refresh with short-lived access tokens (15-60 minutes).
  - Fixed 128-character PKCE verifiers for optimal security.
- **Security**:
  - Exact redirect URI validation.
  - State parameter for CSRF protection.
  - Memory-only storage for access tokens.

### MCP Interaction
- **Protocol**: JSON-RPC 2.0 over HTTP.
- **Operations**:
  - List available tools via `listTools` method.
  - Retrieve tool schemas using `getToolSchema` method.
- **Resilience**:
  - Implement retry mechanisms with exponential backoff.
  - Use circuit breakers (e.g., failure threshold: 3, recovery timeout: 20 seconds).

### Schema Conversion
- **Input**: MCP tool schemas in JSON Schema Draft 7.
- **Output**: Kagent CRDs in OpenAPI v3 (YAML format).
- **Features**:
  - Fail-fast option for immediate error reporting during conversion.
  - Standardized PEP 604 type annotations for better code quality.
- **Conversion Mapping**:
  - **MCP Server → Kagent ToolServer**:
    - `server.name` → `metadata.name`: Lowercase, Kubernetes-compliant (e.g., `mcp-server-1`).
    - `server.description` → `spec.description`: Direct mapping.
    - Server URL → `spec.config`: Map based on transport (e.g., `sse.url`, `websocket.url`, `stdio`).
    - Tools: Discovered dynamically at runtime, not statically defined.
  - **MCP Tool → Kagent Agent Tool Reference**:
    - `tool.name` → `tools[].mcpServer.toolNames[]`: Array of sanitized tool names.
    - Tool Server Reference: Link to generated `ToolServer` CRD name.
    - `type`: Set to `"McpServer"`.
- **Additional Features**:
  - **Metadata Enrichment**: Add labels (e.g., `mcp.source: "converted"`) and annotations (e.g., `mcp.conversion.timestamp`).
  - **Validation**: Ensure CRDs are valid Kubernetes resources using a multi-stage validation pipeline.
  - **Tool Categorization**: Categorize tools (e.g., `network-access`, `data-processing`) using `ToolAnalyzer`.
  - **Risk Assessment**: Assign risk levels (e.g., `low`, `medium`, `high`, `critical`) based on schema analysis.

### Output
- **Format**: Generate Kagent CRD YAML files for `ToolServer` and `Agent` resources.
- **Options**: Output to file (e.g., `mcp_kagent_schemas.yaml`) or stdout.

### Architecture
- **Hierarchical Agent System**:
  - `OrchestrationAgent`: Coordinates workflow and manages child agents.
  - `DiscoveryAgent`: Handles network scanning and server detection.
  - `AuthenticationAgent`: Manages OAuth flows and token lifecycle.
  - `MCPClientAgent`: Communicates with MCP servers via JSONRPC.
  - `ConversionAgent`: Performs schema transformation and validation.
- **Event-Driven**: Use `asyncio.Queue` for inter-agent communication.
- **Modularity**: Ensure components are reusable and independently testable.

### DevOps Integration
- **Package Management**: Use `uv` for dependency management.
- **CI/CD**: Implement pipelines with GitHub Actions for testing, linting, and deployment.
- **Containerization**: Provide a `Dockerfile.prod` for production deployment.
- **Cloud Deployment**: Integrate with Google Cloud Vertex AI, including auto-scaling and monitoring.

## Success Criteria

### Functional
- Discover and authenticate with MCP servers on the local network.
- Convert MCP tool schemas to Kagent CRD format with 100% semantic preservation.
- Generate valid Kubernetes CRDs deployable to a cluster.

### Performance
- Discover 100+ hosts in under 30 seconds.
- Convert schemas in under 100ms per tool for typical configurations.
- Maintain memory usage below 50MB during typical operations.

### Quality
- Achieve 95%+ test coverage for core logic using `pytest` and `pytest-asyncio`.
- Ensure full compliance with OAuth_LIGHTBOX2.1 and PKCE standards.
- Provide comprehensive documentation (e.g., README, architecture guides) and structured logging via `structlog`.

## Timeline Estimate
- **MVP (P0)**: 3-4 weeks (core discovery, authentication, basic conversion).
- **Feature Complete**: 6-8 weeks (full feature set, testing, optimization).
- **Production Ready**: 10-12 weeks (deployment, monitoring, security hardening).

## Implementation Considerations
- **Schema Validation**: Validate MCP schemas and generated CRDs at each conversion step.
- **Error Handling**: Handle invalid MCP specs, name conflicts, and transport errors gracefully.
- **Testing**: Include unit tests, integration tests with mock MCP servers, and end-to-end tests in Kubernetes.
- **Security**: Encrypt refresh tokens, restrict network scanning to allowed ranges, and follow OAuth best practices.

This specification ensures MCP Vacuum aligns with the latest Kagent CRD schemas and provides a robust solution for integrating MCP servers and tools into Kagent workflows.