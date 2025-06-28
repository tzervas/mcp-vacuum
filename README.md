# MCP Vacuum

MCP Vacuum is an AI agent developed in Python 3.12, designed to automatically discover MCP (Model Context Protocol) servers, manage authentication (including OAuth 2.1 with PKCE), and convert their tool schemas into Kagent-compliant formats. It is built using an architecture inspired by the Google Python Agent Developer Kit (ADK) principles, featuring a hierarchical system of specialized agents.

## Overview

The MCP Vacuum agent performs a sequence of operations:
1.  **Discovery**: Scans the local network using protocols like mDNS (SSDP planned) to find active MCP servers.
2.  **Authentication**: For each discovered server, it attempts to authenticate. This primarily uses OAuth 2.1 with PKCE, supporting dynamic client registration (RFC 7591). Tokens are securely stored (e.g., via system keyring) and managed with auto-refresh.
3.  **MCP Interaction**: Once authenticated, it communicates with the MCP server (via JSONRPC 2.0 over HTTP) to list available tools and retrieve their schemas.
4.  **Schema Conversion**: The MCP tool schemas (JSON Schema Draft 7) are then transformed into Kagent Custom Resource Definition (CRD) compatible format (OpenAPI v3). This includes metadata mapping, name sanitization, categorization, and risk assessment.
5.  **Output**: The Kagent schemas can then be used to integrate MCP tools into Kagent-based workflows.

The agent is designed with resilience, featuring retry mechanisms and circuit breakers for external communications.

## ✨ Key Features

*   **Automated Network Discovery**: Employs mDNS for discovering MCP servers (SSDP planned).
*   **Secure OAuth 2.1 Authentication**: Implements Authorization Code Flow with PKCE (RFC 7636) and Dynamic Client Registration (RFC 7591).
*   **Secure Token Management**: Securely stores OAuth tokens (using system keyring by default) with automatic refresh capabilities.
*   **JSONRPC 2.0 Client**: Robust client for interacting with MCP servers over HTTP, with built-in retries and circuit breaker.
*   **Schema Conversion Engine**: Transforms MCP tool schemas (JSON Schema) to Kagent CRD format (OpenAPI v3), including:
    *   Metadata mapping (labels, annotations).
    *   Kubernetes-compliant name sanitization.
    *   Tool categorization and risk assessment.
*   **ADK-inspired Architecture**: Modular design with an `OrchestrationAgent` coordinating specialized child agents for discovery, authentication, communication, and conversion.
*   **Configurable**: Behavior can be customized via environment variables or a JSON configuration file.
*   **Containerized**: Production Dockerfile provided for easy deployment.
*   **Structured Logging**: Uses `structlog` for JSON or console-formatted logs.

##  архитектура (High-Level)

MCP Vacuum employs a hierarchical agent architecture:

*   **OrchestrationAgent**: The top-level agent that manages the overall workflow. It initializes and coordinates the child agents.
*   **DiscoveryAgent**: Responsible for network scanning (mDNS, etc.) and emitting events for discovered MCP servers.
*   **AuthenticationAgent**: Handles the authentication process for each discovered server, managing OAuth flows and tokens via a `TokenManager`.
*   **MCPClientAgent**: Manages communication with authenticated MCP servers. It fetches tool lists and schemas using an `HTTPMCPClient`.
*   **ConversionAgent**: Takes the MCP tool data fetched by `MCPClientAgent` and uses a `SchemaConverterService` to transform it into Kagent schemas.

Communication between the OrchestrationAgent and child agents is event-driven, primarily using `asyncio.Queue` for passing commands and results.

## ⚙️ Configuration

The agent's behavior can be configured via environment variables or a JSON configuration file.

**Environment Variables:**
All configuration options can be set using environment variables prefixed with `MCP_VACUUM_`. Nested configurations are represented by double underscores (though the current `Config.from_env()` uses sub-prefixes like `MCP_VACUUM_DISCOVERY_`). Refer to `src/mcp_vacuum/config.py` for all available options and their corresponding environment variable names.

Examples:
*   `MCP_VACUUM_LOGGING_LEVEL=DEBUG`
*   `MCP_VACUUM_DISCOVERY_ENABLE_MDNS=true`
*   `MCP_VACUUM_AUTH_TOKEN_STORAGE_METHOD=keyring`
*   `MCP_VACUUM_MCP_CLIENT_CB_FAILURE_THRESHOLD=3`

**Configuration File:**
A JSON configuration file can be used by setting the `MCP_VACUUM_CONFIG_FILE` environment variable to its path, or by using the `--config` / `-c` CLI option.

Example `config.json`:
```json
{
  "agent_name": "MyMCPVacuumInstance",
  "logging": {
    "level": "INFO",
    "format": "console"
  },
  "discovery": {
    "enable_mdns": true,
    "cache_ttl_seconds": 600,
    "allowed_networks": ["192.168.1.0/24"]
  },
  "auth": {
    "default_auth_method": "oauth2_pkce",
    "oauth_dynamic_client_registration": true
  },
  "mcp_client": {
    "enable_circuit_breaker": true,
    "cb_failure_threshold": 3,
    "cb_recovery_timeout_seconds": 20.0
  }
}
```
See `src/mcp_vacuum/config.py` for the full configuration schema. The CLI command `mcp-vacuum config-show` can display the currently loaded configuration.

## 🚀 Getting Started / Development Setup

### Prerequisites
*   Python 3.12+
*   [uv](https://github.com/astral-sh/uv) (for package management - recommended) or `pip`
*   Docker (for building/running containerized version or using DevContainer)
*   A C compiler, Python development headers, and `libkrb5-dev` (or equivalent for your OS) might be needed for the `keyring` library's dependencies on some systems if a suitable backend like `SecretService` or `Windows Credential Manager` is not readily available.

### Setup
1.  **Clone the repository:**
    ```bash
    git clone https://github.com/tzervas/mcp-vacuum.git # Or your fork
    cd mcp-vacuum
    ```

2.  **Set up the environment using `uv` (recommended):**
    ```bash
    # Create a virtual environment (e.g., in .venv)
    uv venv
    source .venv/bin/activate # Or .venv\Scripts\activate on Windows

    # Install dependencies including development tools
    uv pip install -e ".[dev]"
    ```
    Alternatively, if you prefer `pip` directly (after creating and activating a venv):
    ```bash
    pip install -e ".[dev]"
    ```

3.  **Using the DevContainer (VS Code):**
    If you have VS Code and the "Dev Containers" extension installed, you can simply:
    *   Open the cloned repository in VS Code.
    *   When prompted "Reopen in Container", click it.
    This will build the development container with all dependencies pre-installed using `uv`.

## 🏃 Running the Agent (CLI)

The agent provides a command-line interface via `mcp-vacuum`.

**Available Commands:**
*   `discover`: Discover MCP servers, authenticate, and generate schemas.
    ```bash
    mcp-vacuum discover [OPTIONS]
    ```
    Options:
    *   `--networks TEXT`: Target networks to scan (e.g., "192.168.1.0/24"). Can be multiple.
    *   `--output FILE`: Output file for Kagent schemas (JSON). Prints to stdout if not specified.
    *   `--config FILE` or `-c FILE`: Path to a custom configuration file.
    *   `--log-level TEXT`: Override log level (e.g., DEBUG, INFO, WARNING).
*   `config-show`: Display the current configuration settings.
*   `version`: Show the agent version.
*   `--help`: Show help for any command.

**Example Usage:**
```bash
# Discover servers on default networks, print schemas to console, with DEBUG logging
mcp-vacuum --log-level DEBUG discover

# Discover servers on a specific network and save schemas to a file
mcp-vacuum discover --networks "192.168.0.0/16" --output mcp_kagent_schemas.json

# Load a custom config file
mcp-vacuum -c ./my_custom_config.json discover
```

## 🧪 Running Tests

Tests are written using `pytest`.

1.  Ensure development dependencies are installed (see Setup).
2.  Activate your virtual environment.
3.  Run tests:
    ```bash
    # Using uv
    uv run pytest

    # Or directly if pytest is in your PATH
    pytest
    ```
    This will run all tests and display a coverage report.

## 🐳 Docker

A production-optimized Docker image can be built using `Dockerfile.prod`.

1.  **Build the image:**
    From the project root directory:
    ```bash
    docker build -f Dockerfile.prod -t mcp-vacuum:latest .
    ```

2.  **Run the image:**
    You can run the agent within the Docker container. You'll likely need to pass network arguments and potentially mount volumes for configuration or output.

    Example (showing help):
    ```bash
    docker run --rm mcp-vacuum:latest --help
    ```

    Example (running discovery, assuming host networking for discovery to work easily):
    ```bash
    # Note: --network="host" gives the container full access to host's network interfaces.
    # This is often needed for network discovery tools but has security implications.
    # Adjust volume mounts and environment variables for configuration as needed.
    docker run --rm --network="host" \
           -e MCP_VACUUM_LOGGING_LEVEL="INFO" \
           mcp-vacuum:latest discover --output /tmp/schemas.json
           # (Output will be inside the container at /tmp/schemas.json)
    ```
    To get output files, you might mount a volume:
    ```bash
    docker run --rm --network="host" \
           -v $(pwd)/output:/app/output \
           -e MCP_VACUUM_LOGGING_LEVEL="INFO" \
           mcp-vacuum:latest discover --output /app/output/schemas.json
    ```

## Security Considerations

*   **OAuth Client Secrets**: If using OAuth with confidential clients (not typical for PKCE public clients which this agent primarily targets), ensure `client_secret` is managed securely (e.g., via environment variables, Docker secrets, or Kubernetes secrets, not hardcoded).
*   **Token Storage**:
    *   `keyring` (default): Relies on the security of the underlying OS credential manager.
    *   `file` (if fully implemented): Requires extremely careful management of the encryption key.
*   **Network Discovery**: Be mindful of the networks you scan. Ensure you have permission.
*   **Permissions**: The agent itself runs as a non-root user inside Docker. If ARP scanning were implemented, it might require higher privileges.
*   **Dependencies**: Regularly update dependencies to patch security vulnerabilities. Use tools like `uv audit` (if available, or `pip-audit`) or Snyk/Dependabot.
*   **Circuit Breakers**: Help prevent cascading failures to downstream MCP servers.
*   **Allowed Networks**: Use the `discovery.allowed_networks` configuration to restrict which discovered server IPs the agent will interact with.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

Tyler Zervas
