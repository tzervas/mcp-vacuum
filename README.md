# MCP Vacuum

An AI agent developed in Python 3.12 using the Google Python Agent Developer Kit (ADK) designed to discover, authenticate with, and integrate MCP Servers.

## Overview

MCP Vacuum is a specialized AI agent that:
- Securely discovers available MCP Servers in the target environment and/or LAN
- Manages authentication with discovered MCP Servers through various methods
- Dynamically ingests and processes available tools from authenticated servers
- Generates Kagent-compliant schemas based on the discovered specifications
- Enables seamless integration between Kagent and MCP Servers

## Security & Authentication

The agent implements a robust security model for MCP Server interactions:

### Pre-configured Authentication
- Supports mapping of authentication credentials to expected server identifiers
- Allows pre-configuration of auth methods per server or server group
- Securely stores and manages authentication credentials

### Auto-discovery Security
When performing auto-discovery, the agent:
1. Attempts to match discovered servers with pre-configured auth settings
2. For unknown servers:
   - Prompts user/agent for authentication if available
   - Clearly identifies servers lacking security measures
   - Requires explicit user acknowledgment of risks for unsecured servers
   - Maintains detailed security logs of all interactions

### Authentication Methods
Supports multiple authentication mechanisms:
- Token-based authentication
- Certificate-based authentication
- Username/password
- Custom authentication plugins
- OAuth 2.0 flows (where supported)

## Requirements

- Python 3.12+
- Google Python Agent Developer Kit (ADK)
- Network access to target MCP Server environment
- Appropriate authentication credentials for target servers

## Installation

Coming soon...

## Usage

Coming soon...

## Security Considerations

- Always use authentication when available
- Regularly rotate credentials
- Monitor security logs
- Use network segmentation when possible
- Follow the principle of least privilege

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

Tyler Zervas
