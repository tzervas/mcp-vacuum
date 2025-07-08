# Agent Workflow Documentation

## Overview

The MCP Vacuum agent system uses a modular, event-driven architecture for managing different aspects of the MCP discovery and conversion process. This document outlines the key workflows and interactions between different agent components.

## Agent Types

### OrchestrationAgent
The top-level coordinator that manages the overall workflow:
- Initializes and coordinates child agents
- Handles cross-agent communication 
- Manages workflow state and transitions
- Provides global error handling and recovery

### DiscoveryAgent
Responsible for finding MCP servers on the network:
- Performs mDNS/SSDP discovery
- Validates discovered server endpoints
- Emits server discovery events
- Manages discovery caching and timeouts

### AuthenticationAgent
Handles authentication with discovered servers:
- Manages OAuth 2.1 PKCE flows
- Stores and refreshes tokens securely
- Handles reauthentication when needed
- Supports multiple auth methods

### MCPClientAgent
Manages communication with authenticated servers:
- Fetches tool lists and schemas
- Handles rate limiting and retries
- Implements circuit breaker patterns
- Validates server responses

### ConversionAgent
Converts MCP schemas to Kagent format:
- Validates input schemas
- Performs schema transformation
- Handles batch processing
- Provides error recovery options

## Workflow Steps

1. **Discovery Phase**
   ```mermaid
   sequenceDiagram
     OrchestrationAgent->>DiscoveryAgent: Start discovery
     DiscoveryAgent->>Network: Scan for servers
     Network-->>DiscoveryAgent: Server found
     DiscoveryAgent->>OrchestrationAgent: Server discovery event
   ```

2. **Authentication Phase** 
   ```mermaid
   sequenceDiagram
     OrchestrationAgent->>AuthenticationAgent: Authenticate server
     AuthenticationAgent->>Server: OAuth authorization
     Server-->>AuthenticationAgent: Auth code
     AuthenticationAgent->>Server: Token exchange
     Server-->>AuthenticationAgent: Access token
     AuthenticationAgent->>OrchestrationAgent: Auth success event
   ```

3. **Schema Retrieval Phase**
   ```mermaid
   sequenceDiagram
     OrchestrationAgent->>MCPClientAgent: Fetch schemas
     MCPClientAgent->>Server: Get tool list
     Server-->>MCPClientAgent: Tool schemas
     MCPClientAgent->>OrchestrationAgent: Schema retrieval event
   ```

4. **Conversion Phase**
   ```mermaid
   sequenceDiagram
     OrchestrationAgent->>ConversionAgent: Convert schemas
     ConversionAgent->>ConversionAgent: Validate schema
     ConversionAgent->>ConversionAgent: Transform to Kagent
     ConversionAgent->>OrchestrationAgent: Conversion complete
   ```

## Error Handling

Each agent implements error handling appropriate to its domain:

### DiscoveryAgent
- Network timeouts and retries
- Invalid server responses
- Duplicate server handling

### AuthenticationAgent  
- Auth flow failures
- Token refresh errors
- Invalid credentials

### MCPClientAgent
- Connection errors
- Rate limiting
- Schema validation

### ConversionAgent
- Schema validation errors
- Transformation failures
- Partial success handling

## Configuration

The agent system is configurable through:
- Environment variables
- Configuration files
- Command line arguments

Example configuration:
```json
{
  "discovery": {
    "enable_mdns": true,
    "scan_timeout": 30,
    "allowed_networks": ["192.168.1.0/24"]
  },
  "authentication": {
    "token_storage": "keyring",
    "refresh_threshold": 300
  },
  "conversion": {
    "fail_fast": false,
    "batch_size": 10
  }
}
```

## Logging and Monitoring

All agents use structured logging:
- JSON format for machine processing
- Console format for development
- Log correlation via request IDs
- Configurable log levels

## Best Practices

1. Use fail-fast options in development
2. Enable proper error handling in production
3. Configure appropriate timeouts
4. Monitor agent health metrics
5. Review logs for failures
6. Test error recovery paths
