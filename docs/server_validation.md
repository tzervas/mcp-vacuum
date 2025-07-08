# Server URL Validation

## Overview
The server URL validation system ensures that MCP server endpoints meet security and format requirements. This 
includes validating URLs, protocols, ports, and IP addresses according to best practices.

## Validation Rules

### URL Format
- URLs must include a valid scheme (`http://` or `https://`)
- The URL must have a valid host component 
- Empty URLs are rejected
- URL fragments are not allowed
- Query parameters are optional but must be valid if present

### Protocol Security
- Only `http` and `https` protocols are supported
- `https` is required for:
  - Production endpoints 
  - Endpoints exposed to public networks
  - Any authentication-related communications

### Port Validation  
- Port numbers must be valid (1-65535)
- Standard ports (80/443) are inferred if not specified
- Localhost services should not use standard public ports
- Custom ports must follow organization/deployment rules

### Host Validation
- IP addresses must be valid IPv4/IPv6 format
- Hostnames must follow DNS naming conventions 
- Localhost restrictions apply for development/testing
- Public hostnames require additional validation

### Error Handling
The validator provides detailed error messages to help diagnose validation failures:

- `Invalid URL format`: The URL structure is malformed
- `Invalid URL protocol`: Unsupported protocol scheme
- `Invalid port number`: Port number outside valid range
- `Localhost with public port`: Security restriction violation
- `Invalid IP address`: Malformed IP address format
- `URL fragments not allowed`: Found URL fragment component

## Usage Example

```python
from mcp_vacuum.server import MCPServer

# Valid configurations
server1 = MCPServer(
    id="prod_server",
    endpoint="https://api.example.com/mcp"  # HTTPS, valid domain
)

server2 = MCPServer(
    id="dev_server", 
    endpoint="http://localhost:8080/mcp"  # Local dev port
)

# Invalid configurations will raise ValidationError
try:
    bad_server = MCPServer(
        id="bad_server",
        endpoint="ftp://example.com"  # Invalid protocol
    )
except ValidationError as e:
    print(f"Validation failed: {e}")
```

## Best Practices

1. Always use HTTPS for production endpoints
2. Use custom ports for local development 
3. Enable proper certificate validation
4. Follow URL encoding guidelines
5. Implement rate limiting and circuit breakers
6. Monitor validation failures for security
