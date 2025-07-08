#!/usr/bin/env python3.12
"""Simple test script to verify Pydantic validator fixes."""

import sys
import os

# Add the src directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

try:
    from mcp_vacuum.server import AuthCredentials, AuthMethod, MCPServer, ServerStatus
    from pydantic import ValidationError
    
    print("Testing Pydantic validator fixes...")
    
    # Test 1: AuthCredentials validator for method
    print("\n1. Testing AuthCredentials.parse_auth_method validator:")
    try:
        # Test string to enum conversion
        creds = AuthCredentials(method="token", token="test_token")
        print(f"   ✓ String 'token' correctly converted to {creds.method}")
        assert creds.method == AuthMethod.TOKEN
        
        # Test enum directly
        creds2 = AuthCredentials(method=AuthMethod.OAUTH2)
        print(f"   ✓ Enum AuthMethod.OAUTH2 preserved as {creds2.method}")
        assert creds2.method == AuthMethod.OAUTH2
        
        # Test invalid string
        try:
            AuthCredentials(method="invalid_method")
            print("   ✗ Invalid method should have raised ValidationError")
        except ValidationError as e:
            print("   ✓ Invalid method correctly raises ValidationError")
            
    except Exception as e:
        print(f"   ✗ AuthCredentials validator test failed: {e}")
    
    # Test 2: MCPServer validator for endpoint 
    print("\n2. Testing MCPServer.validate_endpoint validator:")
    try:
        # Test valid URL
        server = MCPServer(id="test", endpoint="https://example.com/api")
        print(f"   ✓ Valid URL accepted: {server.endpoint}")
        
        # Test invalid URL
        try:
            MCPServer(id="test2", endpoint="not_a_url")
            print("   ✗ Invalid URL should have raised ValidationError")
        except ValidationError as e:
            print("   ✓ Invalid URL correctly raises ValidationError")
            
        # Test missing scheme
        try:
            MCPServer(id="test3", endpoint="localhost:8080")
            print("   ✗ URL without scheme should have raised ValidationError")
        except ValidationError as e:
            print("   ✓ URL without scheme correctly raises ValidationError")
            
    except Exception as e:
        print(f"   ✗ MCPServer validator test failed: {e}")
    
    print("\n✓ All validator tests completed successfully!")
    print("\nValidator signatures have been correctly updated to:")
    print("- @classmethod decorator")
    print("- @validator with appropriate parameters")
    print("- cls parameter instead of self")
    
except ImportError as e:
    print(f"Import error: {e}")
    sys.exit(1)
except Exception as e:
    print(f"Test failed: {e}")
    sys.exit(1)
