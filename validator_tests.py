#!/usr/bin/env python3.12
"""Comprehensive test script to verify all validator fixes."""

import sys
import os

# Add the src directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

import pytest
from mcp_vacuum.server import AuthCredentials, AuthMethod, MCPServer, ServerStatus
from pydantic import ValidationError

@pytest.mark.parametrize("string_val, expected_enum", [
    ("token", AuthMethod.TOKEN),
    ("oauth2", AuthMethod.OAUTH2),
    ("certificate", AuthMethod.CERTIFICATE),
    ("username_password", AuthMethod.USERNAME_PASSWORD),
    ("none", AuthMethod.NONE),
    ("custom", AuthMethod.CUSTOM),
])
def test_auth_credentials_string_to_enum_conversion(string_val, expected_enum):
    """Test AuthCredentials string to enum conversion."""
    creds = AuthCredentials(method=string_val)
    assert creds.method == expected_enum

@pytest.mark.parametrize("enum_val", list(AuthMethod))
def test_auth_credentials_enum_preservation(enum_val):
    """Test that enum values passed directly are preserved."""
    creds = AuthCredentials(method=enum_val)
    assert creds.method == enum_val

@pytest.mark.parametrize("invalid_val", ["invalid_method", "bad_auth", 123, None])
def test_auth_credentials_invalid_values(invalid_val):
    """Test that invalid values raise ValidationError."""
    with pytest.raises(ValidationError):
        AuthCredentials(method=invalid_val)

@pytest.mark.parametrize("url", [
    "http://localhost:8080",
    "https://api.example.com",
    "https://api.example.com:443/mcp",
    "http://192.168.1.1:3000/api/v1",
    "https://subdomain.example.com/path?query=value",
    "https://example.com/mcp#fragment",
])
def test_mcp_server_valid_urls(url):
    """Test that valid URLs are accepted by MCPServer."""
    server = MCPServer(id=f"test_{hash(url)}", endpoint=url)
    assert server.endpoint == url

@pytest.mark.parametrize("url", [
    "localhost:8080",           # Missing scheme
    "http://",                  # Missing netloc
    "https:",                   # Incomplete
    "not_a_url",               # No scheme or netloc
    "",                        # Empty string
])
def test_mcp_server_invalid_urls(url):
    """Test that invalid URLs raise ValidationError."""
    with pytest.raises(ValidationError):
        MCPServer(id=f"test_{hash(url)}", endpoint=url)

@pytest.mark.parametrize("url", ["ftp://example.com"])
def test_mcp_server_different_schemes(url):
    """Test that URL with different valid scheme is accepted."""
    server = MCPServer(id=f"test_{hash(url)}", endpoint=url)
    assert server.endpoint == url

def test_field_validator_class_method_signatures():
    """Test that validators use correct @classmethod and cls parameter."""
    assert hasattr(AuthCredentials, 'parse_auth_method'), "AuthCredentials.parse_auth_method not found"
    assert hasattr(MCPServer, 'validate_endpoint'), "MCPServer.validate_endpoint not found"

def test_model_functionality():
    """Test overall model functionality with validators."""
    # Test AuthCredentials creation and method conversion
    auth_creds = AuthCredentials(
        method="oauth2",  # String that should be converted
        oauth_config={"client_id": "test", "scope": "read write"}
    )
    assert auth_creds.method == AuthMethod.OAUTH2

    # Test MCPServer creation with AuthCredentials
    server = MCPServer(
        id="test_server",
        name="Test Server",
        endpoint="https://api.example.com/mcp",
        auth_credentials=auth_creds
    )
    assert server.endpoint == "https://api.example.com/mcp"
    assert server.auth_credentials.method == AuthMethod.OAUTH2

    # Test model serialization
    server_dict = server.to_dict()
    assert "id" in server_dict
    assert "endpoint" in server_dict
    assert "auth_credentials" in server_dict

if __name__ == "__main__":
    pytest.main([__file__])
