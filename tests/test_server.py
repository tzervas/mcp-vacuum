"""
Unit tests for server.py models and validators.
"""
import pytest
from pydantic import ValidationError

import sys
import os

# Add the src directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from mcp_vacuum.server import (
    AuthCredentials,
    AuthMethod,
    MCPServer,
    ServerStatus,
    ServerCapabilities,
)


class TestAuthCredentials:
    """Test AuthCredentials model and validators."""

    def test_parse_auth_method_from_string(self):
        """Test that auth method validator correctly parses string values."""
        # Test with valid string value
        creds = AuthCredentials(method="token", token="abc123")
        assert creds.method == AuthMethod.TOKEN
        assert isinstance(creds.method, AuthMethod)

        # Test with another valid string value
        creds2 = AuthCredentials(method="oauth2")
        assert creds2.method == AuthMethod.OAUTH2

        # Test with enum value directly (should pass through)
        creds3 = AuthCredentials(method=AuthMethod.CERTIFICATE)
        assert creds3.method == AuthMethod.CERTIFICATE

    def test_parse_auth_method_invalid_string(self):
        """Test that invalid auth method strings raise ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            AuthCredentials(method="invalid_method")
        
        # Check that the error is about the enum value
        assert "invalid_method" in str(exc_info.value)

    def test_auth_credentials_creation_with_different_methods(self):
        """Test creating AuthCredentials with different auth methods."""
        # Test NONE method
        creds_none = AuthCredentials(method=AuthMethod.NONE)
        assert creds_none.method == AuthMethod.NONE
        assert creds_none.token is None

        # Test TOKEN method
        creds_token = AuthCredentials(method=AuthMethod.TOKEN, token="secret_token")
        assert creds_token.method == AuthMethod.TOKEN
        assert creds_token.token == "secret_token"

        # Test USERNAME_PASSWORD method
        creds_userpass = AuthCredentials(
            method=AuthMethod.USERNAME_PASSWORD,
            username="user",
            password="pass"
        )
        assert creds_userpass.method == AuthMethod.USERNAME_PASSWORD
        assert creds_userpass.username == "user"
        assert creds_userpass.password == "pass"

        # Test CERTIFICATE method
        creds_cert = AuthCredentials(
            method=AuthMethod.CERTIFICATE,
            certificate_path="/path/to/cert.pem",
            private_key_path="/path/to/key.pem"
        )
        assert creds_cert.method == AuthMethod.CERTIFICATE
        assert creds_cert.certificate_path == "/path/to/cert.pem"

        # Test OAUTH2 method
        creds_oauth = AuthCredentials(
            method=AuthMethod.OAUTH2,
            oauth_config={"client_id": "test", "scope": "read"}
        )
        assert creds_oauth.method == AuthMethod.OAUTH2
        assert creds_oauth.oauth_config["client_id"] == "test"

        # Test CUSTOM method
        creds_custom = AuthCredentials(
            method=AuthMethod.CUSTOM,
            custom_data={"api_key": "xyz", "secret": "abc"}
        )
        assert creds_custom.method == AuthMethod.CUSTOM
        assert creds_custom.custom_data["api_key"] == "xyz"


class TestMCPServer:
    """Test MCPServer model and validators."""

    def test_validate_endpoint_valid_urls(self):
        """Test endpoint validator accepts valid URLs."""
        # Test HTTP URL
        server1 = MCPServer(id="test1", endpoint="http://localhost:8080")
        assert server1.endpoint == "http://localhost:8080"

        # Test HTTPS URL
        server2 = MCPServer(id="test2", endpoint="https://api.example.com:443/mcp")
        assert server2.endpoint == "https://api.example.com:443/mcp"

        # Test URL with path
        server3 = MCPServer(id="test3", endpoint="https://example.com/api/v1/mcp")
        assert server3.endpoint == "https://example.com/api/v1/mcp"

        # Test URL with query parameters
        server4 = MCPServer(id="test4", endpoint="https://example.com/mcp?version=1")
        assert server4.endpoint == "https://example.com/mcp?version=1"

    def test_validate_endpoint_invalid_urls(self):
        """Test endpoint validator rejects invalid URLs."""
        # Test missing scheme
        with pytest.raises(ValidationError) as exc_info:
            MCPServer(id="test1", endpoint="localhost:8080")
        assert "Invalid URL format" in str(exc_info.value)

        # Test missing netloc (host)
        with pytest.raises(ValidationError) as exc_info:
            MCPServer(id="test2", endpoint="http://")
        assert "Invalid URL format" in str(exc_info.value)

        # Test completely invalid URL
        with pytest.raises(ValidationError) as exc_info:
            MCPServer(id="test3", endpoint="not_a_url")
        assert "Invalid URL format" in str(exc_info.value)

        # Test empty string
        with pytest.raises(ValidationError) as exc_info:
            MCPServer(id="test4", endpoint="")
        assert "Invalid URL format" in str(exc_info.value)

    def test_server_properties(self):
        """Test server property methods work correctly."""
        # Test HTTP server
        server_http = MCPServer(id="http_server", endpoint="http://example.com:8080/api")
        assert server_http.host == "example.com"
        assert server_http.port == 8080
        assert not server_http.is_secure

        # Test HTTPS server without explicit port
        server_https = MCPServer(id="https_server", endpoint="https://secure.example.com/api")
        assert server_https.host == "secure.example.com"
        assert server_https.port == 443  # Default HTTPS port
        assert server_https.is_secure

        # Test HTTP server without explicit port
        server_http_default = MCPServer(id="http_default", endpoint="http://example.com/api")
        assert server_http_default.port == 80  # Default HTTP port

    def test_server_authentication_properties(self):
        """Test authentication-related properties."""
        # Server without auth
        server_no_auth = MCPServer(id="no_auth", endpoint="http://example.com")
        assert not server_no_auth.requires_auth
        assert not server_no_auth.is_authenticated

        # Server with auth credentials
        auth_creds = AuthCredentials(method=AuthMethod.TOKEN, token="test_token")
        server_with_auth = MCPServer(
            id="with_auth",
            endpoint="https://example.com",
            auth_credentials=auth_creds
        )
        assert server_with_auth.requires_auth
        assert not server_with_auth.is_authenticated  # Status is still DISCOVERED

        # Server that is authenticated
        server_authenticated = MCPServer(
            id="authenticated",
            endpoint="https://example.com",
            auth_credentials=auth_creds,
            status=ServerStatus.AUTHENTICATED
        )
        assert server_authenticated.requires_auth
        assert server_authenticated.is_authenticated

    def test_server_status_update(self):
        """Test server status update functionality."""
        server = MCPServer(id="test", endpoint="http://example.com")
        assert server.status == ServerStatus.DISCOVERED  # Default status

        server.update_status(ServerStatus.AUTHENTICATING)
        assert server.status == ServerStatus.AUTHENTICATING

        server.update_status(ServerStatus.AUTHENTICATED)
        assert server.status == ServerStatus.AUTHENTICATED

    def test_server_security_assessment(self):
        """Test security assessment functionality."""
        # Basic HTTP server
        server_basic = MCPServer(id="basic", endpoint="http://example.com")
        assessment = server_basic.get_security_assessment()
        
        assert not assessment["uses_https"]
        assert not assessment["requires_auth"]
        assert not assessment["is_authenticated"]
        assert not assessment["cert_valid"]
        assert not assessment["secure_auth_method"]

        # Secure HTTPS server with certificate auth
        auth_creds = AuthCredentials(
            method=AuthMethod.CERTIFICATE,
            certificate_path="/path/to/cert.pem"
        )
        server_secure = MCPServer(
            id="secure",
            endpoint="https://secure.example.com",
            auth_credentials=auth_creds,
            status=ServerStatus.AUTHENTICATED,
            security_info={"cert_valid": True}
        )
        assessment_secure = server_secure.get_security_assessment()
        
        assert assessment_secure["uses_https"]
        assert assessment_secure["requires_auth"]
        assert assessment_secure["is_authenticated"]
        assert assessment_secure["cert_valid"]
        assert assessment_secure["secure_auth_method"]  # Certificate is secure

        # Server with insecure auth method
        insecure_auth = AuthCredentials(method=AuthMethod.USERNAME_PASSWORD)
        server_insecure_auth = MCPServer(
            id="insecure_auth",
            endpoint="https://example.com",
            auth_credentials=insecure_auth
        )
        assessment_insecure = server_insecure_auth.get_security_assessment()
        assert not assessment_insecure["secure_auth_method"]  # Username/password is not secure

    def test_server_capabilities_and_metadata(self):
        """Test server capabilities and metadata functionality."""
        capabilities = ServerCapabilities(
            tools=["calculator", "weather"],
            resources=["database", "files"],
            prompts=["help", "info"],
            sampling=True,
            logging=True
        )
        
        server = MCPServer(
            id="full_featured",
            endpoint="https://example.com",
            capabilities=capabilities,
            metadata={"version": "1.0", "environment": "production"}
        )
        
        assert server.capabilities.tools == ["calculator", "weather"]
        assert server.capabilities.sampling is True
        assert server.metadata["version"] == "1.0"

        # Test adding metadata
        server.add_metadata("new_key", "new_value")
        assert server.metadata["new_key"] == "new_value"

    def test_server_dict_conversion(self):
        """Test server dictionary conversion methods."""
        auth_creds = AuthCredentials(method=AuthMethod.TOKEN, token="test")
        server = MCPServer(
            id="dict_test",
            name="Test Server",
            endpoint="https://example.com",
            auth_credentials=auth_creds,
            metadata={"test": "value"}
        )
        
        # Test to_dict
        server_dict = server.to_dict()
        assert server_dict["id"] == "dict_test"
        assert server_dict["name"] == "Test Server"
        assert server_dict["endpoint"] == "https://example.com"
        assert server_dict["auth_credentials"]["method"] == "token"  # Enum serialized
        
        # Test from_dict
        recreated_server = MCPServer.from_dict(server_dict)
        assert recreated_server.id == server.id
        assert recreated_server.name == server.name
        assert recreated_server.endpoint == server.endpoint
        assert recreated_server.auth_credentials.method == server.auth_credentials.method


class TestServerCapabilities:
    """Test ServerCapabilities dataclass."""

    def test_default_capabilities(self):
        """Test default values for ServerCapabilities."""
        caps = ServerCapabilities()
        assert caps.tools == []
        assert caps.resources == []
        assert caps.prompts == []
        assert caps.sampling is False
        assert caps.logging is False

    def test_custom_capabilities(self):
        """Test creating ServerCapabilities with custom values."""
        caps = ServerCapabilities(
            tools=["tool1", "tool2"],
            resources=["resource1"],
            prompts=["prompt1", "prompt2", "prompt3"],
            sampling=True,
            logging=True
        )
        assert len(caps.tools) == 2
        assert len(caps.resources) == 1
        assert len(caps.prompts) == 3
        assert caps.sampling is True
        assert caps.logging is True
