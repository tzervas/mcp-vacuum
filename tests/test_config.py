"""Tests for configuration module."""

import os
from pathlib import Path

import pytest

from mcp_vacuum.config import Config, DiscoveryConfig, AuthConfig


def test_config_from_env(monkeypatch):
    """Test loading configuration from environment variables."""
    # Test a few representative environment variables, including nested and different types
    monkeypatch.setenv("MCP_VACUUM_LOGGING_LEVEL", "DEBUG")
    monkeypatch.setenv("MCP_VACUUM_AGENT_NAME", "TestAgent")
    monkeypatch.setenv("MCP_VACUUM_DISCOVERY_TIMEOUT_SECONDS", "45")
    monkeypatch.setenv("MCP_VACUUM_DISCOVERY_ENABLE_MDNS", "false")
    monkeypatch.setenv("MCP_VACUUM_DISCOVERY_ALLOWED_NETWORKS", "192.168.1.0/24,10.0.0.0/8")
    monkeypatch.setenv("MCP_VACUUM_AUTH_DEFAULT_AUTH_METHOD", "token_test")
    monkeypatch.setenv("MCP_VACUUM_AUTH_OAUTH_DYNAMIC_CLIENT_REGISTRATION", "false")
    monkeypatch.setenv("MCP_VACUUM_MCP_CLIENT_MAX_RETRIES", "5")
    monkeypatch.setenv("MCP_VACUUM_MCP_CLIENT_SSL_VERIFY", "false")

    # With pydantic-settings, Config() directly loads from env vars
    config = Config()
    
    assert config.logging.level == "DEBUG"
    assert config.agent_name == "TestAgent"
    assert config.discovery.timeout_seconds == 45
    assert config.discovery.enable_mdns is False
    assert config.discovery.allowed_networks == ["192.168.1.0/24", "10.0.0.0/8"]
    assert config.auth.default_auth_method == "token_test"
    assert config.auth.oauth_dynamic_client_registration is False
    assert config.mcp_client.max_retries == 5
    assert config.mcp_client.ssl_verify is False

def test_config_defaults():
    """Test default configuration values for new and existing fields."""
    config = Config()
    
    # DiscoveryConfig defaults
    assert config.discovery.timeout_seconds == 30
    assert config.discovery.scan_timeout_seconds == 5.0
    assert config.discovery.max_concurrent_scans == 50
    assert config.discovery.enable_mdns is True
    assert config.discovery.mdns_service_types == ["_mcp._tcp.local."]
    assert config.discovery.enable_ssdp is True
    assert config.discovery.ssdp_search_target == "urn:schemas-mcp-org:device:MCPServer:1"
    assert config.discovery.enable_arp_scan is False
    assert config.discovery.cache_ttl_seconds == 300
    assert config.discovery.allowed_networks == []

    # AuthConfig defaults
    assert config.auth.default_auth_method == "oauth2_pkce"
    assert config.auth.oauth_dynamic_client_registration is True
    assert config.auth.oauth_redirect_uri_port == 8080
    assert config.auth.token_storage_method == "keyring"
    assert config.auth.keyring_service_name == "mcp_vacuum_tokens"

    # LoggingConfig defaults
    assert config.logging.level == "INFO"
    assert config.logging.format == "json" # Default from Pydantic field

    # SecurityConfig defaults
    assert config.security.require_auth is True
    assert config.security.allow_insecure is False
    assert config.security.cert_verification is True

    # MCPClientConfig defaults
    assert config.mcp_client.max_retries == 3
    assert config.mcp_client.request_timeout_seconds == 60.0
    assert config.mcp_client.connect_timeout_seconds == 10.0
    assert config.mcp_client.connection_pool_total_limit == 100
    assert config.mcp_client.ssl_verify is True

    # Top-level Config defaults
    assert config.agent_name == "MCPVacuumAgent"
    assert config.agent_version == "0.1.0"


def test_config_from_file(tmp_path):
    """Test loading configuration from a JSON file."""
    config_content = {
        "agent_name": "FileAgent",
        "logging": {
            "level": "WARNING",
            "format": "console"
        },
        "discovery": {
            "timeout_seconds": 50,
            "enable_ssdp": False,
            "allowed_networks": ["172.16.0.0/12"]
        },
        "auth": {
            "default_auth_method": "file_creds",
            "token_storage_method": "file",
            "encrypted_token_file_path": "/tmp/tokens.enc"
        },
        "mcp_client": {
            "max_retries": 2,
            "ssl_verify": False
        }
    }
    config_file = tmp_path / "test_config.json"
    with open(config_file, "w") as f:
        import json
        json.dump(config_content, f)

    config = Config.from_file(config_file)

    assert config.agent_name == "FileAgent"
    assert config.logging.level == "WARNING"
    assert config.logging.format == "console"
    assert config.discovery.timeout_seconds == 50
    assert config.discovery.enable_ssdp is False
    assert config.discovery.allowed_networks == ["172.16.0.0/12"]
    assert config.auth.default_auth_method == "file_creds"
    assert config.auth.token_storage_method == "file"
    # Pydantic converts string path to Path object if field type is Path
    assert str(config.auth.encrypted_token_file_path) == "/tmp/tokens.enc"
    assert config.mcp_client.max_retries == 2
    assert config.mcp_client.ssl_verify is False
    
    # Check that unspecified fields retain defaults
    assert config.discovery.enable_mdns is True # Default
    assert config.security.require_auth is True # Default


def test_partial_config_from_file(tmp_path):
    """Test loading partial configuration from a file, defaults should apply."""
    config_content = {
        "discovery": {
            "timeout_seconds": 25
        }
    }
    config_file = tmp_path / "test_config.json"
    with open(config_file, "w") as f:
        import json
        json.dump(config_content, f)

    config = Config.from_file(config_file)

    assert config.discovery.timeout_seconds == 25
    assert config.discovery.enable_mdns is True # Default
    assert config.logging.level == "INFO" # Default
    assert config.agent_name == "MCPVacuumAgent" # Default
