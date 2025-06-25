"""Tests for configuration module."""

import os
from pathlib import Path

import pytest

from mcp_vacuum.config import Config, DiscoveryConfig, AuthConfig


def test_config_from_env(monkeypatch):
    """Test loading configuration from environment variables."""
    monkeypatch.setenv("MCP_DISCOVERY_TIMEOUT", "45")
    monkeypatch.setenv("AUTH_METHOD", "token")
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")
    
    config = Config.from_env()
    
    assert config.discovery.timeout == 45
    assert config.auth.method == "token"
    assert config.logging.level == "DEBUG"


def test_config_defaults():
    """Test default configuration values."""
    config = Config()
    
    assert config.discovery.timeout == 30
    assert config.discovery.max_concurrent_scans == 10
    assert config.auth.method == "keyring"
    assert config.logging.level == "INFO"
    assert config.security.require_auth is True


def test_discovery_config():
    """Test discovery configuration."""
    discovery = DiscoveryConfig(
        timeout=60,
        max_concurrent_scans=5,
        default_port_range="9000-9999"
    )
    
    assert discovery.timeout == 60
    assert discovery.max_concurrent_scans == 5
    assert discovery.default_port_range == "9000-9999"


def test_auth_config():
    """Test authentication configuration."""
    auth = AuthConfig(
        method="certificate",
        keyring_service="test-service"
    )
    
    assert auth.method == "certificate"
    assert auth.keyring_service == "test-service"
