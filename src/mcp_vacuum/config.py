"""Configuration management for MCP Vacuum."""

import os
from pathlib import Path
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class DiscoveryConfig(BaseModel):
    """Configuration for MCP server discovery."""

    timeout: int = Field(default=30, description="Discovery timeout in seconds")
    max_concurrent_scans: int = Field(
        default=10, description="Maximum concurrent scans"
    )
    default_port_range: str = Field(
        default="8000-9000", description="Default port range to scan"
    )
    network_interfaces: List[str] = Field(
        default_factory=list, description="Network interfaces to scan"
    )


class AuthConfig(BaseModel):
    """Configuration for authentication."""

    method: str = Field(default="keyring", description="Authentication method")
    credentials_file: Optional[Path] = Field(
        default=None, description="Path to credentials file"
    )
    keyring_service: str = Field(
        default="mcp-vacuum", description="Keyring service name"
    )


class LoggingConfig(BaseModel):
    """Configuration for logging."""

    level: str = Field(default="INFO", description="Log level")
    format: str = Field(default="json", description="Log format")
    file: Optional[Path] = Field(default=None, description="Log file path")


class SecurityConfig(BaseModel):
    """Configuration for security settings."""

    require_auth: bool = Field(
        default=True, description="Require authentication for all servers"
    )
    allow_insecure: bool = Field(
        default=False, description="Allow connections to insecure servers"
    )
    cert_verification: bool = Field(
        default=True, description="Verify SSL certificates"
    )


class Config(BaseModel):
    """Main configuration for MCP Vacuum."""

    discovery: DiscoveryConfig = Field(default_factory=DiscoveryConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)

    @classmethod
    def from_env(cls) -> "Config":
        """Create configuration from environment variables."""
        config_data = {}

        # Discovery configuration
        discovery_config = {}
        if timeout := os.getenv("MCP_DISCOVERY_TIMEOUT"):
            discovery_config["timeout"] = int(timeout)
        if max_scans := os.getenv("MCP_MAX_CONCURRENT_SCANS"):
            discovery_config["max_concurrent_scans"] = int(max_scans)
        if port_range := os.getenv("MCP_DEFAULT_PORT_RANGE"):
            discovery_config["default_port_range"] = port_range

        if discovery_config:
            config_data["discovery"] = discovery_config

        # Auth configuration
        auth_config = {}
        if auth_method := os.getenv("AUTH_METHOD"):
            auth_config["method"] = auth_method

        if auth_config:
            config_data["auth"] = auth_config

        # Logging configuration
        logging_config = {}
        if log_level := os.getenv("LOG_LEVEL"):
            logging_config["level"] = log_level
        if log_format := os.getenv("LOG_FORMAT"):
            logging_config["format"] = log_format

        if logging_config:
            config_data["logging"] = logging_config

        return cls(**config_data)

    @classmethod
    def from_file(cls, file_path: Path) -> "Config":
        """Create configuration from a file."""
        import json

        with open(file_path) as f:
            config_data = json.load(f)

        return cls(**config_data)
