"""Configuration management for MCP Vacuum."""

import os
from pathlib import Path
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class DiscoveryConfig(BaseModel):
    """Configuration for MCP server discovery."""

    timeout_seconds: int = Field(default=30, ge=5, le=300, description="Global discovery timeout in seconds for operations like mDNS listening.")
    scan_timeout_seconds: float = Field(default=5.0, ge=0.5, le=60, description="Timeout for individual host/port scans.")
    max_concurrent_scans: int = Field(default=50, ge=1, le=200, description="Maximum concurrent discovery operations or host scans.")

    enable_mdns: bool = Field(default=True, description="Enable mDNS/DNS-SD discovery.")
    mdns_service_types: List[str] = Field(default_factory=lambda: ["_mcp._tcp.local."], description="mDNS service types to query.")

    enable_ssdp: bool = Field(default=True, description="Enable SSDP/UPnP discovery.")
    ssdp_search_target: str = Field(default="urn:schemas-mcp-org:device:MCPServer:1", description="SSDP search target (ST) for MCP servers.")

    enable_arp_scan: bool = Field(default=False, description="Enable ARP scanning (requires privileges).")
    arp_scan_networks: List[str] = Field(default_factory=list, description="Networks to ARP scan if enabled (e.g., ['192.168.1.0/24']). If empty, tries to infer from interfaces.")

    target_networks: List[str] = Field(default_factory=list, description="Explicit target networks/IP ranges to scan (e.g., ['192.168.1.0/24', '10.0.0.5']). Supplements ARP/interface-based discovery.")
    network_interfaces: List[str] = Field(default_factory=list, description="Specific network interfaces to use for discovery (e.g., ['eth0', 'wlan0']). If empty, tries to use all suitable.")

    cache_ttl_seconds: int = Field(default=300, ge=10, le=3600, description="TTL for discovered service cache in seconds.")
    allowed_networks: List[str] = Field(default_factory=list, description="List of allowed network ranges (CIDR format) for discovered services. If empty, all are allowed.")

class OAuthClientDetails(BaseModel):
    """Details for a pre-configured OAuth client."""
    client_id: str
    client_secret: Optional[str] = None # For confidential clients; typically not for PKCE public clients
    authorization_endpoint: Optional[HttpUrl] = None # Can be discovered via .well-known
    token_endpoint: Optional[HttpUrl] = None # Can be discovered via .well-known
    redirect_uri: Optional[HttpUrl] = Field(default="http://localhost:8080/oauth/callback", description="Default redirect URI for CLI flows.") # Needs to be flexible
    scopes: List[str] = Field(default_factory=lambda: ["openid", "profile", "mcp:tools", "mcp:resources"])
    # registration_endpoint: Optional[HttpUrl] = None # For servers that support dynamic client registration

class AuthConfig(BaseModel):
    """Configuration for authentication."""

    default_auth_method: str = Field(default="oauth2_pkce", description="Default authentication method to try (e.g., 'oauth2_pkce', 'token', 'none').")

    # OAuth 2.1 PKCE specific settings
    oauth_default_client: Optional[OAuthClientDetails] = Field(None, description="Default OAuth client credentials if not dynamically registered or server-specific.")
    oauth_dynamic_client_registration: bool = Field(default=True, description="Enable dynamic client registration (RFC 7591) if supported by server.")
    oauth_redirect_uri_port: int = Field(default=8080, description="Default port for localhost redirect URI during CLI auth flow.")

    # For pre-configured tokens or other methods
    preconfigured_credentials_file: Optional[Path] = Field(default=None, description="Path to a file with pre-configured server credentials (e.g., API keys, tokens).")

    # Secure storage for tokens
    token_storage_method: str = Field(default="keyring", description="Method for storing sensitive tokens ('keyring', 'file').")
    keyring_service_name: str = Field(default="mcp_vacuum_tokens", description="Service name for system keyring storage.")
    encrypted_token_file_path: Optional[Path] = Field(None, description="Path for encrypted token file if 'file' storage method is used.")
    # Encryption key for file-based token storage would ideally be handled by keyring or environment variable, not directly in config.

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
    # Add a general section for Agent specific config
    agent_name: str = Field(default="MCPVacuumAgent", description="Name of the agent.")
    # Potentially ADK/Vertex AI related configs if user-configurable
    # vertex_ai_project: Optional[str] = Field(None, description="Google Cloud Project ID for Vertex AI.")
    # vertex_ai_location: Optional[str] = Field(None, description="Google Cloud Location for Vertex AI.")
    # vertex_ai_endpoint: Optional[HttpUrl] = Field(None, description="Vertex AI endpoint override.")

class MCPClientConfig(BaseModel):
    """Configuration for the MCP client behavior."""
    max_retries: int = Field(default=3, ge=0, description="Maximum number of retries for failed requests.")
    initial_backoff_seconds: float = Field(default=1.0, ge=0.1, description="Initial backoff delay for retries.")
    max_backoff_seconds: float = Field(default=30.0, ge=1.0, description="Maximum backoff delay for retries.")
    request_timeout_seconds: float = Field(default=60.0, ge=5.0, description="Default timeout for individual requests to MCP server.")
    connect_timeout_seconds: float = Field(default=10.0, ge=1.0, description="Timeout for establishing a connection to MCP server.")

    # For aiohttp session TCPConnector settings
    connection_pool_total_limit: int = Field(default=100, ge=1, description="Total connection pool limit for aiohttp session.")
    connection_pool_per_host_limit: int = Field(default=30, ge=1, description="Per-host connection pool limit for aiohttp session.")
    connection_pool_dns_cache_ttl_seconds: int = Field(default=300, ge=0, description="DNS cache TTL in seconds for aiohttp session.")
    ssl_verify: bool = Field(default=True, description="Enable/disable SSL certificate verification for HTTP clients. Warning: disabling is insecure.")
    # We might also need:
    # ssl_ca_bundle: Optional[Path] = Field(None, description="Path to a custom CA bundle file for SSL verification.")

    # Circuit Breaker Settings
    cb_failure_threshold: int = Field(default=5, ge=1, description="Number of failures to open the circuit breaker.")
    cb_recovery_timeout_seconds: float = Field(default=30.0, gt=0, description="Seconds the circuit breaker stays open before moving to half-open.")
    cb_half_open_max_successes: int = Field(default=2, ge=1, description="Number of successful calls in half-open state to close the circuit.")
    enable_circuit_breaker: bool = Field(default=True, description="Globally enable/disable circuit breakers for MCP clients.")


class Config(BaseModel):
    """Main configuration for MCP Vacuum."""

    discovery: DiscoveryConfig = Field(default_factory=DiscoveryConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    mcp_client: MCPClientConfig = Field(default_factory=MCPClientConfig)
    agent_name: str = Field(default="MCPVacuumAgent", description="Configurable name of the agent instance.")
    agent_version: str = Field(default="0.1.0", description="Version of the MCP Vacuum agent software.") # Added agent_version

    class Config:
        # Pydantic V2 way to specify model config
        # For pydantic-settings, you'd use model_config = SettingsConfigDict(env_prefix='MCP_VACUUM_')
        # For now, we'll improve from_env manually
        extra = 'ignore' # Ignore extra fields from env/file if not defined in schema

    @classmethod
    def _load_env_vars(cls, model: type[BaseModel], prefix: str) -> Dict:
        """Helper to load environment variables for a given model and prefix."""
        data = {}
        for field_name, field_info in model.model_fields.items():
            env_var_name = f"{prefix}{field_name.upper()}"
            env_var_value = os.getenv(env_var_name)

            if env_var_value is not None:
                # Attempt to cast to the field type if simple (e.g., int, bool, float)
                # Pydantic will handle more complex parsing when model is initialized
                try:
                    if field_info.annotation == int:
                        data[field_name] = int(env_var_value)
                    elif field_info.annotation == float:
                        data[field_name] = float(env_var_value)
                    elif field_info.annotation == bool:
                        # Handle common boolean string representations
                        data[field_name] = env_var_value.lower() in ("true", "1", "yes")
                    elif field_info.annotation == List[str]:
                         # Simple comma-separated list for env vars
                        data[field_name] = [item.strip() for item in env_var_value.split(',')]
                    else:
                        data[field_name] = env_var_value
                except ValueError:
                    # If casting fails, pass the raw string; Pydantic will validate
                    data[field_name] = env_var_value

            # For nested models, recursively load their env vars
            # This part is tricky without pydantic-settings's nested env var handling.
            # A simple approach might not cover all cases (e.g. nested model field names).
            # For now, this simple loader focuses on direct fields.
            # Pydantic-settings handles nested models like MCP_VACUUM_DISCOVERY_TIMEOUT_SECONDS

        return data

    @classmethod
    def from_env(cls, prefix: str = "MCP_VACUUM_") -> "Config":
        """Create configuration from environment variables.
        Example env var: MCP_VACUUM_LOGGING_LEVEL=DEBUG
                         MCP_VACUUM_DISCOVERY_TIMEOUT_SECONDS=60
                         MCP_VACUUM_AUTH_OAUTH_DEFAULT_CLIENT_CLIENT_ID="myid" (more complex for nested)
        """
        config_data = cls._load_env_vars(cls, prefix)

        # Manually handle nested models for now, as _load_env_vars is simplified
        if "discovery" not in config_data: # only load if not already set by direct top-level var
            discovery_prefix = f"{prefix}DISCOVERY_"
            config_data["discovery"] = cls._load_env_vars(DiscoveryConfig, discovery_prefix)

        if "auth" not in config_data:
            auth_prefix = f"{prefix}AUTH_"
            auth_data = cls._load_env_vars(AuthConfig, auth_prefix)
            # Example for a nested model within AuthConfig like OAuthClientDetails
            if "oauth_default_client" not in auth_data and os.getenv(f"{auth_prefix}OAUTH_DEFAULT_CLIENT_CLIENT_ID"):
                 oauth_client_prefix = f"{auth_prefix}OAUTH_DEFAULT_CLIENT_"
                 auth_data["oauth_default_client"] = cls._load_env_vars(OAuthClientDetails, oauth_client_prefix)
            config_data["auth"] = auth_data

        if "logging" not in config_data:
            logging_prefix = f"{prefix}LOGGING_"
            config_data["logging"] = cls._load_env_vars(LoggingConfig, logging_prefix)

        if "security" not in config_data:
            security_prefix = f"{prefix}SECURITY_"
            config_data["security"] = cls._load_env_vars(SecurityConfig, security_prefix)

        if "mcp_client" not in config_data:
            mcp_client_prefix = f"{prefix}MCP_CLIENT_"
            config_data["mcp_client"] = cls._load_env_vars(MCPClientConfig, mcp_client_prefix)

        # agent_name and agent_version are top-level fields, so _load_env_vars(cls, prefix) should pick them up.
        # No special handling needed here unless they were nested.

        # Filter out empty dicts for nested models if no env vars were found for them
        for key in ["discovery", "auth", "logging", "security", "mcp_client"]:
            if isinstance(config_data.get(key), dict) and not config_data.get(key):
                config_data.pop(key, None)

        return cls(**config_data)

    @classmethod
    def from_file(cls, file_path: Path) -> "Config":
        """Create configuration from a file."""
        import json

        with open(file_path) as f:
            config_data = json.load(f)

        # Using model_validate is the Pydantic V2 way for parsing raw dicts
        return cls.model_validate(config_data)
