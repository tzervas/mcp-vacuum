"""Configuration management for MCP Vacuum."""

import json
from pathlib import Path
from typing import List, Optional

from pydantic import BaseModel, Field, HttpUrl, EmailStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class DiscoveryConfig(BaseModel): # Remains BaseModel, nested under Config (BaseSettings)
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

class DynamicClientRegistrationSettings(BaseModel):
    """Settings for dynamic client registration metadata."""
    client_name_suffix: Optional[str] = Field(None, description="Optional suffix to append to the auto-generated client name during dynamic registration. e.g., 'MyOrg'.")
    client_uri: Optional[HttpUrl] = Field(None, description="URL of the home page of the client application.")
    logo_uri: Optional[HttpUrl] = Field(None, description="URL that references a logo for the client application.")
    contacts: List[EmailStr] = Field(default_factory=list, description="Contact email addresses for the client (must be valid emails).")
    # policy_uri: Optional[HttpUrl] = Field(None, description="URL that client developers can Read to understand how the client uses data.")
    # tos_uri: Optional[HttpUrl] = Field(None, description="URL that client developers can Read to understand terms of service.")

class OAuthClientDetails(BaseModel): # Remains BaseModel
    """Details for a pre-configured OAuth client."""
    client_id: str
    client_secret: Optional[str] = None
    authorization_endpoint: Optional[HttpUrl] = None
    token_endpoint: Optional[HttpUrl] = None
    redirect_uri: Optional[HttpUrl] = Field(default="http://localhost:8080/oauth/callback", description="Default redirect URI for CLI flows.")
    scopes: List[str] = Field(default_factory=lambda: ["openid", "profile", "mcp:tools", "mcp:resources"])

class AuthConfig(BaseModel): # Remains BaseModel
    """Configuration for authentication."""

    default_auth_method: str = Field(default="oauth2_pkce", description="Default authentication method to try.")
    oauth_default_client: Optional[OAuthClientDetails] = Field(None, description="Default OAuth client credentials.")
    oauth_dynamic_client_registration: bool = Field(default=True, description="Enable dynamic client registration.")
    oauth_redirect_uri_port: int = Field(default=8080, description="Default port for localhost redirect URI.")

    dynamic_client_metadata: DynamicClientRegistrationSettings = Field(default_factory=lambda: DynamicClientRegistrationSettings(), description="Metadata to use for dynamic client registration.")

    preconfigured_credentials_file: Optional[Path] = Field(None, description="Path to pre-configured credentials file.")
    token_storage_method: str = Field(default="keyring", description="Method for storing tokens ('keyring', 'file').")
    keyring_service_name: str = Field(default="mcp_vacuum_tokens", description="Service name for keyring storage.")
    encrypted_token_file_path: Optional[Path] = Field(None, description="Path for encrypted token file.")


class LoggingConfig(BaseModel): # Remains BaseModel
    """Configuration for logging."""

    level: str = Field(default="INFO", description="Log level")
    format: str = Field(default="json", description="Log format")
    file: Optional[Path] = Field(default=None, description="Log file path")

class SecurityConfig(BaseModel): # Remains BaseModel
    """Configuration for security settings."""

    require_auth: bool = Field(default=True, description="Require authentication for all servers")
    allow_insecure: bool = Field(default=False, description="Allow connections to insecure servers")
    cert_verification: bool = Field(default=True, description="Verify SSL certificates")

class MCPClientConfig(BaseModel): # Remains BaseModel
    """Configuration for the MCP client behavior."""
    max_retries: int = Field(default=3, ge=0, description="Maximum number of retries for failed requests.")
    initial_backoff_seconds: float = Field(default=1.0, ge=0.1, description="Initial backoff delay for retries.")
    max_backoff_seconds: float = Field(default=30.0, ge=1.0, description="Maximum backoff delay for retries.")
    request_timeout_seconds: float = Field(default=60.0, ge=5.0, description="Default timeout for individual requests to MCP server.")
    connect_timeout_seconds: float = Field(default=10.0, ge=1.0, description="Timeout for establishing a connection to MCP server.")
    connection_pool_total_limit: int = Field(default=100, ge=1, description="Total connection pool limit for aiohttp session.")
    connection_pool_per_host_limit: int = Field(default=30, ge=1, description="Per-host connection pool limit for aiohttp session.")
    connection_pool_dns_cache_ttl_seconds: int = Field(default=300, ge=0, description="DNS cache TTL in seconds for aiohttp session.")
    ssl_verify: bool = Field(default=True, description="Enable/disable SSL certificate verification for HTTP clients.")
    cb_failure_threshold: int = Field(default=5, ge=1, description="Number of failures to open the circuit breaker.")
    cb_recovery_timeout_seconds: float = Field(default=30.0, gt=0, description="Seconds the circuit breaker stays open before moving to half-open.")
    cb_half_open_max_successes: int = Field(default=2, ge=1, description="Number of successful calls in half-open state to close the circuit.")
    enable_circuit_breaker: bool = Field(default=True, description="Globally enable/disable circuit breakers for MCP clients.")


class Config(BaseSettings):
    """Main configuration for MCP Vacuum. Loads from environment variables prefixed with MCP_VACUUM_."""

    # Pydantic-settings model_config
    model_config = SettingsConfigDict(
        env_prefix='MCP_VACUUM_',
        env_nested_delimiter='__', # e.g., MCP_VACUUM_DISCOVERY__TIMEOUT_SECONDS
        extra='ignore', # Ignore extra fields from env/file if not defined in schema
        env_file='.env', # Optionally load a .env file
        env_file_encoding='utf-8'
    )

    discovery: DiscoveryConfig = Field(default_factory=DiscoveryConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    mcp_client: MCPClientConfig = Field(default_factory=MCPClientConfig)
    agent_name: str = Field(default="MCPVacuumAgent", description="Configurable name of the agent instance.")
    agent_version: str = Field(default="0.1.0", description="Version of the MCP Vacuum agent software.")

    # Removed custom Config inner class
    # Removed _load_env_vars method
    # Removed from_env method (pydantic-settings handles this)

    @classmethod
    def from_file(cls, file_path: Path) -> "Config":
        """Create configuration strictly from a JSON file.
        Note: This does not layer with environment variables. For layered loading,
        pydantic-settings offers other mechanisms if env_file in SettingsConfigDict is not sufficient.
        """
        with open(file_path) as f:
            config_data = json.load(f)
        return cls.model_validate(config_data)

    # Consider adding a method to load from file AND environment variables,
    # potentially using pydantic-settings features for multiple env files or customisation.
    # For now, direct instantiation `Config()` loads from env vars (and .env file by default).
    # `Config.from_file()` loads *only* from the specified JSON file.
