"""MCP Server model and related classes."""

from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator, ConfigDict
import structlog

logger = structlog.get_logger(__name__)


from .models.common import AuthMethod
class ServerStatus(Enum):
    """Server status enumeration."""

    DISCOVERED = "discovered"
    AUTHENTICATING = "authenticating"
    AUTHENTICATED = "authenticated"
    AUTH_FAILED = "auth_failed"
    ERROR = "error"


@dataclass
class ServerCapabilities:
    """MCP Server capabilities."""

    tools: list[str] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)
    prompts: list[str] = field(default_factory=list)
    sampling: bool = False
    logging: bool = False


class AuthCredentials(BaseModel):
    """Authentication credentials for a server."""

    method: AuthMethod
    username: str | None = None
    password: str | None = None
    token: str | None = None
    certificate_path: str | None = None
    private_key_path: str | None = None
    oauth_config: dict[str, str] | None = None
    custom_data: dict[str, str] | None = None

    @field_validator("method", mode="before")
    @classmethod
    def parse_auth_method(cls, v):
        """Parse auth method from string if needed."""
        if isinstance(v, str):
            return AuthMethod(v)
        return v


class MCPServer(BaseModel):
    """Represents an MCP Server."""

    id: str = Field(..., description="Unique server identifier")
    name: str | None = Field(None, description="Human-readable server name")
    endpoint: str = Field(..., description="Server endpoint URL")
    version: str | None = Field(None, description="Server version")
    status: ServerStatus = Field(
        default=ServerStatus.DISCOVERED, description="Current server status"
    )
    capabilities: ServerCapabilities | None = Field(
        None, description="Server capabilities"
    )
    auth_credentials: AuthCredentials | None = Field(
        None, description="Authentication credentials"
    )
    metadata: dict[str, str] = Field(
        default_factory=dict, description="Additional server metadata"
    )
    schema: dict | None = Field(None, description="Generated Kagent schema")
    last_seen: str | None = Field(None, description="Last time server was seen")
    security_info: dict[str, bool] = Field(
        default_factory=dict, description="Security assessment"
    )

    model_config = ConfigDict(use_enum_values=True)

    @field_validator("endpoint")
    @classmethod
    def validate_endpoint(cls, v):
        """Validate endpoint URL format and scheme."""
        if not v or not isinstance(v, str):
            msg = "Invalid URL format"
            logger.warning(msg, url=v)
            raise ValueError(msg)

        parsed = urlparse(v)
        if not parsed.scheme or not parsed.netloc:
            # Missing scheme (e.g. localhost:8080) or host (http://)
            msg = "Invalid URL format"
            logger.warning(msg, url=v)
            raise ValueError(msg)

        scheme = parsed.scheme.lower()
        if scheme not in ("http", "https"):
            msg = f"Invalid URL protocol '{parsed.scheme}'. Must be HTTP or HTTPS."
            logger.warning(msg, url=v)
            raise ValueError(msg)

        # Reject URLs with fragments
        if parsed.fragment:
            msg = "URL fragments not allowed"
            logger.warning(msg, url=v)
            raise ValueError(msg)

        # Port range check when explicitly present
        if parsed.port is not None and not (1 <= parsed.port <= 65535):
            msg = "Invalid port number"
            logger.warning(msg, url=v)
            raise ValueError(msg)

        return v

    @property
    def host(self) -> str:
        """Get the host from endpoint."""
        return urlparse(self.endpoint).hostname or ""

    @property
    def port(self) -> int:
        """Get the port from endpoint."""
        parsed = urlparse(self.endpoint)
        if parsed.port:
            return parsed.port
        return 443 if parsed.scheme == "https" else 80

    @property
    def is_secure(self) -> bool:
        """Check if the server uses HTTPS."""
        return urlparse(self.endpoint).scheme == "https"

    @property
    def requires_auth(self) -> bool:
        """Check if server requires authentication."""
        return self.auth_credentials is not None

    @property
    def is_authenticated(self) -> bool:
        """Check if server is authenticated."""
        # use_enum_values=True stores status as the enum value string
        return self.status in (
            ServerStatus.AUTHENTICATED,
            ServerStatus.AUTHENTICATED.value,
        )

    def update_status(self, status: ServerStatus) -> None:
        """Update server status."""
        self.status = status

    def set_auth_credentials(self, credentials: AuthCredentials) -> None:
        """Set authentication credentials."""
        self.auth_credentials = credentials

    def set_capabilities(self, capabilities: ServerCapabilities) -> None:
        """Set server capabilities."""
        self.capabilities = capabilities

    def add_metadata(self, key: str, value: str) -> None:
        """Add metadata to the server."""
        self.metadata[key] = value

    def get_security_assessment(self) -> dict[str, bool]:
        """Get security assessment of the server."""
        assessment = {
            "uses_https": self.is_secure,
            "requires_auth": self.requires_auth,
            "is_authenticated": self.is_authenticated,
            "cert_valid": self.security_info.get("cert_valid", False),
            "secure_auth_method": False,
        }

        if self.auth_credentials:
            secure_methods = {
                AuthMethod.CERTIFICATE,
                AuthMethod.OAUTH2,
                AuthMethod.TOKEN,
            }
            assessment["secure_auth_method"] = (
                self.auth_credentials.method in secure_methods
            )

        return assessment

    def to_dict(self) -> dict:
        """Convert server to dictionary representation."""
        return self.model_dump()

    @classmethod
    def from_dict(cls, data: dict) -> "MCPServer":
        """Create server from dictionary representation."""
        return cls(**data)
