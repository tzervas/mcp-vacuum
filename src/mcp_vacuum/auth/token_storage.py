"""
Secure storage for OAuth 2.1 tokens and client credentials.
"""
import abc
import json
import base64
from typing import Optional, Dict, Any, Type

import keyring
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from ..models.auth import OAuth2Token, ClientCredentials
from ..config import AuthConfig # For keyring service name, file paths
import structlog # Import structlog

logger = structlog.get_logger(__name__)

class TokenStorageError(Exception):
    """Base class for token storage errors."""
    pass

class TokenNotFoundError(TokenStorageError):
    """Raised when a token is not found for a given key."""
    pass

class EncryptionError(TokenStorageError):
    """Raised for issues related to encryption/decryption."""
    pass

class BaseTokenStorage(abc.ABC):
    """Abstract base class for storing and retrieving OAuth tokens and client credentials."""

    @abc.abstractmethod
    async def store_oauth_token(self, server_id: str, token: OAuth2Token) -> None:
        """Stores an OAuth2Token for a given server ID."""
        pass

    @abc.abstractmethod
    async def get_oauth_token(self, server_id: str) -> Optional[OAuth2Token]:
        """Retrieves an OAuth2Token for a given server ID."""
        pass

    @abc.abstractmethod
    async def delete_oauth_token(self, server_id: str) -> None:
        """Deletes an OAuth2Token for a given server ID."""
        pass

    @abc.abstractmethod
    async def store_client_credentials(self, server_id: str, credentials: ClientCredentials) -> None:
        """Stores ClientCredentials for a given server ID (e.g., after dynamic registration)."""
        pass

    @abc.abstractmethod
    async def get_client_credentials(self, server_id: str) -> Optional[ClientCredentials]:
        """Retrieves ClientCredentials for a given server ID."""
        pass

    @abc.abstractmethod
    async def delete_client_credentials(self, server_id: str) -> None:
        """Deletes ClientCredentials for a given server ID."""
        pass

class KeyringTokenStorage(BaseTokenStorage):
    """
    Stores tokens and credentials securely in the system keyring.
    Uses separate entries for OAuth tokens and client credentials, prefixed by server_id.
    """
    OAUTH_TOKEN_SUFFIX = "_oauth_token"
    CLIENT_CREDS_SUFFIX = "_client_creds"

    def __init__(self, auth_config: AuthConfig):
        self.service_name = auth_config.keyring_service_name
        self.logger = logger.bind(storage_type="keyring", service_name=self.service_name)

    def _get_key(self, server_id: str, suffix: str) -> str:
        return f"{server_id}{suffix}"

    async def _store_item(self, key: str, item_model: Type[OAuth2Token] | Type[ClientCredentials], item_data: Dict[str, Any]) -> None:
        try:
            # Pydantic model to JSON string
            item_json = item_model(**item_data).model_dump_json()
            keyring.set_password(self.service_name, key, item_json)
            self.logger.debug("Stored item in keyring", key_hint=key[:10]+"...") # Avoid logging full key if sensitive
        except keyring.errors.NoKeyringError:
            self.logger.error("No keyring backend found. Please install a keyring provider (e.g., SecretService, Windows Credential Manager).")
            raise TokenStorageError("No keyring backend available.")
        except Exception as e:
            self.logger.error("Failed to store item in keyring", key_hint=key[:10]+"...", error=str(e))
            raise TokenStorageError(f"Failed to store item in keyring for key '{key}': {e}") from e

    async def _get_item(self, key: str, item_model: Type[OAuth2Token] | Type[ClientCredentials]) -> Optional[Any]: # Actually Optional[OAuth2Token] or Optional[ClientCredentials]
        try:
            item_json = keyring.get_password(self.service_name, key)
            if item_json:
                # JSON string to Pydantic model
                return item_model.model_validate_json(item_json)
            return None
        except keyring.errors.NoKeyringError:
            self.logger.error("No keyring backend found when trying to retrieve item.")
            raise TokenStorageError("No keyring backend available.")
        except json.JSONDecodeError as e:
            self.logger.warning("Failed to decode JSON from keyring for item", key_hint=key[:10]+"...", error=str(e))
            # Potentially corrupted data, treat as not found and maybe delete
            await self._delete_item(key) # Clean up corrupted entry
            return None
        except ValueError as e: # Pydantic validation error
            self.logger.warning("Failed to validate item data from keyring", key_hint=key[:10]+"...", error=str(e))
            await self._delete_item(key) # Clean up invalid entry
            return None
        except Exception as e:
            self.logger.error("Failed to retrieve item from keyring", key_hint=key[:10]+"...", error=str(e))
            raise TokenStorageError(f"Failed to retrieve item from keyring for key '{key}': {e}") from e


    async def _delete_item(self, key: str) -> None:
        try:
            keyring.delete_password(self.service_name, key)
            self.logger.debug("Deleted item from keyring", key_hint=key[:10]+"...")
        except keyring.errors.PasswordDeleteError:
            # This error might mean the password/item didn't exist. Not always a critical failure.
            self.logger.warning("Item not found or could not be deleted from keyring", key_hint=key[:10]+"...")
            pass # Fail silently or raise specific error if needed
        except keyring.errors.NoKeyringError:
            self.logger.error("No keyring backend found when trying to delete item.")
            raise TokenStorageError("No keyring backend available.")
        except Exception as e:
            self.logger.error("Failed to delete item from keyring", key_hint=key[:10]+"...", error=str(e))
            raise TokenStorageError(f"Failed to delete item from keyring for key '{key}': {e}") from e

    async def store_oauth_token(self, server_id: str, token: OAuth2Token) -> None:
        key = self._get_key(server_id, self.OAUTH_TOKEN_SUFFIX)
        await self._store_item(key, OAuth2Token, token.model_dump())

    async def get_oauth_token(self, server_id: str) -> Optional[OAuth2Token]:
        key = self._get_key(server_id, self.OAUTH_TOKEN_SUFFIX)
        token_data = await self._get_item(key, OAuth2Token)
        return token_data if isinstance(token_data, OAuth2Token) else None


    async def delete_oauth_token(self, server_id: str) -> None:
        key = self._get_key(server_id, self.OAUTH_TOKEN_SUFFIX)
        await self._delete_item(key)

    async def store_client_credentials(self, server_id: str, credentials: ClientCredentials) -> None:
        key = self._get_key(server_id, self.CLIENT_CREDS_SUFFIX)
        await self._store_item(key, ClientCredentials, credentials.model_dump())

    async def get_client_credentials(self, server_id: str) -> Optional[ClientCredentials]:
        key = self._get_key(server_id, self.CLIENT_CREDS_SUFFIX)
        creds_data = await self._get_item(key, ClientCredentials)
        return creds_data if isinstance(creds_data, ClientCredentials) else None

    async def delete_client_credentials(self, server_id: str) -> None:
        key = self._get_key(server_id, self.CLIENT_CREDS_SUFFIX)
        await self._delete_item(key)


class EncryptedFileTokenStorage(BaseTokenStorage):
    """
    Stores tokens and credentials in a single encrypted file.
    Uses Fernet encryption. Requires an encryption key (derive from password or env var).
    WARNING: Managing the encryption key securely is critical.
             Storing it directly in config or code is insecure.
             Best practice is to use a key derived from a user-provided password
             or from a securely managed environment variable (e.g., via Docker secrets, k8s secrets).
    """
    # TODO: Implement this class.
    # Key aspects:
    # - Needs an encryption key. How is it provided/derived securely?
    #   - One option: Use a password provided by user/env, derive key using PBKDF2HMAC.
    #   - Store salt alongside encrypted data if PBKDF2 is used.
    # - File structure: JSON dictionary where keys are server_ids, values are dicts of tokens/creds.
    #   {
    #     "server1_oauth_token": "encrypted_oauth_token_json_for_server1",
    #     "server1_client_creds": "encrypted_client_creds_json_for_server1",
    #     ...
    #   }
    # - Need to read the whole file, decrypt, modify, encrypt, write back. (Consider atomicity).
    # - Fernet requires the data to be bytes.

    def __init__(self, auth_config: AuthConfig, encryption_key: bytes):
        self.file_path = auth_config.encrypted_token_file_path
        if not self.file_path:
            raise ValueError("Encrypted token file path is not configured.")
        self.fernet = Fernet(encryption_key) # Encryption key must be urlsafe-base64-encoded 32-byte key
        self.logger = logger.bind(storage_type="encrypted_file", file_path=str(self.file_path))
        # Ensure file path directory exists, handle file locking for concurrent access if necessary (complex for async)

    @staticmethod
    def derive_key_from_password(password: str, salt: bytes) -> bytes:
        """Derives an encryption key from a password using PBKDF2HMAC-SHA256."""
        if not password:
            raise ValueError("Password cannot be empty for key derivation.")
        if not salt or len(salt) < 16: # Salt should be at least 16 bytes
             raise ValueError("Salt must be provided and be at least 16 bytes for key derivation.")
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32, # Fernet key length
            salt=salt,
            iterations=480000, # NIST recommended minimum for PBKDF2
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    # Actual implementation of store/get/delete methods for EncryptedFileTokenStorage
    # would involve file I/O, locking (e.g. aiofiles, fasteners for async context),
    # and careful handling of encryption/decryption. This is non-trivial.
    # For P0, KeyringTokenStorage is likely sufficient if a keyring backend is available.
    # A full implementation of EncryptedFileTokenStorage is deferred for brevity here
    # but the structure is outlined.

    async def store_oauth_token(self, server_id: str, token: OAuth2Token) -> None:
        self.logger.warning("EncryptedFileTokenStorage.store_oauth_token is not fully implemented.")
        raise NotImplementedError("EncryptedFileTokenStorage is not fully implemented.")

    async def get_oauth_token(self, server_id: str) -> Optional[OAuth2Token]:
        self.logger.warning("EncryptedFileTokenStorage.get_oauth_token is not fully implemented.")
        raise NotImplementedError("EncryptedFileTokenStorage is not fully implemented.")

    async def delete_oauth_token(self, server_id: str) -> None:
        self.logger.warning("EncryptedFileTokenStorage.delete_oauth_token is not fully implemented.")
        raise NotImplementedError("EncryptedFileTokenStorage is not fully implemented.")

    async def store_client_credentials(self, server_id: str, credentials: ClientCredentials) -> None:
        self.logger.warning("EncryptedFileTokenStorage.store_client_credentials is not fully implemented.")
        raise NotImplementedError("EncryptedFileTokenStorage is not fully implemented.")

    async def get_client_credentials(self, server_id: str) -> Optional[ClientCredentials]:
        self.logger.warning("EncryptedFileTokenStorage.get_client_credentials is not fully implemented.")
        raise NotImplementedError("EncryptedFileTokenStorage is not fully implemented.")

    async def delete_client_credentials(self, server_id: str) -> None:
        self.logger.warning("EncryptedFileTokenStorage.delete_client_credentials is not fully implemented.")
        raise NotImplementedError("EncryptedFileTokenStorage is not fully implemented.")


# Factory function or part of TokenManager to select storage based on config
def get_token_storage(auth_config: AuthConfig) -> BaseTokenStorage:
    """
    Factory function to get a token storage instance based on configuration.
    Requires ENCRYPTION_KEY_ENV_VAR or similar for EncryptedFileTokenStorage if used.
    """
    if auth_config.token_storage_method == "keyring":
        return KeyringTokenStorage(auth_config)
    elif auth_config.token_storage_method == "file":
        # Securely get encryption key for file storage
        # Example: key_from_env = os.getenv("MCP_VACUUM_ENCRYPTION_KEY")
        # if not key_from_env:
        #     raise TokenStorageError("Encryption key for file storage not found in env var MCP_VACUUM_ENCRYPTION_KEY.")
        # encryption_key = key_from_env.encode() # Assuming it's already base64 encoded
        # For now, as it's not fully implemented:
        logger.error("EncryptedFileTokenStorage is selected but not fully implemented or encryption key management is pending.")
        raise NotImplementedError("EncryptedFileTokenStorage key management needs secure implementation.")
        # return EncryptedFileTokenStorage(auth_config, encryption_key)
    else:
        logger.error(f"Unsupported token_storage_method: {auth_config.token_storage_method}")
        raise ValueError(f"Unsupported token_storage_method: {auth_config.token_storage_method}")
