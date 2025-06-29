"""
Unit tests for TokenStorage implementations.
"""
from unittest.mock import MagicMock, patch

import pytest

from mcp_vacuum.auth.token_storage import (
    KeyringTokenStorage,
    TokenStorageError,
    get_token_storage,
)
from mcp_vacuum.config import AuthConfig
from mcp_vacuum.models.auth import ClientCredentials, OAuth2Token


@pytest.fixture
def auth_config_keyring():
    return AuthConfig(token_storage_method="keyring", keyring_service_name="test_mcp_vacuum_service")

@pytest.fixture
def mock_keyring_module():
    with patch('mcp_vacuum.auth.token_storage.keyring') as mock_keyring:
        # Setup mock keyring to behave like a dictionary for tests
        mock_keyring_db = {}

        def set_password_mock(service, username, password):
            mock_keyring_db[(service, username)] = password

        def get_password_mock(service, username):
            return mock_keyring_db.get((service, username))

        def delete_password_mock(service, username):
            # Allow trying to delete non-existent passwords without error, like some backends
            mock_keyring_db.pop((service, username), None)
            # To simulate PasswordDeleteError if item not found, you could:
            # if (service, username) not in mock_keyring_db:
            #     raise keyring.errors.PasswordDeleteError("not found")
            # mock_keyring_db.pop((service, username), None)

        mock_keyring.set_password = MagicMock(side_effect=set_password_mock)
        mock_keyring.get_password = MagicMock(side_effect=get_password_mock)
        mock_keyring.delete_password = MagicMock(side_effect=delete_password_mock)
        mock_keyring.errors = MagicMock() # Mock the errors submodule
        mock_keyring.errors.NoKeyringError = type('NoKeyringError', (Exception,), {})
        mock_keyring.errors.PasswordDeleteError = type('PasswordDeleteError', (Exception,), {})

        yield mock_keyring, mock_keyring_db # Allow tests to inspect the mock_db

@pytest.mark.asyncio
async def test_keyring_store_and_get_oauth_token(auth_config_keyring, mock_keyring_module):
    """Test storing and retrieving OAuth2Token using KeyringTokenStorage."""
    mock_keyring, db = mock_keyring_module
    storage = KeyringTokenStorage(auth_config_keyring)

    server_id = "server_oauth_1"
    token_data = OAuth2Token(access_token="acc123", refresh_token="ref456", expires_in=3600)

    await storage.store_oauth_token(server_id, token_data)

    # Verify keyring.set_password was called
    expected_key = f"{server_id}{storage.OAUTH_TOKEN_SUFFIX}"
    mock_keyring.set_password.assert_called_once_with(
        auth_config_keyring.keyring_service_name,
        expected_key,
        token_data.model_dump_json()
    )
    assert (auth_config_keyring.keyring_service_name, expected_key) in db

    retrieved_token = await storage.get_oauth_token(server_id)
    assert retrieved_token is not None
    assert retrieved_token.access_token == token_data.access_token
    assert retrieved_token.refresh_token == token_data.refresh_token

    mock_keyring.get_password.assert_called_with(
        auth_config_keyring.keyring_service_name,
        expected_key
    )

@pytest.mark.asyncio
async def test_keyring_get_non_existent_oauth_token(auth_config_keyring, mock_keyring_module):
    """Test retrieving a non-existent OAuth2Token."""
    mock_keyring, _ = mock_keyring_module
    storage = KeyringTokenStorage(auth_config_keyring)

    retrieved_token = await storage.get_oauth_token("non_existent_server")
    assert retrieved_token is None
    mock_keyring.get_password.assert_called_once()

@pytest.mark.asyncio
async def test_keyring_delete_oauth_token(auth_config_keyring, mock_keyring_module):
    """Test deleting an OAuth2Token."""
    mock_keyring, db = mock_keyring_module
    storage = KeyringTokenStorage(auth_config_keyring)
    server_id = "server_oauth_to_delete"
    token_data = OAuth2Token(access_token="delete_me_acc", expires_in=100)

    # Store it first
    await storage.store_oauth_token(server_id, token_data)
    expected_key = f"{server_id}{storage.OAUTH_TOKEN_SUFFIX}"
    assert (auth_config_keyring.keyring_service_name, expected_key) in db

    # Delete it
    await storage.delete_oauth_token(server_id)
    mock_keyring.delete_password.assert_called_with(
        auth_config_keyring.keyring_service_name,
        expected_key
    )
    assert (auth_config_keyring.keyring_service_name, expected_key) not in db

    # Try to get it again, should be None
    assert await storage.get_oauth_token(server_id) is None

@pytest.mark.asyncio
async def test_keyring_store_and_get_client_credentials(auth_config_keyring, mock_keyring_module):
    """Test storing and retrieving ClientCredentials."""
    mock_keyring, db = mock_keyring_module
    storage = KeyringTokenStorage(auth_config_keyring)
    server_id = "server_creds_1"
    creds_data = ClientCredentials(client_id="client123", client_secret="secretABC") # Secret optional

    await storage.store_client_credentials(server_id, creds_data)
    expected_key = f"{server_id}{storage.CLIENT_CREDS_SUFFIX}"
    mock_keyring.set_password.assert_called_with(
        auth_config_keyring.keyring_service_name,
        expected_key,
        creds_data.model_dump_json()
    )
    assert (auth_config_keyring.keyring_service_name, expected_key) in db


    retrieved_creds = await storage.get_client_credentials(server_id)
    assert retrieved_creds is not None
    assert retrieved_creds.client_id == creds_data.client_id
    assert retrieved_creds.client_secret == creds_data.client_secret

@pytest.mark.asyncio
async def test_keyring_corrupted_json_data(auth_config_keyring, mock_keyring_module):
    """Test handling of corrupted JSON data in keyring."""
    mock_keyring, db = mock_keyring_module
    storage = KeyringTokenStorage(auth_config_keyring)
    server_id = "server_corrupt"
    expected_key = f"{server_id}{storage.OAUTH_TOKEN_SUFFIX}"

    # Manually put corrupted JSON into the mock db
    db[(auth_config_keyring.keyring_service_name, expected_key)] = "this is not json"

    token = await storage.get_oauth_token(server_id)
    assert token is None
    # Check if delete_password was called to clean up corrupted entry
    mock_keyring.delete_password.assert_called_with(auth_config_keyring.keyring_service_name, expected_key)
    assert (auth_config_keyring.keyring_service_name, expected_key) not in db


@pytest.mark.asyncio
async def test_keyring_no_backend_error_on_set(auth_config_keyring, mock_keyring_module):
    """Test NoKeyringError on set_password."""
    mock_keyring, _ = mock_keyring_module
    storage = KeyringTokenStorage(auth_config_keyring)
    mock_keyring.set_password.side_effect = mock_keyring.errors.NoKeyringError("No backend")

    with pytest.raises(TokenStorageError, match="No keyring backend available"):
        await storage.store_oauth_token("s1", OAuth2Token(access_token="t"))

@pytest.mark.asyncio
async def test_keyring_no_backend_error_on_get(auth_config_keyring, mock_keyring_module):
    """Test NoKeyringError on get_password."""
    mock_keyring, _ = mock_keyring_module
    storage = KeyringTokenStorage(auth_config_keyring)
    mock_keyring.get_password.side_effect = mock_keyring.errors.NoKeyringError("No backend")

    with pytest.raises(TokenStorageError, match="No keyring backend available"):
        await storage.get_oauth_token("s1")


def test_get_token_storage_factory(auth_config_keyring):
    """Test the get_token_storage factory function."""
    storage = get_token_storage(auth_config_keyring)
    assert isinstance(storage, KeyringTokenStorage)

    # Test for unsupported method
    unsupported_config = AuthConfig(token_storage_method="unsupported_method")
    with pytest.raises(ValueError, match="Unsupported token_storage_method: unsupported_method"):
        get_token_storage(unsupported_config)

    # Test for file method (currently raises NotImplementedError for key management)
    file_config = AuthConfig(token_storage_method="file", encrypted_token_file_path="dummy.enc")
    with pytest.raises(NotImplementedError, match="EncryptedFileTokenStorage key management needs secure implementation"):
        get_token_storage(file_config)

# EncryptedFileTokenStorage tests are deferred as its implementation is incomplete.
# When implemented, tests would need to cover:
# - Key derivation (if using password)
# - File creation, read, write, encryption, decryption
# - Handling of file not found, permission errors
# - Atomicity of file operations (if possible/needed)
