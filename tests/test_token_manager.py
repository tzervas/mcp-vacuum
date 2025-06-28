"""
Unit tests for TokenManager.
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
import time

from mcp_vacuum.config import Config, AuthConfig, OAuthClientDetails as AppOAuthClientDetails, MCPServerInfo as ConfigMCPServerInfo # Assuming MCPServerInfo might be in config for defaults
from mcp_vacuum.auth.token_manager import TokenManager
from mcp_vacuum.auth.token_storage import BaseTokenStorage, TokenNotFoundError
from mcp_vacuum.auth.oauth_client import OAuth2Client
from mcp_vacuum.auth.dynamic_registration import DynamicClientRegistrar, DynamicRegistrationError
from mcp_vacuum.models.auth import OAuth2Token, ClientCredentials, OAuth2ClientConfig
from mcp_vacuum.models.mcp import MCPServerInfo, AuthenticationMetadata # MCPServerInfo is used by TokenManager
from mcp_vacuum.models.common import AuthMethod
from mcp_vacuum.mcp_client.exceptions import MCPAuthError

@pytest.fixture
def app_config():
    # Configure default OAuth client details for tests, so _get_oauth_client_config can work
    default_oauth_details = AppOAuthClientDetails(
        client_id="default_test_client_id",
        authorization_endpoint="https://default.example.com/auth",
        token_endpoint="https://default.example.com/token",
        redirect_uri="http://localhost:9090/callback"
    )
    auth_cfg = AuthConfig(oauth_default_client=default_oauth_details, oauth_dynamic_client_registration=False) # Disable DCR by default for some tests
    return Config(auth=auth_cfg)

@pytest.fixture
def mock_token_storage():
    storage = AsyncMock(spec=BaseTokenStorage)
    storage.get_oauth_token = AsyncMock(return_value=None)
    storage.store_oauth_token = AsyncMock()
    storage.delete_oauth_token = AsyncMock()
    storage.get_client_credentials = AsyncMock(return_value=None)
    storage.store_client_credentials = AsyncMock()
    return storage

@pytest.fixture
def token_manager(app_config, mock_token_storage):
    return TokenManager(app_config=app_config, token_storage=mock_token_storage)

@pytest.fixture
def sample_server_info():
    # MCPServerInfo needs auth_metadata for OAuth endpoints
    auth_meta = AuthenticationMetadata(
        method=AuthMethod.OAUTH2_PKCE,
        authorization_endpoint="https://server.example.com/auth",
        token_endpoint="https://server.example.com/token",
        registration_endpoint="https://server.example.com/register" # For DCR tests
    )
    return MCPServerInfo(id="test_server_1", name="TestServer", endpoint="http://testserver.example.com", auth_metadata=auth_meta, registration_endpoint="https://server.example.com/register")


@pytest.mark.asyncio
async def test_get_valid_token_cache_hit(token_manager, sample_server_info):
    """Test getting a valid token from in-memory cache."""
    server_id = sample_server_info.id
    cached_token = OAuth2Token(access_token="cached_valid_token", expires_in=3600) # Valid for 1hr
    token_manager._token_cache[server_id] = cached_token

    retrieved_token = await token_manager.get_valid_oauth_token(server_id, sample_server_info)

    assert retrieved_token == cached_token
    token_manager._token_storage.get_oauth_token.assert_not_called() # Should not hit storage

@pytest.mark.asyncio
async def test_get_valid_token_storage_hit_valid(token_manager, mock_token_storage, sample_server_info):
    """Test getting a valid token from persistent storage."""
    server_id = sample_server_info.id
    stored_valid_token = OAuth2Token(access_token="stored_valid_token", expires_in=3600)
    mock_token_storage.get_oauth_token.return_value = stored_valid_token

    retrieved_token = await token_manager.get_valid_oauth_token(server_id, sample_server_info)

    assert retrieved_token == stored_valid_token
    assert token_manager._token_cache[server_id] == stored_valid_token # Cache updated
    mock_token_storage.get_oauth_token.assert_called_once_with(server_id)

@pytest.mark.asyncio
@patch('mcp_vacuum.auth.token_manager.OAuth2Client') # Patch where OAuth2Client is imported/used
async def test_get_valid_token_storage_hit_expired_refresh_success(
    MockOAuth2Client, token_manager, mock_token_storage, sample_server_info, app_config
):
    """Test getting an expired token from storage, followed by successful refresh."""
    server_id = sample_server_info.id
    expired_stored_token = OAuth2Token(
        access_token="stored_expired_token",
        refresh_token="valid_refresh_token",
        expires_in=10, # Expired soon after creation
        created_at=time.time() - 3600 # Created 1 hour ago
    )
    mock_token_storage.get_oauth_token.return_value = expired_stored_token

    refreshed_token = OAuth2Token(access_token="newly_refreshed_token", expires_in=3600, refresh_token="new_refresh_token_maybe")

    # Mock OAuth2Client instance and its refresh_token method
    mock_oauth_client_instance = AsyncMock(spec=OAuth2Client)
    mock_oauth_client_instance.refresh_token = AsyncMock(return_value=refreshed_token)
    MockOAuth2Client.return_value.__aenter__.return_value = mock_oauth_client_instance # For async context manager

    # Ensure _get_oauth_client_config returns a valid config
    # If server_info.auth_metadata is enough, and no DCR/stored creds needed for this client_id source
    # then this might work. Or mock _get_oauth_client_config.
    # Let's assume default client_id from app_config.auth.oauth_default_client is used.

    retrieved_token = await token_manager.get_valid_oauth_token(server_id, sample_server_info)

    assert retrieved_token == refreshed_token
    mock_token_storage.get_oauth_token.assert_called_once_with(server_id)
    mock_oauth_client_instance.refresh_token.assert_called_once_with(expired_stored_token.refresh_token)
    mock_token_storage.store_oauth_token.assert_called_once_with(server_id, refreshed_token)
    assert token_manager._token_cache[server_id] == refreshed_token

@pytest.mark.asyncio
@patch('mcp_vacuum.auth.token_manager.OAuth2Client')
async def test_get_valid_token_refresh_failure_auth_error(
    MockOAuth2Client, token_manager, mock_token_storage, sample_server_info
):
    """Test token refresh failure due to MCPAuthError (e.g. invalid refresh token)."""
    server_id = sample_server_info.id
    expired_token = OAuth2Token(access_token="acc", refresh_token="invalid_ref", created_at=time.time() - 7200, expires_in=3600)
    mock_token_storage.get_oauth_token.return_value = expired_token

    mock_oauth_client_instance = AsyncMock()
    # Simulate refresh token being invalid, requires re-authentication
    mock_oauth_client_instance.refresh_token = AsyncMock(side_effect=MCPAuthError("Invalid grant", requires_reauth=True))
    MockOAuth2Client.return_value.__aenter__.return_value = mock_oauth_client_instance

    retrieved_token = await token_manager.get_valid_oauth_token(server_id, sample_server_info)

    assert retrieved_token is None # Refresh failed, no valid token
    mock_token_storage.delete_oauth_token.assert_called_once_with(server_id) # Token data should be cleared
    assert server_id not in token_manager._token_cache


@pytest.mark.asyncio
async def test_get_valid_token_no_token_found(token_manager, mock_token_storage, sample_server_info):
    """Test scenario where no token is found in cache or storage."""
    server_id = sample_server_info.id
    mock_token_storage.get_oauth_token.return_value = None # No token in storage

    retrieved_token = await token_manager.get_valid_oauth_token(server_id, sample_server_info)

    assert retrieved_token is None
    mock_token_storage.get_oauth_token.assert_called_once_with(server_id)
    assert server_id not in token_manager._token_cache

@pytest.mark.asyncio
async def test_store_new_token(token_manager, mock_token_storage):
    """Test storing a new token."""
    server_id = "new_server_token"
    new_token = OAuth2Token(access_token="newly_acquired_acc", expires_in=3600)

    await token_manager.store_new_token(server_id, new_token)

    mock_token_storage.store_oauth_token.assert_called_once_with(server_id, new_token)
    assert token_manager._token_cache[server_id] == new_token

@pytest.mark.asyncio
async def test_clear_all_server_credentials(token_manager, mock_token_storage):
    """Test clearing all credentials for a server."""
    server_id = "server_to_clear"
    token_manager._token_cache[server_id] = OAuth2Token(access_token="dummy") # Add to cache

    await token_manager.clear_all_server_credentials(server_id)

    assert server_id not in token_manager._token_cache
    mock_token_storage.delete_oauth_token.assert_called_once_with(server_id)
    mock_token_storage.delete_client_credentials.assert_called_once_with(server_id)


@pytest.mark.asyncio
@patch('mcp_vacuum.auth.token_manager.DynamicClientRegistrar')
async def test_get_oauth_client_config_dynamic_registration_success(
    MockDynamicRegistrar, token_manager, mock_token_storage, sample_server_info, app_config
):
    """Test _get_oauth_client_config with successful dynamic client registration."""
    app_config.auth.oauth_dynamic_client_registration = True # Enable DCR for this test
    server_id = sample_server_info.id
    mock_token_storage.get_client_credentials.return_value = None # No stored credentials

    registered_creds = ClientCredentials(client_id="dyn_client_id", client_secret="dyn_secret")
    mock_registrar_instance = AsyncMock(spec=DynamicClientRegistrar)
    mock_registrar_instance.register_client = AsyncMock(return_value=registered_creds)
    MockDynamicRegistrar.return_value.__aenter__.return_value = mock_registrar_instance # For async context

    client_config = await token_manager._get_oauth_client_config(server_id, sample_server_info, token_manager.logger)

    assert client_config is not None
    assert client_config.client_id == "dyn_client_id"
    assert client_config.client_secret == "dyn_secret"
    mock_registrar_instance.register_client.assert_called_once()
    # Check that new creds were stored
    mock_token_storage.store_client_credentials.assert_called_once_with(server_id, registered_creds)


@pytest.mark.asyncio
async def test_get_oauth_client_config_uses_stored_credentials(
    token_manager, mock_token_storage, sample_server_info
):
    """Test _get_oauth_client_config uses stored client credentials if available."""
    server_id = sample_server_info.id
    stored_creds = ClientCredentials(client_id="stored_client_id_123")
    mock_token_storage.get_client_credentials.return_value = stored_creds

    # DCR should not be attempted if stored creds are found
    with patch('mcp_vacuum.auth.token_manager.DynamicClientRegistrar') as MockDCR:
        client_config = await token_manager._get_oauth_client_config(server_id, sample_server_info, token_manager.logger)
        MockDCR.assert_not_called() # Ensure DCR was not called

    assert client_config is not None
    assert client_config.client_id == "stored_client_id_123"

@pytest.mark.asyncio
async def test_get_oauth_client_config_uses_default_config_fallback(
    token_manager, mock_token_storage, sample_server_info, app_config # app_config has default client
):
    """Test _get_oauth_client_config falls back to default config if no stored/DCR creds."""
    server_id = sample_server_info.id
    mock_token_storage.get_client_credentials.return_value = None # No stored
    app_config.auth.oauth_dynamic_client_registration = False # Disable DCR for this test

    client_config = await token_manager._get_oauth_client_config(server_id, sample_server_info, token_manager.logger)

    assert client_config is not None
    assert client_config.client_id == app_config.auth.oauth_default_client.client_id
    assert client_config.authorization_endpoint == str(sample_server_info.auth_metadata.authorization_endpoint) # Prefers server_info over default
    assert client_config.token_endpoint == str(sample_server_info.auth_metadata.token_endpoint)


@pytest.mark.asyncio
async def test_get_oauth_client_config_no_client_id_fails(
    token_manager, mock_token_storage, sample_server_info, app_config
):
    """Test _get_oauth_client_config fails if no client_id can be determined."""
    server_id = sample_server_info.id
    mock_token_storage.get_client_credentials.return_value = None
    app_config.auth.oauth_dynamic_client_registration = False
    app_config.auth.oauth_default_client = None # Remove default client config

    client_config = await token_manager._get_oauth_client_config(server_id, sample_server_info, token_manager.logger)
    assert client_config is None

# TODO: Test concurrent access to get_valid_oauth_token for the same server_id
# to ensure the lock prevents multiple refresh attempts. This is harder to test directly
# without more complex asyncio synchronization in the test itself.
# One way is to make refresh_token sleep, start two tasks, and check call counts.

@pytest.mark.asyncio
@patch('mcp_vacuum.auth.token_manager.OAuth2Client')
async def test_get_valid_token_concurrent_refresh_lock(
    MockOAuth2Client, token_manager, mock_token_storage, sample_server_info
):
    """Test that concurrent calls to get_valid_oauth_token for an expired token result in only one refresh attempt."""
    server_id = sample_server_info.id
    expired_stored_token = OAuth2Token(
        access_token="concurrent_expired_token",
        refresh_token="concurrent_refresh_token",
        expires_in=10,
        created_at=time.time() - 3600 # Expired 1 hour ago
    )
    mock_token_storage.get_oauth_token.return_value = expired_stored_token

    refreshed_token = OAuth2Token(access_token="concurrent_refreshed_token", expires_in=3600)

    # Mock _perform_token_refresh directly to control its execution and count calls
    # The actual OAuth2Client part is less important here than the lock mechanism.
    # We need to mock the method on the instance of token_manager.

    # Create a counter for _perform_token_refresh calls
    refresh_call_count = 0
    original_perform_refresh = token_manager._perform_token_refresh

    async def mock_perform_refresh_with_delay(*args, **kwargs):
        nonlocal refresh_call_count
        refresh_call_count += 1
        # Simulate network delay for the refresh operation
        await asyncio.sleep(0.2) # Increased delay to ensure tasks contend for lock
        # Call the original method or return a fixed token
        # For simplicity, let's assume it returns a fixed token here,
        # as we've tested the full refresh logic elsewhere.
        # Or, we can mock the OAuth2Client part as in other tests if _get_oauth_client_config is robust

        # In this test, we are focusing on the lock, so _get_oauth_client_config should be reliable
        # or mocked if it makes external calls (like DCR) that we don't want here.
        # Let's ensure _get_oauth_client_config returns something valid without DCR.
        app_config = token_manager.app_config
        app_config.auth.oauth_dynamic_client_registration = False # Disable DCR

        # Simulate a successful refresh that would be done by original_perform_refresh
        # This requires OAuth2Client to be mocked if we were calling original_perform_refresh
        # For this specific test, let's directly return the refreshed_token from this mock
        # and check the call count.

        # The mocked OAuth2Client from the decorator
        mock_oauth_client_instance = AsyncMock(spec=OAuth2Client)
        mock_oauth_client_instance.refresh_token = AsyncMock(return_value=refreshed_token)
        MockOAuth2Client.return_value.__aenter__.return_value = mock_oauth_client_instance

        # This mock is for _perform_token_refresh, so it should return the token
        # and handle storage internally like the original would.
        await token_manager._token_storage.store_oauth_token(server_id, refreshed_token)
        token_manager._token_cache[server_id] = refreshed_token
        return refreshed_token

    with patch.object(token_manager, '_perform_token_refresh', side_effect=mock_perform_refresh_with_delay) as mock_refresh_method:
        task1 = asyncio.create_task(token_manager.get_valid_oauth_token(server_id, sample_server_info))
        task2 = asyncio.create_task(token_manager.get_valid_oauth_token(server_id, sample_server_info))
        task3 = asyncio.create_task(token_manager.get_valid_oauth_token(server_id, sample_server_info))

        results = await asyncio.gather(task1, task2, task3)

    assert refresh_call_count == 1 # Check our manual counter
    mock_refresh_method.assert_called_once() # Check the mock object's call count

    for result_token in results:
        assert result_token is not None
        assert result_token.access_token == "concurrent_refreshed_token"

    # Verify token is stored and cached
    mock_token_storage.store_oauth_token.assert_called_with(server_id, refreshed_token)
    assert token_manager._token_cache[server_id] == refreshed_token
