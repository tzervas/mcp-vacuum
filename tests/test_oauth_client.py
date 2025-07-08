"""
Unit tests for OAuth2Client.
"""
import json
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import parse_qs, urlparse

import pytest  # type: ignore[import-not-found]
import aiohttp  # type: ignore[import-not-found]

from mcp_vacuum.auth.oauth_client import OAuth2Client
from mcp_vacuum.auth.pkce import generate_pkce_challenge_pair
from mcp_vacuum.config import Config
from mcp_vacuum.mcp_client.exceptions import MCPAuthError, MCPConnectionError
from mcp_vacuum.models.auth import OAuth2ClientConfig as AppOAuthClientConfig
from mcp_vacuum.models.auth import OAuth2Token, OAuthError


# Default app_config for tests
@pytest.fixture
def app_config():
    return Config()

# Default OAuth2ClientConfig for tests
@pytest.fixture
def oauth_client_config_data():
    return AppOAuthClientConfig(
        client_id="test_client_id",
        token_endpoint="https://example.com/token",
        authorization_endpoint="https://example.com/authorize",
        redirect_uri="http://localhost:8080/callback",
        scopes=["openid", "profile", "mcp:tools"]
    )

@pytest.fixture
def oauth_client(oauth_client_config_data, app_config):
    # Session will be created internally by OAuth2Client if not provided
    return OAuth2Client(client_config=oauth_client_config_data, app_config=app_config)

@pytest.mark.asyncio
async def test_oauth_client_create_authorization_url(oauth_client):
    """Test creation of the authorization URL."""
    pkce = generate_pkce_challenge_pair()
    state = "test_state_123"

    auth_url, out_state, out_verifier = oauth_client.create_authorization_url(state=state, pkce=pkce)

    assert out_state == state
    assert out_verifier == pkce.code_verifier

    parsed_url = urlparse(auth_url)
    query_params = parse_qs(parsed_url.query)

    assert parsed_url.scheme == "https"
    assert parsed_url.netloc == "example.com"
    assert parsed_url.path == "/authorize"
    assert query_params["response_type"] == ["code"]
    assert query_params["client_id"] == [oauth_client.client_config.client_id]
    assert query_params["redirect_uri"] == [str(oauth_client.client_config.redirect_uri)]
    assert query_params["scope"] == [" ".join(oauth_client.client_config.scopes)]
    assert query_params["state"] == [state]
    assert query_params["code_challenge"] == [pkce.code_challenge]
    assert query_params["code_challenge_method"] == [pkce.code_challenge_method]

    await oauth_client.close_session() # Clean up session

@pytest.mark.asyncio
async def test_oauth_client_exchange_code_for_token_success(oauth_client, app_config):
    """Test successful exchange of authorization code for token."""
    mock_session_post = AsyncMock()

    # Mock successful token response
    token_response_data = {
        "access_token": "mock_access_token",
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": "mock_refresh_token",
        "scope": "openid profile"
    }
    mock_response = AsyncMock()
    mock_response.status = 200
    mock_response.text = AsyncMock(return_value=json.dumps(token_response_data))
    mock_response.json = AsyncMock(return_value=token_response_data) # If client uses .json()

    mock_session_post.return_value.__aenter__.return_value = mock_response # Simulate context manager

    # Patch the _get_session method to return a session that uses our mock_session_post
    mock_aiohttp_session = MagicMock()
    mock_aiohttp_session.post = mock_session_post

    with patch.object(oauth_client, '_get_session', AsyncMock(return_value=mock_aiohttp_session)):
        auth_code = "test_auth_code"
        verifier = "test_verifier_long_enough_for_pkce_if_it_mattered_here" # Actual verifier value

        token = await oauth_client.exchange_code_for_token(code=auth_code, code_verifier=verifier)

        assert isinstance(token, OAuth2Token)
        assert token.access_token == "mock_access_token"
        assert token.refresh_token == "mock_refresh_token"

        # Check that session.post was called correctly
        mock_session_post.assert_called_once()
        call_args = mock_session_post.call_args
        assert call_args[0][0] == str(oauth_client.client_config.token_endpoint)
        payload = call_args[1]['data']
        assert payload['grant_type'] == "authorization_code"
        assert payload['code'] == auth_code
        assert payload['code_verifier'] == verifier
        assert payload['client_id'] == oauth_client.client_config.client_id
        assert payload['redirect_uri'] == str(oauth_client.client_config.redirect_uri)

    await oauth_client.close_session()


@pytest.mark.asyncio
async def test_oauth_client_exchange_code_for_token_failure(oauth_client):
    """Test failed exchange of authorization code (e.g., server error)."""
    mock_session_post = AsyncMock()

    error_response_data = {"error": "invalid_grant", "error_description": "Authorization code expired"}
    mock_response = AsyncMock()
    mock_response.status = 400 # Bad Request
    mock_response.text = AsyncMock(return_value=json.dumps(error_response_data))

    mock_session_post.return_value.__aenter__.return_value = mock_response

    mock_aiohttp_session = MagicMock()
    mock_aiohttp_session.post = mock_session_post

    with patch.object(oauth_client, '_get_session', AsyncMock(return_value=mock_aiohttp_session)):
        with pytest.raises(MCPAuthError) as excinfo:
            await oauth_client.exchange_code_for_token(code="invalid_code", code_verifier="verifier")

        assert "Token exchange failed: invalid_grant" in str(excinfo.value)
        assert isinstance(excinfo.value.server_error, OAuthError)
        assert excinfo.value.server_error.error == "invalid_grant"

    await oauth_client.close_session()

@pytest.mark.asyncio
async def test_oauth_client_refresh_token_success(oauth_client):
    """Test successful token refresh."""
    mock_session_post = AsyncMock()

    refreshed_token_data = {
        "access_token": "new_mock_access_token",
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": "new_mock_refresh_token", # Server might return a new refresh token
        "scope": "openid profile"
    }
    mock_response = AsyncMock()
    mock_response.status = 200
    mock_response.text = AsyncMock(return_value=json.dumps(refreshed_token_data))

    mock_session_post.return_value.__aenter__.return_value = mock_response

    mock_aiohttp_session = MagicMock()
    mock_aiohttp_session.post = mock_session_post

    with patch.object(oauth_client, '_get_session', AsyncMock(return_value=mock_aiohttp_session)):
        original_refresh_token = "old_refresh_token_value"
        new_token = await oauth_client.refresh_token(original_refresh_token)

        assert new_token.access_token == "new_mock_access_token"
        assert new_token.refresh_token == "new_mock_refresh_token"

        payload = mock_session_post.call_args[1]['data']
        assert payload['grant_type'] == "refresh_token"
        assert payload['refresh_token'] == original_refresh_token
        assert payload['client_id'] == oauth_client.client_config.client_id

    await oauth_client.close_session()


@pytest.mark.asyncio
async def test_oauth_client_refresh_token_no_new_refresh_token_returned(oauth_client):
    """Test token refresh when server doesn't return a new refresh token."""
    mock_session_post = AsyncMock()

    refreshed_token_data = { # No refresh_token in this response
        "access_token": "new_access_token_only",
        "token_type": "Bearer",
        "expires_in": 1800,
        "scope": "openid"
    }
    mock_response = AsyncMock()
    mock_response.status = 200
    mock_response.text = AsyncMock(return_value=json.dumps(refreshed_token_data))

    mock_session_post.return_value.__aenter__.return_value = mock_response

    mock_aiohttp_session = MagicMock()
    mock_aiohttp_session.post = mock_session_post

    with patch.object(oauth_client, '_get_session', AsyncMock(return_value=mock_aiohttp_session)):
        original_refresh_token = "persistent_refresh_token"
        new_token = await oauth_client.refresh_token(original_refresh_token)

        assert new_token.access_token == "new_access_token_only"
        assert new_token.refresh_token == original_refresh_token # Should retain the old one

    await oauth_client.close_session()


@pytest.mark.asyncio
async def test_oauth_client_refresh_token_invalid_grant(oauth_client):
    """Test token refresh failure due to invalid grant (e.g., revoked refresh token)."""
    mock_session_post = AsyncMock()

    error_response_data = {"error": "invalid_grant", "error_description": "Refresh token is invalid or revoked"}
    mock_response = AsyncMock()
    mock_response.status = 400
    mock_response.text = AsyncMock(return_value=json.dumps(error_response_data))

    mock_session_post.return_value.__aenter__.return_value = mock_response

    mock_aiohttp_session = MagicMock()
    mock_aiohttp_session.post = mock_session_post # Corrected typo here

    with patch.object(oauth_client, '_get_session', AsyncMock(return_value=mock_aiohttp_session)):
        with pytest.raises(MCPAuthError) as excinfo:
            await oauth_client.refresh_token("revoked_refresh_token")

        assert "Refresh token likely invalid/revoked" in str(excinfo.value)
        assert excinfo.value.requires_reauth is True

    await oauth_client.close_session()

@pytest.mark.asyncio
async def test_oauth_client_connection_error(oauth_client_config_data, app_config):
    """Test connection error during token exchange."""
    # Create client without patching _get_session initially to test session creation path
    client_under_test = OAuth2Client(client_config=oauth_client_config_data, app_config=app_config)

    mock_session_post = AsyncMock(side_effect=aiohttp.ClientConnectorError(MagicMock(), OSError("Connection timed out")))

    # We need to mock the session that client_under_test will create.
    # Patch aiohttp.ClientSession globally for this test, or patch where it's instantiated.
    # A simpler way for this specific test: mock the session object after it's created by _get_session.

    # Let _get_session run once to create the session object
    real_session = await client_under_test._get_session()
    # Now, replace its post method with our mock
    real_session.post = mock_session_post

    with pytest.raises(MCPConnectionError) as excinfo:
        await client_under_test.exchange_code_for_token(code="any_code", code_verifier="any_verifier")

    assert "Connection to token endpoint" in str(excinfo.value)
    assert "failed: Connection timed out" in str(excinfo.value)

    await client_under_test.close_session()

# Helper method test cases
@pytest.mark.asyncio
async def test_prepare_token_request(oauth_client):
    """Test _prepare_token_request helper method."""
    token_request_data = TokenRequest(
        grant_type="test_grant",
        code="test_code",
        client_id=oauth_client.client_config.client_id
    )

    payload, headers, timeout = oauth_client._prepare_token_request("test_grant", token_request_data)

    # Check payload
    assert payload == token_request_data.model_dump(exclude_none=True, by_alias=True)

    # Check headers
    assert headers["Content-Type"] == "application/x-www-form-urlencoded"
    assert headers["Accept"] == "application/json"

    # Check timeout settings
    assert isinstance(timeout, aiohttp.ClientTimeout)
    assert timeout.total == oauth_client.app_config.mcp_client.request_timeout_seconds
    assert timeout.connect == oauth_client.app_config.mcp_client.connect_timeout_seconds

    await oauth_client.close_session()

@pytest.mark.asyncio
async def test_send_token_request_success(oauth_client):
    """Test _send_token_request helper method for successful case."""
    mock_session_post = AsyncMock()
    response_data = {"access_token": "test_token"}
    mock_response = AsyncMock()
    mock_response.status = 200
    mock_response.text = AsyncMock(return_value=json.dumps(response_data))
    mock_session_post.return_value.__aenter__.return_value = mock_response

    mock_aiohttp_session = MagicMock()
    mock_aiohttp_session.post = mock_session_post

    with patch.object(oauth_client, '_get_session', AsyncMock(return_value=mock_aiohttp_session)):
        payload = {"grant_type": "test_grant"}
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        timeout = aiohttp.ClientTimeout(total=30)

        result = await oauth_client._send_token_request(payload, headers, timeout)
        assert result == response_data

    await oauth_client.close_session()

@pytest.mark.asyncio
async def test_handle_error_response_invalid_grant(oauth_client):
    """Test _handle_error_response helper method with invalid_grant error."""
    error_body = json.dumps({
        "error": "invalid_grant",
        "error_description": "Refresh token is invalid or revoked"
    })

    with pytest.raises(MCPAuthError) as excinfo:
        await oauth_client._handle_error_response(400, error_body)

    assert "Token refresh failed" in str(excinfo.value)
    assert excinfo.value.requires_reauth is True
    assert isinstance(excinfo.value.server_error, OAuthError)

    await oauth_client.close_session()

@pytest.mark.asyncio
async def test_handle_error_response_non_json(oauth_client):
    """Test _handle_error_response helper method with non-JSON response."""
    error_body = "Internal Server Error"

    with pytest.raises(MCPAuthError) as excinfo:
        await oauth_client._handle_error_response(500, error_body)

    assert "Token request failed with status 500" in str(excinfo.value)

    await oauth_client.close_session()

def test_parse_token_response_success(oauth_client):
    """Test _parse_token_response helper method for successful case."""
    token_data = {
        "access_token": "test_access_token",
        "token_type": "Bearer",
        "expires_in": 3600
    }

    token = oauth_client._parse_token_response(token_data, "existing_refresh_token")

    assert isinstance(token, OAuth2Token)
    assert token.access_token == "test_access_token"
    assert token.refresh_token == "existing_refresh_token"
    assert token.expires_in == 3600

def test_parse_token_response_invalid_data(oauth_client):
    """Test _parse_token_response helper method with invalid data."""
    invalid_token_data = {
        "not_a_token": "invalid"
    }

    with pytest.raises(MCPAuthError) as excinfo:
        oauth_client._parse_token_response(invalid_token_data)

    assert "Invalid token data received" in str(excinfo.value)

# TODO: Add tests for state mismatch in exchange_code_for_token.
# TODO: Add tests for session management (owned vs provided session).
# TODO: Test different SSL verification scenarios if _get_session SSL logic becomes more complex.
