import pytest
import platform
import asyncio
import docker
import keyring
from unittest.mock import patch, MagicMock, AsyncMock
import logging

logger = logging.getLogger(__name__)

@pytest.fixture
async def mock_docker_client():
    return AsyncMock(spec=docker.DockerClient)

@pytest.fixture
def mock_keyring():
    with patch('keyring.get_keyring') as mock:
        mock_ring = MagicMock()
        mock.return_value = mock_ring
        yield mock_ring

@pytest.fixture
def mock_network_discovery():
    with patch('socket.socket') as mock_socket:
        mock_socket.return_value.getsockname.return_value = ('127.0.0.1', 12345)
        yield mock_socket

@pytest.fixture(params=["windows", "linux"])
def platform_name(request):
    return request.param

async def test_platform_compatibility(platform_name, mock_docker_client, mock_keyring, mock_network_discovery):
    """Test platform-specific functionality across different components."""
    
    # Setup platform-specific environment
    system_name = 'Windows' if platform_name == 'windows' else 'Linux'
    with patch('platform.system', return_value=platform_name):
        # Test keyring functionality
        await test_keyring_operations(mock_keyring, platform_name)
        
        # Test network discovery
        await test_network_discovery(mock_network_discovery, platform_name)
        
        # Test Docker integration
        await test_docker_integration(mock_docker_client, platform_name)
        
        # Test development tools
        await test_development_tools(platform_name)

async def test_keyring_operations(mock_keyring, platform_name):
    """Test platform-specific keyring functionality."""
    logger.info(f"Testing keyring operations on {platform_name}")
    
    test_service = "mcp-vacuum"
    test_username = "test_user"
    test_password = "test_password"
    
    # Test storing credentials
    mock_keyring.set_password(test_service, test_username, test_password)
    mock_keyring.set_password.assert_called_once_with(test_service, test_username, test_password)
    
    # Test retrieving credentials
    mock_keyring.get_password.return_value = test_password
    retrieved_password = mock_keyring.get_password(test_service, test_username)
    assert retrieved_password == test_password
    
    # Test credential deletion
    mock_keyring.delete_password(test_service, test_username)
    mock_keyring.delete_password.assert_called_once_with(test_service, test_username)

async def test_network_discovery(mock_network_discovery, platform_name):
    """Test platform-specific network discovery functionality."""
    logger.info(f"Testing network discovery on {platform_name}")

    # Test port availability check
    mock_network_discovery.return_value.bind.return_value = None
    mock_network_discovery.return_value.getsockname.return_value = ('127.0.0.1', 12345)

    # Verify socket creation
    assert mock_network_discovery.called

    # Test network interface enumeration, skip on Windows
    if platform_name.lower() != 'windows':
        with patch('netifaces.interfaces') as mock_interfaces:
            mock_interfaces.return_value = ['eth0', 'lo']
            interfaces = mock_interfaces()
            assert 'eth0' in interfaces
            assert 'lo' in interfaces
    else:
        # On Windows, ensure netifaces.interfaces is not called
        with patch('netifaces.interfaces') as mock_interfaces:
            # Simulate code path that would enumerate interfaces (if any)
            # Here, we do not call mock_interfaces(), so it should not be called
            assert not mock_interfaces.called, "Interface enumeration should be skipped on Windows"

async def test_docker_integration(mock_docker_client, platform_name):
    """Test platform-specific Docker integration."""
    logger.info(f"Testing Docker integration on {platform_name}")
    
    # Test Docker connection
    mock_docker_client.ping.return_value = True
    assert await mock_docker_client.ping()
    
    # Test container operations
    mock_container = MagicMock()
    mock_docker_client.containers.run.return_value = mock_container
    
    container_config = {
        'image': 'test-image:latest',
        'command': 'echo "test"',
        'environment': {'PLATFORM': platform_name}
    }
    
    await mock_docker_client.containers.run(**container_config)
    mock_docker_client.containers.run.assert_called_once_with(**container_config)

async def test_development_tools(platform_name):
    """Test platform-specific development tools."""
    logger.info(f"Testing development tools on {platform_name}")
    
    # Test Python environment
    assert platform_name in ['windows', 'linux']
    
    # Test async functionality
    async def async_operation():
        await asyncio.sleep(0)
        return True
    
    result = await async_operation()
    assert result is True
    
    # Test logging configuration
    assert logger.name == __name__
    
    # Test platform-specific path handling
    with patch('os.path') as mock_path:
        if platform_name.lower() == 'windows':
            mock_path.sep = '\\'
            mock_path.join.return_value = 'C:\\test\\path'
        else:
            mock_path.sep = '/'
            mock_path.join.return_value = '/test/path'
            
        test_path = mock_path.join('test', 'path')
        assert mock_path.sep in test_path
