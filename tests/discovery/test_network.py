"""Tests for network interface discovery module."""

import platform
import asyncio
from unittest.mock import patch, MagicMock

import pytest
from mcp_vacuum.models.common import TransportType, AuthMethod
from mcp_vacuum.discovery.network import (
    get_network_interfaces,
    get_windows_interfaces,
    get_linux_interfaces,
    get_interface_ips,
    get_active_interfaces,
    NetworkDiscovery
)

def test_get_network_interfaces_with_netifaces():
    """Test successful netifaces-based interface discovery."""
    mock_interfaces = ['eth0', 'wlan0', 'lo']
    with patch('netifaces.interfaces', return_value=mock_interfaces):
        interfaces = get_network_interfaces()
        assert 'eth0' in interfaces
        assert 'wlan0' in interfaces
        assert 'lo' not in interfaces  # Should be filtered out

def test_get_network_interfaces_windows_fallback():
    """Test Windows fallback when netifaces fails."""
    with patch('netifaces.interfaces', side_effect=Exception("netifaces error")), \
         patch('platform.system', return_value="Windows"), \
         patch('subprocess.check_output', return_value="Admin State    State        Type             Interface Name\nEnabled        Connected     Dedicated       Ethernet\n"):
        interfaces = get_network_interfaces()
        assert 'Ethernet' in interfaces

def test_get_network_interfaces_linux_fallback():
    """Test Linux fallback when netifaces fails."""
    with patch('netifaces.interfaces', side_effect=Exception("netifaces error")), \
         patch('platform.system', return_value="Linux"), \
         patch('subprocess.check_output', return_value="1: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP>\n2: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP>\n"):
        interfaces = get_network_interfaces()
        assert 'eth0' in interfaces
        assert 'wlan0' in interfaces

def test_get_interface_ips():
    """Test getting IP addresses for an interface."""
    mock_addr_info = {
        netifaces.AF_INET: [{'addr': '192.168.1.100'}],
        netifaces.AF_INET6: [{'addr': 'fe80::1234%eth0'}]
    }
    with patch('netifaces.ifaddresses', return_value=mock_addr_info):
        ips = get_interface_ips('eth0')
        assert '192.168.1.100' in ips
        assert 'fe80::1234' in ips  # Interface identifier should be stripped

def test_get_active_interfaces():
    """Test getting only active interfaces with IP addresses."""
    with patch('mcp_vacuum.discovery.network.get_network_interfaces', return_value=['eth0', 'wlan0']), \
         patch('mcp_vacuum.discovery.network.get_interface_ips', side_effect=[{'192.168.1.100'}, set()]):
        interfaces = get_active_interfaces()
        assert 'eth0' in interfaces
        assert 'wlan0' not in interfaces  # No IPs, should be excluded

def test_get_interface_ips_no_ips():
    """Test handling of interface with no IP addresses."""
    with patch('netifaces.ifaddresses', return_value={}):
        ips = get_interface_ips('eth0')
        assert len(ips) == 0

def test_get_interface_ips_error_handling():
    """Test error handling when getting interface IPs."""
    with patch('netifaces.ifaddresses', side_effect=OSError("Test error")):
        ips = get_interface_ips('eth0')
        assert len(ips) == 0

@pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
def test_get_windows_interfaces():
    """Test Windows interface discovery (only on Windows)."""
    mock_output = "Admin State    State        Type             Interface Name\nEnabled        Connected     Dedicated       Ethernet\n"
    with patch('subprocess.check_output', return_value=mock_output):
        interfaces = get_windows_interfaces()
        assert 'Ethernet' in interfaces

@pytest.mark.skipif(platform.system() != "Linux", reason="Linux-specific test")
def test_get_linux_interfaces():
    """Test Linux interface discovery (only on Linux)."""
    mock_output = "1: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP>\n2: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP>\n"
    with patch('subprocess.check_output', return_value=mock_output):
        interfaces = get_linux_interfaces()
        assert 'eth0' in interfaces
        assert 'wlan0' in interfaces

# NetworkDiscovery Class Tests
@pytest.fixture
def network_discovery():
    return NetworkDiscovery()

@pytest.mark.asyncio
@patch('mcp_vacuum.discovery.network.get_network_interfaces')
@patch('mcp_vacuum.discovery.network.get_interface_ips')
async def test_discover_services(mock_get_ips, mock_get_interfaces, network_discovery):
    """Test service discovery on network interfaces."""
    # Mock network interfaces
    mock_get_interfaces.return_value = ['eth0', 'wlan0']
    
    # Mock IP addresses for interfaces
    mock_get_ips.side_effect = lambda iface: {
        'eth0': {'192.168.1.100'},
        'wlan0': {'192.168.2.100'}
    }[iface]

    # Collect discovered services
    services = []
    async for service in network_discovery.discover_services():
        services.append(service)

    # Verify discovered services
    assert len(services) == 2
    
    # Check eth0 service
    eth0_service = next(s for s in services if '192.168.1.100' in s.endpoint)
    assert eth0_service.id == 'network-eth0-192.168.1.100'
    assert eth0_service.transport_type == TransportType.HTTP
    assert eth0_service.discovery_method == 'network'
    assert eth0_service.auth_method == AuthMethod.NONE

    # Check wlan0 service
    wlan0_service = next(s for s in services if '192.168.2.100' in s.endpoint)
    assert wlan0_service.id == 'network-wlan0-192.168.2.100'
    assert wlan0_service.transport_type == TransportType.HTTP
    assert wlan0_service.discovery_method == 'network'
    assert wlan0_service.auth_method == AuthMethod.NONE

@pytest.mark.asyncio
async def test_get_network_interfaces_async(network_discovery):
    """Test network interface retrieval."""
    with patch('mcp_vacuum.discovery.network.get_network_interfaces') as mock_get_interfaces:
        mock_get_interfaces.return_value = ['eth0', 'wlan0']
        
        interfaces = await network_discovery.get_network_interfaces()
        
        assert interfaces == ['eth0', 'wlan0']
        mock_get_interfaces.assert_called_once_with(skip_loopback=True)
