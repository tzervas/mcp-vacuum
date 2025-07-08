"""Network interface discovery utilities for MCP Vacuum."""

import asyncio
import logging
import netifaces
import platform
import subprocess
import socket
from typing import List, Optional, Set, AsyncGenerator
import structlog

from ..models.mcp import MCPServiceRecord
from ..models.common import TransportType, AuthMethod

logger = structlog.get_logger(__name__)

def get_windows_interfaces() -> List[str]:
    """Get network interfaces on Windows using netsh.
    
    Returns:
        List[str]: List of interface names.
    """
    try:
        output = subprocess.check_output(
            ["netsh", "interface", "show", "interface"], 
            universal_newlines=True
        )
        interfaces = []
        for line in output.split('\n')[3:]:  # Skip header rows
            if line.strip():
                parts = line.split()
                if len(parts) >= 4 and parts[0] == "Enabled":
                    interfaces.append(parts[3])  # Interface name is in 4th column
        return interfaces
    except (subprocess.SubprocessError, IndexError) as e:
        logger.error("Failed to get Windows interfaces", error=str(e))
        return []

def get_linux_interfaces() -> List[str]:
    """Get network interfaces on Linux using ip command.
    
    Returns:
        List[str]: List of interface names.
    """
    try:
        output = subprocess.check_output(
            ["ip", "link", "show"], 
            universal_newlines=True
        )
        interfaces = []
        for line in output.split('\n'):
            if ": " in line:  # Lines with interfaces contain ": "
                iface = line.split(": ")[1].split("@")[0]  # Get interface name
                if iface != "lo":  # Skip loopback
                    interfaces.append(iface)
        return interfaces
    except subprocess.SubprocessError as e:
        logger.error("Failed to get Linux interfaces", error=str(e))
        return []

def get_network_interfaces(skip_loopback: bool = True) -> List[str]:
    """Get list of network interfaces in a platform-agnostic way.
    
    Args:
        skip_loopback: Whether to exclude loopback interfaces.
        
    Returns:
        List[str]: List of interface names.
    """
    try:
        interfaces = netifaces.interfaces()
        if skip_loopback:
            # Filter out loopback interfaces (typically 'lo' on Unix, 'Loopback' on Windows)
            interfaces = [
                iface for iface in interfaces 
                if not (iface.lower().startswith(("lo", "loopback")))
            ]
        return interfaces
    except Exception as e:
        logger.warning("netifaces discovery failed: %s, trying platform-specific fallback", str(e))
        
        # Platform-specific fallbacks
        if platform.system() == "Windows":
            return get_windows_interfaces()
        return get_linux_interfaces()

def get_interface_ips(interface: str) -> Set[str]:
    """Get all IP addresses for a given interface.
    
    Args:
        interface: Network interface name.
        
    Returns:
        Set[str]: Set of IP addresses associated with the interface.
    """
    addresses = set()
    try:
        addr_info = netifaces.ifaddresses(interface)
        # Get IPv4 addresses
        if netifaces.AF_INET in addr_info:
            for addr in addr_info[netifaces.AF_INET]:
                if 'addr' in addr:
                    addresses.add(addr['addr'])
        # Get IPv6 addresses
        if netifaces.AF_INET6 in addr_info:
            for addr in addr_info[netifaces.AF_INET6]:
                if 'addr' in addr:
                    # Remove interface identifier from IPv6 address
                    addresses.add(addr['addr'].split('%')[0])
        return addresses
    except (ValueError, KeyError, OSError) as e:
        logger.error("Failed to get addresses for interface %s: %s", interface, str(e))
        return set()

def get_active_interfaces() -> List[str]:
    """Get list of active network interfaces that have IP addresses.
    
    Returns:
        List[str]: List of active interface names.
    """
    active = [
        iface for iface in get_network_interfaces() if get_interface_ips(iface)
    ]
return active


class NetworkDiscovery:
    """Handles network interface and address discovery."""

    def __init__(self):
        self._active_discoveries = set()

    async def get_network_interfaces(self) -> List[str]:
        """Retrieve non-loopback network interfaces."""
        return get_network_interfaces(skip_loopback=True)

    async def discover_services(self) -> AsyncGenerator[MCPServiceRecord, None]:
        """Discover MCP services on the identified network interfaces."""
        interfaces = await self.get_network_interfaces()
        logger.info("Scanning interfaces for services", interfaces=interfaces)

        for iface in interfaces:
            ips = get_interface_ips(iface)
            for ip in ips:
                # Create a service record for each discovered IP
                # In a real implementation, we would:
                # 1. Port scan common MCP ports
                # 2. Try to connect and verify MCP protocol
                # 3. Get capabilities and version info
                service_record = MCPServiceRecord(
                    id=f"network-{iface}-{ip}",
                    name=f"Service on {ip}",
                    endpoint=f"http://{ip}:80",
                    transport_type=TransportType.HTTP,
                    discovery_method="network",
                    version="1.0",  # This would be determined by actual connection
                    auth_method=AuthMethod.NONE  # This would be determined by actual connection
                )
                yield service_record
