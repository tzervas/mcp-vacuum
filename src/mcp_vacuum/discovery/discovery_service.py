"""
Service responsible for discovering MCP servers on the network
using various protocols like mDNS, SSDP.
"""
import asyncio
import ipaddress  # For IP address and network validation
import socket
import time  # For TTL cache
from collections.abc import AsyncGenerator

import structlog  # type: ignore[import-not-found]
from zeroconf import ServiceStateChange, Zeroconf  # type: ignore[import-not-found]
from zeroconf.asyncio import AsyncServiceBrowser, AsyncServiceInfo, AsyncZeroconf  # type: ignore[import-not-found]

from ..config import Config, DiscoveryConfig
from ..models.common import (  # Assuming these are relevant for initial record
    AuthMethod,
    TransportType,
)
from ..models.mcp import MCPServiceRecord

logger = structlog.get_logger(__name__)

class MCPDiscoveryService:
    """
    Handles the discovery of MCP servers using mDNS and SSDP.
    ARP scanning can be added later.
    """

    def __init__(self, app_config: Config):
        self.app_config = app_config
        self.discovery_config: DiscoveryConfig = app_config.discovery
        self.logger = logger.bind(service="MCPDiscoveryService")
        # Cache: service_id -> (MCPServiceRecord, discovery_timestamp)
        self._discovered_services_cache: dict[str, Tuple[MCPServiceRecord, float]] = {}
        self._active_discoveries: set[asyncio.Task] = set()


    async def discover_servers_mdns(self, timeout: int | None = None) -> AsyncGenerator[MCPServiceRecord, None]:
        """
        Discovers MCP servers using mDNS/DNS-SD.
        Yields MCPServiceRecord as they are discovered.
        """
        if not self.discovery_config.enable_mdns:
            self.logger.info("mDNS discovery is disabled in configuration.")
            return

        # Use service types from config, default to "_mcp._tcp.local."
        service_types_to_query = self.discovery_config.mdns_service_types or ["_mcp._tcp.local."]
        self.logger.info("Starting mDNS discovery", service_types=service_types_to_query, timeout=timeout)

        # Discovered services in this specific scan session to avoid re-yielding from self._discovered_services
        session_discovered_ids: set[str] = set()

        mdns_queue = asyncio.Queue()
        self._mdns_internal_queue = mdns_queue # Share queue with processor for _process_mdns_service_info

        try:
            async with AsyncZeroconf() as aiozc: # Use AsyncZeroconf as a context manager
                async def on_service_state_change(
                    zc: Zeroconf, service_type: str, name: str, state_change: ServiceStateChange
                ) -> None:
                    log = self.logger.bind(service_name=name, service_type=service_type, state=state_change)
                    log.debug("mDNS service state change detected.")

                    if state_change == ServiceStateChange.Added:
                        # Schedule the async processing of service info
                        asyncio.create_task(self._process_mdns_service_info(aiozc.zeroconf, service_type, name, session_discovered_ids))

                browser = AsyncServiceBrowser(
                    aiozc.zeroconf, service_types_to_query, handlers=[on_service_state_change]
                )

                discovery_duration = timeout if timeout is not None else self.discovery_config.timeout_seconds
                end_time = asyncio.get_event_loop().time() + discovery_duration

                try:
                    while asyncio.get_event_loop().time() < end_time:
                        try:
                            record: MCPServiceRecord = await asyncio.wait_for(mdns_queue.get(), timeout=0.5)

                            # Ensure _is_service_allowed is awaited if it becomes async
                            allowed = self._is_service_allowed(record)
                            if hasattr(allowed, '__await__'): # Check if it's awaitable
                                allowed = await allowed

                            if not allowed:
                                self.logger.debug("mDNS discovered service filtered out by allowed_networks", service_id=record.id, endpoint=record.endpoint)
                                mdns_queue.task_done()
                                continue

                            now = time.time()
                            cached_entry = self._discovered_services_cache.get(record.id)

                            if cached_entry:
                                _, last_seen_time = cached_entry
                                self._discovered_services_cache[record.id] = (record, now)
                                if (now - last_seen_time) < self.discovery_config.cache_ttl_seconds:
                                    self.logger.debug("mDNS service re-discovered, cache updated.", service_id=record.id)
                                else:
                                    self.logger.info("mDNS service re-discovered after TTL, yielding again.", service_id=record.id)
                                    yield record
                            else: # New discovery
                                self._discovered_services_cache[record.id] = (record, now)
                                yield record

                            mdns_queue.task_done()
                        except TimeoutError:
                            if not browser.running: # browser might stop if aiozc is closed early
                                break
                            continue
                finally:
                    self.logger.info("mDNS discovery loop ended or browser stopped. Cleaning up browser.")
                    if browser and hasattr(browser, 'async_cancel'): # Ensure browser exists and has method
                         await browser.async_cancel()
                    # aiozc will be closed automatically by async with
        finally:
            if hasattr(self, '_mdns_internal_queue'):
                del self._mdns_internal_queue # Clean up queue reference
                self.logger.debug("Cleaned up _mdns_internal_queue.")
            self.logger.info("mDNS discovery finalized.")


    async def _process_mdns_service_info(self, zc: Zeroconf, service_type: str, name: str, session_ids: set[str]):
        """Helper to resolve and process service info for mDNS."""
        log = self.logger.bind(service_name=name, service_type=service_type)
        try:
            info = AsyncServiceInfo(service_type, name)
            # Request info with a short timeout
            if await info.async_request(zc, 3000): # 3 seconds timeout for request
                service_id = f"mdns-{info.server}-{info.port}" # Create a unique ID

                if service_id in session_ids: # Already processed in this scan session
                    return
                session_ids.add(service_id)

                log.debug("Successfully resolved mDNS service info", server=info.server, port=info.port, addresses=info.parsed_addresses())

                properties = {k.decode(): v.decode() if isinstance(v, bytes) else v
                              for k, v in info.properties.items()}

                # Prefer IPv4 if available
                ip_address = None
                if info.parsed_addresses_by_version(socket.AF_INET):
                    ip_address = info.parsed_addresses_by_version(socket.AF_INET)[0]
                elif info.parsed_addresses_by_version(socket.AF_INET6): # Fallback to IPv6
                    ip_address = info.parsed_addresses_by_version(socket.AF_INET6)[0]

                if not ip_address:
                    log.warning("No IP address found for mDNS service.")
                    return

                # Construct endpoint: Assume http unless specified in TXT records (e.g., 'tls=1' or 'scheme=https')
                scheme = "http"
                if properties.get("tls", "0") == "1" or properties.get("scheme") == "https":
                    scheme = "https"

                endpoint_url = f"{scheme}://{ip_address}:{info.port}"
                # Further path components might be in TXT e.g. properties.get("path", "/")

                # Create MCPServiceRecord
                record = MCPServiceRecord(
                    id=service_id,
                    name=properties.get("name", info.server.split('.')[0]), # Use TXT name or part of server name
                    endpoint=endpoint_url,
                    transport_type=TransportType.HTTP, # Default for mDNS unless specified otherwise
                    version=properties.get("version", "1.0"),
                    # capabilities: List[MCPCapability] - This needs more info from TXT or a follow-up query
                    auth_method=AuthMethod(properties.get("auth", "none").lower()), # Ensure valid enum
                    discovery_method="mdns",
                    metadata=properties # Store all TXT records in metadata
                )
                log.info("Constructed MCPServiceRecord from mDNS", record_id=record.id, record_name=record.name)

                if hasattr(self, '_mdns_internal_queue') and self._mdns_internal_queue:
                    await self._mdns_internal_queue.put(record)
                else:
                    log.warning("mDNS internal queue not available for processed service info.")
            else:
                log.warning("Failed to resolve mDNS service info (request timed out or no info).")
        except Exception as e:
            log.exception("Error processing mDNS service info", error=str(e))


    async def discover_servers_ssdp(self, timeout: int | None = None) -> AsyncGenerator[MCPServiceRecord, None]:
        """
        Discovers MCP servers using SSDP/UPnP.
        Yields MCPServiceRecord as they are discovered.
        """
        if not self.discovery_config.enable_ssdp:
            self.logger.info("SSDP discovery is disabled.")
            return

        ssdp_timeout = timeout if timeout is not None else self.discovery_config.scan_timeout_seconds # Per-scan timeout
        # SSDP M-SEARCH usually has MX value (max wait in seconds for response), typically small (1-5s)
        # The overall discovery timeout is different.

        self.logger.info("Starting SSDP discovery", search_target=self.discovery_config.ssdp_search_target, timeout=ssdp_timeout)

        # SSDP discovery logic based on Network Discovery Technical Guide
        # This requires raw socket operations or a library that handles SSDP M-SEARCH.
        # The provided guide snippet is synchronous. We need an async version.

        # For an async implementation, we'd use asyncio.DatagramProtocol
        # or a library like `async_upnp_client` (if it allows generic SSDP ST search)
        # or `aioesphomeapi.zeroconf.ssdp` (part of aioesphomeapi, might be too specific).

        # Simplified conceptual async SSDP client:
        # 1. Create UDP socket.
        # 2. Send M-SEARCH multicast message.
        # 3. Listen for responses for a duration (MX value from M-SEARCH).

        # This is a placeholder for a full async SSDP implementation.
        # The Network Discovery Technical Guide example is a good start for the protocol details.
        # For P0, focusing on mDNS might be sufficient, and SSDP can be expanded.

        # Example of what it might look like (conceptual):
        # try:
        #     transport, protocol = await asyncio.get_event_loop().create_datagram_endpoint(
        #         lambda: SSDPClientProtocol(self.discovery_config.ssdp_search_target, self.logger, self._discovered_services_cache),
        #         local_addr=('0.0.0.0', 0) # Bind to any available port
        #     )
        #     protocol.send_m_search()
        #     await asyncio.sleep(ssdp_timeout) # Listen for responses
        # finally:
        #     if transport: transport.close()

        # For now, yield nothing for SSDP as a full async implementation is non-trivial here.
        self.logger.warning("Async SSDP discovery is not fully implemented in this P0 version. Skipping.")
        if False: # Keep Pyright happy about async generator
            yield

    async def _is_service_allowed(self, service_record: MCPServiceRecord) -> bool:
        """Checks if the service's endpoint IP is within the allowed networks."""
        if not self.discovery_config.allowed_networks:
            return True # No filter means all are allowed

        try:
            # Extract host IP from endpoint URL
            # service_record.endpoint is a Pydantic HttpUrl
            endpoint_host = service_record.endpoint.host
            if not endpoint_host: # Should not happen for valid HttpUrl
                self.logger.warning("Service record has no host in endpoint", service_id=service_record.id)
                return False

            try:
                host_ip = ipaddress.ip_address(endpoint_host) # Works for both IPv4 and IPv6
            except ValueError:
                # If endpoint_host is a hostname, try to resolve it
                self.logger.debug("Endpoint host is not an IP, attempting DNS resolution for filtering", host=endpoint_host)
                try:
                    loop = asyncio.get_event_loop()
                    # Use loop.getaddrinfo for async DNS resolution
                    addr_infos = await loop.getaddrinfo(endpoint_host, None)
                    resolved_ips = {ipaddress.ip_address(info[4][0]) for info in addr_infos if info[4]} # info[4] is the sockaddr
                    self.logger.debug("Resolved IPs for host", host=endpoint_host, ips=resolved_ips)

                    # Check if any resolved IP is in an allowed network
                    for res_ip in resolved_ips:
                        for network_str in self.discovery_config.allowed_networks:
                            try:
                                allowed_net = ipaddress.ip_network(network_str, strict=False)
                                if res_ip in allowed_net:
                                    return True # Allowed if any resolved IP matches
                            except ValueError as e:
                                self.logger.error("Invalid network in allowed_networks config during hostname check", network_str=network_str, error=str(e))
                    return False # None of the resolved IPs are in allowed networks
                except socket.gaierror as e:
                    self.logger.warning("DNS resolution failed for endpoint host", host=endpoint_host, error=str(e))
                    return False # Cannot determine if allowed if DNS fails
                except Exception as e: # Catch other potential errors during async resolution
                    self.logger.error("Unexpected error during async DNS resolution", host=endpoint_host, error=str(e))
                    return False


            # If host_ip was already an IP address (no ValueError)
            for network_str in self.discovery_config.allowed_networks:
                try:
                    allowed_net = ipaddress.ip_network(network_str, strict=False)
                    if host_ip in allowed_net:
                        return True
                except ValueError as e:
                    self.logger.error("Invalid network in allowed_networks config", network_str=network_str, error=str(e))
            return False # Not found in any allowed network
        except ValueError as e: # Error parsing host_ip
            self.logger.warning("Could not parse IP from service endpoint for filtering", endpoint=str(service_record.endpoint), error=str(e))
            return False # Default to deny if IP parsing fails

    def get_cached_server(self, server_id: str) -> MCPServiceRecord | None:
        """Returns a cached MCPServiceRecord if found and not expired."""
        cached_entry = self._discovered_services_cache.get(server_id)
        if cached_entry:
            record, timestamp = cached_entry
            if (time.time() - timestamp) < self.discovery_config.cache_ttl_seconds:
                return record
            else:
                # TTL Expired, remove from cache
                self.logger.debug("Cached service TTL expired, removing.", server_id=server_id)
                del self._discovered_services_cache[server_id]
        return None

    def get_all_cached_servers(self) -> list[MCPServiceRecord]:
        """Returns all currently cached and valid (non-expired TTL) MCPServiceRecords."""
        valid_records = []
        now = time.time()
        expired_ids = []
        for server_id, (record, timestamp) in list(self._discovered_services_cache.items()): # list() for safe iteration if modifying
            if (now - timestamp) < self.discovery_config.cache_ttl_seconds:
                valid_records.append(record)
            else:
                expired_ids.append(server_id)

        # Clean up expired entries
        for server_id in expired_ids:
            self.logger.debug("Removing TTL expired service from cache during get_all.", server_id=server_id)
            del self._discovered_services_cache[server_id]

        return valid_records

    async def clear_cache(self):
        """Clears the discovery cache."""
        self.logger.info("Clearing discovery cache.")
        self._discovered_services_cache.clear()

    async def stop_discovery(self):
        """Stops any ongoing discovery processes."""
        self.logger.info("Stopping all active discovery tasks.")
        for task in list(self._active_discoveries): # Iterate over a copy
            if not task.done():
                task.cancel()
        await asyncio.gather(*self._active_discoveries, return_exceptions=True)
        self._active_discoveries.clear()
        self.logger.info("All discovery tasks stopped.")

# Note: A full SSDP async client is more involved.
# The mDNS part uses zeroconf library.
# ARP scanning is also complex and requires privileges, deferred.
# Error handling, logging, and configuration use are placeholders.
# The `_process_mdns_service_info` needs to handle putting services onto a queue
# that `discover_servers_mdns` can then yield from, to make it truly async generator.
# Updated mDNS to use an internal queue for yielding.
# The `session_discovered_ids` helps avoid processing the same mDNS announcement multiple times *within a single scan session*.
# The global `self._discovered_services` is used to avoid yielding a service if it was found in a *previous* scan (unless cache is cleared).
# This service focuses on pure discovery. Filtering (e.g. by allowed_networks) would happen after discovery,
# possibly in the DiscoveryAgent or OrchestrationAgent.
# The service_id for mDNS is now `mdns-{info.server}-{info.port}`. Ensure this is unique enough.
# SSL context for mDNS endpoint: `scheme` is determined from TXT. `transport_type` is defaulted to HTTP.
# Capabilities and detailed auth_metadata from mDNS TXT records are parsed, but might need a follow-up call to the server.
