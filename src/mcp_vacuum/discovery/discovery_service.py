"""
Service responsible for discovering MCP servers on the network
using various protocols like mDNS, SSDP.
"""
import asyncio
import socket
import ipaddress # For IP address and network validation
from typing import List, Dict, Optional, Set, AsyncGenerator
from urllib.parse import urlparse

import structlog
from zeroconf import ServiceStateChange, Zeroconf
from zeroconf.asyncio import AsyncServiceBrowser, AsyncZeroconf, AsyncServiceInfo

import time # For TTL cache
from ..config import DiscoveryConfig, Config
from ..models.mcp import MCPServiceRecord
from ..models.common import AuthMethod, TransportType # Assuming these are relevant for initial record

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
        self._discovered_services_cache: Dict[str, Tuple[MCPServiceRecord, float]] = {}
        self._active_discoveries: Set[asyncio.Task] = set()


    async def discover_servers_mdns(self, timeout: Optional[int] = None) -> AsyncGenerator[MCPServiceRecord, None]:
        """
        Discovers MCP servers using mDNS/DNS-SD.
        Yields MCPServiceRecord as they are discovered.
        """
        if not self.discovery_config.enable_mdns:
            self.logger.info("mDNS discovery is disabled in configuration.")
            return

        aiozc = AsyncZeroconf()
        # Use service types from config, default to "_mcp._tcp.local."
        service_types_to_query = self.discovery_config.mdns_service_types or ["_mcp._tcp.local."]
        self.logger.info("Starting mDNS discovery", service_types=service_types_to_query, timeout=timeout)

        # Discovered services in this specific scan session to avoid re-yielding from self._discovered_services
        session_discovered_ids: Set[str] = set()

        async def on_service_state_change(
            zc: Zeroconf, service_type: str, name: str, state_change: ServiceStateChange
        ) -> None:
            log = self.logger.bind(service_name=name, service_type=service_type, state=state_change)
            log.debug("mDNS service state change detected.")

            if state_change == ServiceStateChange.Added:
                info = AsyncServiceInfo(service_type, name)
                # Resolve service info. Need to do this within the handler or shortly after.
                # The AsyncServiceBrowser might call this multiple times for the same service.
                # We need to ensure we only process and yield a new service once.

                # The example in docs uses zc.get_service_info, but with AsyncZeroconf,
                # we should use await info.async_request(zc, timeout_ms=3000)
                # However, AsyncServiceBrowser's handler is synchronous.
                # A common pattern is to schedule the async request.
                asyncio.create_task(self._process_mdns_service_info(aiozc.zeroconf, service_type, name, session_discovered_ids))

        browser = AsyncServiceBrowser(
            aiozc.zeroconf, service_types_to_query, handlers=[on_service_state_change]
        )

        # Keep discovery running for the specified timeout or a default duration
        # This generator will yield services as they are found by _process_mdns_service_info
        # The actual yielding happens in _process_mdns_service_info via a queue or callback passed to it,
        # or this method needs to poll a list populated by _process_mdns_service_info.
        # For simplicity here, _process_mdns_service_info will directly try to yield
        # This requires _process_mdns_service_info to be an async generator itself or use a queue.
        # Let's use an internal queue for discovered records from callbacks.

        mdns_queue = asyncio.Queue()
        self._mdns_internal_queue = mdns_queue # Share queue with processor

        discovery_duration = timeout if timeout is not None else self.discovery_config.timeout_seconds

        end_time = asyncio.get_event_loop().time() + discovery_duration
        try:
            while asyncio.get_event_loop().time() < end_time:
                try:
                    record: MCPServiceRecord = await asyncio.wait_for(mdns_queue.get(), timeout=0.5)

                    # Apply allowed_networks filter before caching or yielding
                    if not self._is_service_allowed(record):
                        self.logger.debug("mDNS discovered service filtered out by allowed_networks", service_id=record.id, endpoint=record.endpoint)
                        mdns_queue.task_done()
                        continue

                    now = time.time()
                    cached_entry = self._discovered_services_cache.get(record.id)

                    if cached_entry:
                        _, last_seen_time = cached_entry
                        # Update timestamp even if already cached, effectively refreshing its TTL
                        self._discovered_services_cache[record.id] = (record, now)
                        if (now - last_seen_time) < self.discovery_config.cache_ttl_seconds:
                             # If re-discovered within TTL, don't re-yield unless behavior dictates it.
                             # For now, let's assume re-discovery means it's still active, update cache, but don't re-yield if recently yielded.
                             # This depends on desired behavior: yield once per discovery session vs. once per TTL expiration.
                             # The `session_discovered_ids` in _process_mdns_service_info handles "once per scan session".
                             # The outer layer (DiscoveryAgent) might handle yielding based on its own logic.
                             # For this service, we'll just update the cache.
                            self.logger.debug("mDNS service re-discovered, cache updated.", service_id=record.id)
                        else:
                            # Was cached but TTL expired, so it's like a new discovery for yielding purposes
                            self.logger.info("mDNS service re-discovered after TTL, yielding again.", service_id=record.id)
                            yield record
                    else: # New discovery
                        self._discovered_services_cache[record.id] = (record, now)
                        yield record

                    mdns_queue.task_done()
                except asyncio.TimeoutError:
                    if not browser.running: # Browser might have been cancelled early
                        break
                    continue # Continue waiting if browser is still running
        finally:
            self.logger.info("mDNS discovery period ended. Cleaning up.")
            await browser.async_cancel()
            await aiozc.async_close()
            del self._mdns_internal_queue # Clean up queue reference
            self.logger.info("mDNS discovery finalized.")


    async def _process_mdns_service_info(self, zc: Zeroconf, service_type: str, name: str, session_ids: Set[str]):
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


    async def discover_servers_ssdp(self, timeout: Optional[int] = None) -> AsyncGenerator[MCPServiceRecord, None]:
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

    def _is_service_allowed(self, service_record: MCPServiceRecord) -> bool:
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

            host_ip = ipaddress.ip_address(endpoint_host) # Works for both IPv4 and IPv6

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

    def get_cached_server(self, server_id: str) -> Optional[MCPServiceRecord]:
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

    def get_all_cached_servers(self) -> List[MCPServiceRecord]:
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
