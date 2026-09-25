import asyncio
import threading
import os
import logging
from typing import Dict, Optional, Any, Callable
from scapy.all import sniff, DNS, IP
from datetime import datetime

# Setup logging
logger = logging.getLogger("DNSentinel.Capture")

class DNSCaptureEngine:
    """
    DNS sniffer built on Scapy (opt-in via ENABLE_LIVE_CAPTURE).
    Runs in a background thread to prevent blocking the FastAPI event loop.
    """
    def __init__(self):
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._stats = {
            "packets_captured": 0,
            "dns_queries": 0,
            "dns_responses": 0,
            "start_time": None
        }
        self._broadcast_callback: Optional[Callable] = None
        self._interface = "eth0"

    def set_sync_context(self, loop: asyncio.AbstractEventLoop, callback: Callable):
        """Sets the async loop and broadcast callback for real-time streaming."""
        self._loop = loop
        self._broadcast_callback = callback

    def _packet_callback(self, packet):
        """Internal callback executed for every captured packet."""
        if not packet.haslayer(DNS):
            return

        self._stats["packets_captured"] += 1

        try:
            dns_layer = packet.getlayer(DNS)
            ip_layer = packet.getlayer(IP)
            if ip_layer is None:  # IPv6 / non-IP carriers are not handled yet
                return

            event = {
                "timestamp": datetime.fromtimestamp(packet.time).isoformat(),
                "src_ip": ip_layer.src,
                "dst_ip": ip_layer.dst,
                "query_name": "",
                "query_type": "",
                "response_code": dns_layer.get_field('rcode').i2repr(dns_layer, dns_layer.rcode),
                "answer_ips": [],
                "ttl": 0
            }

            # Parse Query/Response logic
            if dns_layer.qd:
                try:
                    qname = dns_layer.qd.qname.decode('utf-8', errors='ignore').rstrip('.')
                    event["query_name"] = qname
                    event["query_type"] = dns_layer.qd.get_field('qtype').i2repr(dns_layer.qd, dns_layer.qd.qtype)
                except Exception:
                    pass

            if dns_layer.qr == 1: # It's a response
                self._stats["dns_responses"] += 1
                if dns_layer.ancount > 0:
                    for i in range(dns_layer.ancount):
                        try:
                            ans = dns_layer.an[i]
                            if hasattr(ans, 'rdata'):
                                event["answer_ips"].append(str(ans.rdata))
                            if i == 0: event["ttl"] = getattr(ans, 'ttl', 0)
                        except Exception:
                            continue
            else:
                self._stats["dns_queries"] += 1

            # Only queries are analysed; responses would double-count every lookup.
            if dns_layer.qr == 0 and self._loop and self._broadcast_callback:
                logger.debug("Captured %s from %s", event["query_name"], event["src_ip"])
                asyncio.run_coroutine_threadsafe(
                    self._broadcast_callback(event),
                    self._loop
                )

        except Exception as e:
            logger.error(f"Field extraction failed: {e}")

    def _run_sniff(self):
        """Threading target for Scapy sniff on all active interfaces."""
        from scapy.all import get_if_list
        try:
            # On Windows, we explicitly sniff on all active interfaces to ensure coverage
            interfaces = get_if_list()
            logger.info(f"DNS Multi-Interface Sniffer: Starting on {interfaces}")

            sniff(
                iface=interfaces,
                filter="udp port 53 or tcp port 53",
                prn=self._packet_callback,
                store=0,
                stop_filter=lambda x: self._stop_event.is_set()
            )
        except Exception as e:
            logger.error(f"Sniffer execution error: {e}")

    def start(self, interface: Optional[str] = None):
        """Initializes and starts the background sniffer."""
        if os.name != 'nt' and os.geteuid() != 0:
            raise RuntimeError("PRIVILEGE_ERROR: Root required.")

        if self._thread and self._thread.is_alive():
            return

        self._stop_event.clear()
        self._stats["start_time"] = datetime.now().isoformat()
        self._thread = threading.Thread(target=self._run_sniff, daemon=True)
        self._thread.start()
        logger.info("DNS Capture Engine Initialized")

    def stop(self):
        """Gracefully shuts down the sniffer."""
        if self._thread:
            self._stop_event.set()
            self._thread.join(timeout=2.0)

    def get_stats(self) -> Dict[str, Any]:
        return self._stats

# Singleton instance for the application
engine = DNSCaptureEngine()

def start_capture(interface: str, loop: asyncio.AbstractEventLoop, callback: Callable):
    engine.set_sync_context(loop, callback)
    engine.start(interface)

def stop_capture():
    engine.stop()

def get_stats() -> Dict[str, Any]:
    return engine.get_stats()
