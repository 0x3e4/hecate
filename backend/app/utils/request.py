from __future__ import annotations

import ipaddress
import socket
import time
from functools import lru_cache
from typing import Optional

import structlog
from fastapi import Request

from app.core.config import settings

log = structlog.get_logger()
_forwarded_header_warned = False


_HOSTNAME_TTL_SECONDS = 30.0
# hostname -> (resolved at, addresses). Kept on failure, so a DNS hiccup does not
# suddenly make every client share the gateway's address.
_resolved_hosts: dict[str, tuple[float, frozenset[str]]] = {}


@lru_cache(maxsize=8)
def _parse_trusted(entries: tuple[str, ...]) -> tuple[bool, tuple[str, ...], tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]]:
    wildcard = "*" in entries
    hostnames: list[str] = []
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for entry in entries:
        if entry == "*":
            continue
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            hostnames.append(entry.lower())
    return wildcard, tuple(hostnames), tuple(networks)


def _host_addresses(hostname: str) -> frozenset[str]:
    """The addresses a trusted proxy's name points at, looked up at most every 30 s."""
    now = time.monotonic()
    cached = _resolved_hosts.get(hostname)
    if cached and now - cached[0] < _HOSTNAME_TTL_SECONDS:
        return cached[1]
    try:
        infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
        addresses = frozenset(str(info[4][0]).split("%", 1)[0] for info in infos)
    except OSError as exc:
        log.warning("request.trusted_proxy_unresolved", host=hostname, error=str(exc))
        addresses = cached[1] if cached else frozenset()
    _resolved_hosts[hostname] = (now, addresses)
    return addresses


def is_trusted_proxy(host: str | None) -> bool:
    """Whether the direct peer is one of ``TRUSTED_PROXY_IPS``.

    Entries are addresses, CIDR ranges (``172.16.0.0/12``, ``fd00::/8``), host
    names or ``*``. A host name is resolved (cached for 30 s) and trusts exactly
    the addresses it points at: ``frontend`` in Docker Compose follows the gateway
    container across restarts without trusting its neighbours on the network.
    """
    if not host:
        return False
    entries = settings.trusted_proxy_ips
    if not entries:
        return False
    wildcard, hostnames, networks = _parse_trusted(tuple(entries))
    if wildcard:
        return True
    try:
        address = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if any(address.version == net.version and address in net for net in networks):
        return True
    peer = str(address)
    return any(peer in _host_addresses(name) for name in hostnames)


def _warn_forwarded_header_ignored(request: Request, direct_host: str) -> None:
    """Say once when a proxy sits in front of us without being configured.

    Every client then shares the proxy's address, so ten bad passwords from one
    of them lock the auth throttle for all of them.
    """
    global _forwarded_header_warned
    header_name = settings.trusted_proxy_forward_header or "x-forwarded-for"
    if _forwarded_header_warned or not request.headers.get(header_name):
        return
    _forwarded_header_warned = True
    log.warning(
        "request.forwarded_header_from_untrusted_peer",
        peer=direct_host,
        hint="Set TRUSTED_PROXY_IPS to this address (or its network's CIDR) if it is your reverse proxy.",
    )


def get_client_ip(request: Request) -> Optional[str]:
    """
    Determine the client IP address, respecting trusted proxy configuration.

    - When TRUSTED_PROXY_IPS is configured and the request originates from one of
      those proxies (or a wildcard entry '*'), the function prefers the header
      specified via TRUSTED_PROXY_FORWARD_HEADER (default: X-Forwarded-For).
    - Falls back to X-Real-IP when configured and the forward header is absent.
    - Ultimately returns the direct client host provided by ASGI if no trusted
      proxy match or header data is available.
    """

    client = request.client
    direct_host = client.host if client else None
    if direct_host is None:
        return None

    if is_trusted_proxy(direct_host):
        header_name = settings.trusted_proxy_forward_header
        if header_name:
            forwarded_value = request.headers.get(header_name)
            if forwarded_value:
                forwarded_ips = [item.strip() for item in forwarded_value.split(",") if item.strip()]
                if forwarded_ips:
                    return forwarded_ips[0]

        real_ip_header = settings.trusted_proxy_real_ip_header
        if real_ip_header:
            real_ip = request.headers.get(real_ip_header)
            if real_ip and real_ip.strip():
                return real_ip.strip()

    return direct_host


def get_security_client_ip(request: Request) -> str:
    """Client IP for SECURITY decisions (IP safelists, brute-force lockout).

    Unlike :func:`get_client_ip` (which is for logging and intentionally echoes
    the client-claimed left-most ``X-Forwarded-For`` hop), this never trusts a
    client-supplied forwarded header unless the *direct* peer is a configured
    trusted proxy. When it is, it uses the **right-most** hop — the address the
    trusted proxy actually observed and appended (nginx ``$proxy_add_x_forwarded_for``
    appends the real peer to the right) — not the left-most value an attacker
    can freely prepend. With no ``TRUSTED_PROXY_IPS`` configured it returns the
    direct peer and ignores the header entirely (fail-closed).

    Assumes a single trusted proxy hop, which is what the shipped reverse-proxy
    templates deploy; in a multi-proxy chain configure ``TRUSTED_PROXY_IPS`` with
    every proxy and front it with one that overwrites the header.
    """
    client = request.client
    direct_host = client.host if client else ""
    if not direct_host:
        return ""

    if not is_trusted_proxy(direct_host):
        # Direct peer is authoritative; a client-supplied XFF is not trusted.
        _warn_forwarded_header_ignored(request, direct_host)
        return direct_host

    header_name = settings.trusted_proxy_forward_header or "x-forwarded-for"
    forwarded_value = request.headers.get(header_name)
    if forwarded_value:
        hops = [item.strip() for item in forwarded_value.split(",") if item.strip()]
        if hops:
            return hops[-1]

    real_ip_header = settings.trusted_proxy_real_ip_header
    if real_ip_header:
        real_ip = request.headers.get(real_ip_header)
        if real_ip and real_ip.strip():
            return real_ip.strip()

    return direct_host
