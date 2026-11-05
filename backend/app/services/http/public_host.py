"""
Whether a URL someone typed into the UI points at the public internet.

The backend fetches advisory feeds added on the System page itself, and what it
reads ends up on a public page. Without this check, anyone holding the system
password could make the backend read an internal service (the cloud metadata
endpoint, an admin interface on the LAN) and publish what it answers.
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
from urllib.parse import urlsplit

import structlog

log = structlog.get_logger()

_RESOLVE_TIMEOUT_SECONDS = 5.0


def is_public_address(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return address.is_global and not address.is_multicast


async def is_public_url(url: str) -> bool:
    """
    True when every address the URL's host resolves to is a public one. A host that
    does not resolve counts as not public: the fetch would fail anyway, and a name
    that only resolves on the internal network is exactly what is refused.

    The check runs again before every fetch, so a host that is moved to a private
    address later is caught on the next run. It cannot pin the address for the
    request that follows, so a resolver that answers differently within seconds
    (DNS rebinding) is out of its reach.
    """
    parts = urlsplit(url)
    host = parts.hostname
    if not host:
        return False
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError:
        return False
    if _is_literal(host):
        return is_public_address(host)
    try:
        infos = await asyncio.wait_for(
            asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM),
            timeout=_RESOLVE_TIMEOUT_SECONDS,
        )
    except (OSError, TimeoutError) as exc:
        log.info("public_host.resolve_failed", host=host, error=str(exc) or type(exc).__name__)
        return False
    addresses = {str(info[4][0]) for info in infos}
    return bool(addresses) and all(is_public_address(address) for address in addresses)


def _is_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True
