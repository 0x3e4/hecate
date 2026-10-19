from __future__ import annotations

from typing import Optional

from fastapi import Request

from app.core.config import settings


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

    trusted_ips = settings.trusted_proxy_ips
    is_trusted_proxy = (
        bool(trusted_ips)
        and (direct_host in trusted_ips or "*" in trusted_ips)
    )

    if is_trusted_proxy:
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

    trusted_ips = settings.trusted_proxy_ips
    is_trusted_proxy = bool(trusted_ips) and (direct_host in trusted_ips or "*" in trusted_ips)
    if not is_trusted_proxy:
        # Direct peer is authoritative; a client-supplied XFF is not trusted.
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
