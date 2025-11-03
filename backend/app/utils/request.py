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
