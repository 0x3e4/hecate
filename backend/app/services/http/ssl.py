from __future__ import annotations

from app.core.config import settings


def get_http_verify() -> str | bool:
    """Return the ``verify`` value for :class:`httpx.AsyncClient`.

    When ``HTTP_CA_BUNDLE`` points to a PEM file, httpx uses it as the trust
    store (needed for MITM proxies with a self-signed root CA). Otherwise
    httpx falls back to its default certifi bundle.
    """
    bundle = settings.http_ca_bundle
    return bundle if bundle else True
