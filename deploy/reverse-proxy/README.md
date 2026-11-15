# Reverse-proxy templates

TLS-terminating reverse-proxy configs that put the recommended HTTP security
headers in front of Hecate. Pick **one** proxy:

| File | Proxy | TLS |
| --- | --- | --- |
| [`nginx.conf.example`](nginx.conf.example) | nginx | Bring your own cert (paths in the file; e.g. certbot) |
| [`Caddyfile.example`](Caddyfile.example) | Caddy | Automatic (Let's Encrypt, built in) |
| [`traefik-static.yml.example`](traefik-static.yml.example) + [`traefik-dynamic.yml.example`](traefik-dynamic.yml.example) | Traefik | Automatic (ACME resolver in the static file) |

They all deliver the same header set and send **every** request to the
**frontend** container (`:8080`). That container is Hecate's gateway: it serves
the SPA and forwards `/api`, `/mcp` and `/.well-known/oauth-*` to the backend
itself, so the backend publishes no port and is not reachable from outside
Compose. The proxy only treats two paths specially:

- `/api/v1/events` and `/mcp`: streamed, so no buffering (SSE / MCP streamable HTTP)
- `/api/docs`, `/api/redoc`: a looser CSP (optional, see below)

**Client IP:** the gateway trusts `X-Forwarded-For` from private networks by
default (`TRUSTED_PROXIES`), and the backend trusts the gateway
(`TRUSTED_PROXY_IPS=hecate-frontend`). If your proxy reaches the frontend from a public
address, set `TRUSTED_PROXIES` on the frontend service to that address.

**Upgrading from a setup that sent `/api` to the backend:** that still works as
long as the backend keeps a port, but the point of the gateway is that it no
longer needs one. Point every route at the frontend, drop the backend's `ports:`
and set `TRUSTED_PROXY_IPS=hecate-frontend` in `.env` (your old value named the reverse
proxy, which no longer talks to the backend).

## Why the headers live in the proxy

The frontend image is nginx on `:8080` and sets **no** security headers of its
own (only `Cache-Control`), so the proxy is the only place to add them. Everything the SPA loads is
bundled and same-origin (no CDN), which is why the Content-Security-Policy can
stay strict (`script-src 'self'`, `connect-src 'self'`).

## Before you deploy — replace the placeholders

- `hecate.example.com` → your domain
- `hecate-frontend:8080` → the frontend's host:port
  (Docker Compose service name shown; use a container name or IP as needed)
- nginx: the `/etc/letsencrypt/live/hecate.example.com/...` cert paths
- Caddy / Traefik: the ACME e-mail (`admin@example.com`)

## Things to know

- **`style-src 'unsafe-inline'` is mandatory** — react-select/emotion and Mermaid
  inject `<style>` tags at runtime. Removing it breaks the UI. Scripts stay
  strict (`'self'`).
- **The built-in API docs need a looser CSP.** FastAPI's Swagger UI (`/api/docs`)
  and ReDoc (`/api/redoc`) load assets from `cdn.jsdelivr.net` and run an inline
  init script. Each template has an **optional** docs block that relaxes CSP for
  just those two paths — delete it if you don't expose the raw docs.
- **SSE** (`/api/v1/events`) and **MCP** need unbuffered streaming. Caddy and
  Traefik do this automatically; the nginx template sets `proxy_buffering off` +
  a long read timeout explicitly. The gateway does the same towards the backend.
- **Uploads:** the gateway accepts request bodies up to `MAX_UPLOAD_MB` (100 MB
  default); the nginx template sets the same `client_max_body_size`.
- **`X-Forwarded-Proto`** is set on every backend route so the backend sees
  `https` (matters for `is_production_like()` and MCP OAuth redirect URIs). For
  MCP you can additionally pin `MCP_PUBLIC_URL=https://hecate.example.com` in
  `.env`.
- **HSTS `includeSubDomains`** is left off by default. Enable it only if every
  `*.example.com` subdomain is HTTPS.

## Traefik: labels instead of the dynamic file

If you run Traefik with the Docker provider, you can drop
`traefik-dynamic.yml.example` and express the same routers/middlewares as
`labels:` on the `frontend` service in `docker-compose.yml`
(enable `providers.docker` in the static config). The dynamic file is provided
because it's self-contained and keeps the routing in one readable place.

## Verify

```bash
# nginx
nginx -t && systemctl reload nginx        # or: docker exec <nginx> nginx -s reload

# Caddy
caddy validate --config Caddyfile && caddy reload --config Caddyfile

# Traefik: reloads the dynamic file automatically (watch: true)
```

Then re-scan on <https://securityheaders.com> — you should land an **A**.

If the **Attack Path** tab (Mermaid) logs a CSP violation for an *inline script*,
that's Vite's `modulepreload` polyfill — harmless on modern browsers, or silence
it with `build: { modulePreload: { polyfill: false } }` in
`frontend/vite.config.ts` and rebuild.
