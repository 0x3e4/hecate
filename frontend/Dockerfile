FROM node:24-alpine AS dev
WORKDIR /app

RUN corepack enable pnpm

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile

RUN apk add --no-cache rsync
COPY docker-entrypoint.sh /usr/local/bin/frontend-entrypoint
RUN chmod +x /usr/local/bin/frontend-entrypoint
COPY . .

FROM dev AS build
ARG VITE_API_BASE_URL=/api
ENV VITE_API_BASE_URL=$VITE_API_BASE_URL
# Bake the build SHA into the bundle. Vite auto-exposes any VITE_*-prefixed
# env var to the client via `import.meta.env.VITE_BUILD_SHA`. Empty in
# local-build setups where the build-arg isn't passed; the Support page
# falls back to "Build SHA unknown" in that case.
ARG HECATE_BUILD_SHA=
ENV VITE_BUILD_SHA=$HECATE_BUILD_SHA
RUN pnpm run build

# The built app is static files; nginx serves them. The former node + `serve`
# runtime carried npm, corepack and serve's own dependencies (undici,
# minimatch, compression, ip-address, …), none of which the page needs, and
# every one of them a scan finding. Same port as before.
FROM nginx:1.31.8-alpine AS runtime
RUN apk upgrade --no-cache  && rm -f /etc/nginx/conf.d/default.conf
# The frontend is also the gateway to the backend (nginx.conf.template). The nginx
# image fills in the ${...} placeholders from these variables on start (envsubst on
# /etc/nginx/templates); nginx's own $variables are left alone.
COPY nginx.conf.template /etc/nginx/templates/default.conf.template
# real_ip settings from TRUSTED_PROXIES, written before the templates are rendered.
COPY --chmod=755 docker-entrypoint.d/15-real-ip.sh /docker-entrypoint.d/15-real-ip.sh
RUN sed -i 's/$//' /docker-entrypoint.d/15-real-ip.sh
# BACKEND_UPSTREAM: the backend as the frontend reaches it (Compose service name).
# UPSTREAM_RESOLVER: Docker's embedded DNS; set your cluster DNS outside Docker.
# MAX_UPLOAD_MB: request body limit for /api and /mcp (SBOMs, source archives, backups).
# TRUSTED_PROXIES: who may tell nginx the client IP (the reverse proxy in front).
ENV BACKEND_UPSTREAM=http://backend:8000     UPSTREAM_RESOLVER=127.0.0.11     MAX_UPLOAD_MB=100     TRUSTED_PROXIES=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.1,::1,fc00::/7
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 4173
