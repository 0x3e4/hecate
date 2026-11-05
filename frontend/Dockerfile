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
FROM nginx:1.30.6-alpine AS runtime
RUN apk upgrade --no-cache
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 4173
