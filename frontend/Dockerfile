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
RUN pnpm run build

FROM node:24-alpine AS runtime
WORKDIR /app

RUN npm install -g serve
COPY --from=build /app/dist ./dist

EXPOSE 4173
CMD ["serve", "-s", "dist", "-l", "4173"]
