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
ARG VITE_SCA_AUTO_SCAN_ENABLED=false
ARG VITE_SCA_FEATURES_ENABLED=true
ARG VITE_AI_FEATURES_ENABLED=true
ARG VITE_TIMEZONE=
ENV VITE_SCA_AUTO_SCAN_ENABLED=$VITE_SCA_AUTO_SCAN_ENABLED
ENV VITE_SCA_FEATURES_ENABLED=$VITE_SCA_FEATURES_ENABLED
ENV VITE_AI_FEATURES_ENABLED=$VITE_AI_FEATURES_ENABLED
ENV VITE_TIMEZONE=$VITE_TIMEZONE
RUN pnpm run build

FROM node:24-alpine AS runtime
WORKDIR /app

RUN npm install -g serve
COPY --from=build /app/dist ./dist

EXPOSE 4173
CMD ["serve", "-s", "dist", "-l", "4173"]
