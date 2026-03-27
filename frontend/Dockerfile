FROM node:24-alpine AS dev
WORKDIR /app

COPY package.json package-lock.json* pnpm-lock.yaml* yarn.lock* ./
RUN if [ -f yarn.lock ]; then yarn install --frozen-lockfile; \
    elif [ -f pnpm-lock.yaml ]; then corepack enable pnpm && pnpm install --frozen-lockfile; \
    elif [ -f package-lock.json ]; then npm install; \
    else npm install; \
    fi

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
RUN npm run build

FROM node:24-alpine AS runtime
WORKDIR /app

RUN npm install -g serve
COPY --from=build /app/dist ./dist

EXPOSE 4173
CMD ["serve", "-s", "dist", "-l", "4173"]
