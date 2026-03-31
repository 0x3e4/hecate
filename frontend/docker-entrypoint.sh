#!/bin/sh
set -e

WORKSPACE_DIR="${WORKSPACE:-/workspace}"
APP_DIR="/app"

if [ -d "${WORKSPACE_DIR}" ]; then
  mkdir -p "${WORKSPACE_DIR}"
  # Sync host sources into container app directory, keep node_modules from image.
  rsync -a --delete --exclude=node_modules --exclude=dist "${WORKSPACE_DIR}/" "${APP_DIR}/"
fi

cd "${APP_DIR}"

pnpm install
if [ -f pnpm-lock.yaml ]; then
  cp pnpm-lock.yaml .pnpm-install.stamp 2>/dev/null || true
fi

if [ "$#" -gt 0 ]; then
  "$@"
else
  pnpm run build
fi

if [ -d "${WORKSPACE_DIR}" ] && [ -f "${APP_DIR}/pnpm-lock.yaml" ]; then
  cp "${APP_DIR}/pnpm-lock.yaml" "${WORKSPACE_DIR}/pnpm-lock.yaml"
fi

if [ -d "${WORKSPACE_DIR}" ] && [ -d "${APP_DIR}/dist" ]; then
  rm -rf "${WORKSPACE_DIR}/dist"
  mkdir -p "${WORKSPACE_DIR}/dist"
  rsync -a "${APP_DIR}/dist/" "${WORKSPACE_DIR}/dist/"
fi
