#!/bin/sh
# When HTTP_CA_BUNDLE points to a PEM, append it to the container's default
# trust store and point every tool we shell out to (git, trivy, grype, syft,
# osv-scanner, dockle, trufflehog, semgrep) at the combined bundle. Without
# this, Python httpx honors HTTP_CA_BUNDLE but subprocess tools still fail
# because they read /etc/ssl/certs/ca-certificates.crt only.
set -e

if [ -n "$HTTP_CA_BUNDLE" ] && [ -f "$HTTP_CA_BUNDLE" ]; then
    COMBINED=/tmp/hecate-trust-bundle.pem
    cat /etc/ssl/certs/ca-certificates.crt "$HTTP_CA_BUNDLE" > "$COMBINED"
    echo "[entrypoint] Combined system CAs + $HTTP_CA_BUNDLE into $COMBINED"
    export SSL_CERT_FILE="$COMBINED"
    export GIT_SSL_CAINFO="$COMBINED"
    export REQUESTS_CA_BUNDLE="$COMBINED"
    export HTTP_CA_BUNDLE="$COMBINED"
fi

# Pre-warm the grype vulnerability DB in the background so the first scan after a
# (re)start doesn't pay the full DB download/extract INSIDE its own scan-timeout
# budget. The cache (GRYPE_DB_CACHE_DIR) lives in tmpfs by default and is wiped
# on restart, so without this the first big-target scan can blow past
# GRYPE_TIMEOUT_SECONDS on the DB step alone. Best-effort and non-blocking:
# grype keeps auto-update on, so a scan that starts before this finishes still
# works; failures (e.g. offline) are ignored and the next scan retries.
( grype db update >/tmp/grype-db-prewarm.log 2>&1 && echo "[entrypoint] grype DB pre-warmed" || echo "[entrypoint] grype DB pre-warm skipped (see /tmp/grype-db-prewarm.log)" ) &

exec "$@"
