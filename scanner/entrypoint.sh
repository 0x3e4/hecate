#!/bin/sh
# When HTTP_CA_BUNDLE points to a PEM, append it to the container's default
# trust store and point every tool we shell out to (git, trivy, grype, syft,
# osv-scanner, dockle, trufflehog, semgrep) at the combined bundle. Without
# this, Python httpx honors HTTP_CA_BUNDLE but subprocess tools still fail
# because they read /etc/ssl/certs/ca-certificates.crt only.
set -e

# The compose example hands the backend's whole .env to this container too, but
# nothing here needs the admin password, AI keys or database credentials, and
# this is the one service that handles untrusted archives and repositories.
# Scanner tools keep their own prefixed settings and SCANNER_AUTH, and the sidecar
# keeps SCA_SCANNER_SECRET, which it takes out of its own environment at startup.
for name in $(env | sed -n 's/^\([A-Za-z_][A-Za-z0-9_]*\)=.*/\1/p'); do
    case "$name" in
        TRIVY_*|GRYPE_*|SYFT_*|SEMGREP_*|SCANNER_AUTH|SCA_SCANNER_SECRET) ;;
        MONGO_*|OPENSEARCH_*|*PASSWORD*|*SECRET*|*API_KEY*|*_TOKEN) unset "$name" ;;
    esac
done

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
