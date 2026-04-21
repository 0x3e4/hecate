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

exec "$@"
