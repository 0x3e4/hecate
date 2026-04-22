#!/bin/sh
# When HTTP_CA_BUNDLE points to a PEM, append it to the container's default
# trust store. httpx treats verify=<path> as the sole trust store (not additive
# to certifi), so a bundle containing only a corporate root CA would break every
# non-MITM-proxied egress. Concatenating /etc/ssl/certs/ca-certificates.crt +
# the user's PEM keeps public API calls working while also trusting the
# corporate CA. SSL_CERT_FILE also makes google-genai honor the combined bundle
# (the SDK has no verify= kwarg but its stdlib ssl context picks up the env).
set -e

if [ -n "$HTTP_CA_BUNDLE" ] && [ -f "$HTTP_CA_BUNDLE" ]; then
    COMBINED=/tmp/hecate-trust-bundle.pem
    cat /etc/ssl/certs/ca-certificates.crt "$HTTP_CA_BUNDLE" > "$COMBINED"
    echo "[entrypoint] Combined system CAs + $HTTP_CA_BUNDLE into $COMBINED"
    export SSL_CERT_FILE="$COMBINED"
    export REQUESTS_CA_BUNDLE="$COMBINED"
    export HTTP_CA_BUNDLE="$COMBINED"
fi

exec "$@"
