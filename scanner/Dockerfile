FROM aquasec/trivy:0.69.3 AS trivy
FROM anchore/grype:v0.111.0 AS grype
FROM anchore/syft:v1.42.4 AS syft
FROM python:3.13-slim

# Install git for source repo cloning, skopeo for image fetching, and Poetry for dependency management
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates curl skopeo \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir poetry

# Copy scanner binaries from official images
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=grype /grype /usr/local/bin/grype
COPY --from=syft /syft /usr/local/bin/syft

# Install Dockle
RUN curl -fsSL https://github.com/goodwithtech/dockle/releases/download/v0.4.15/dockle_0.4.15_Linux-64bit.tar.gz \
    | tar xz -C /usr/local/bin dockle

# Install osv-scanner
RUN curl -fsSL https://github.com/google/osv-scanner/releases/download/v2.3.5/osv-scanner_linux_amd64 \
    -o /usr/local/bin/osv-scanner && chmod +x /usr/local/bin/osv-scanner

# Install Dive (Docker image layer analysis)
RUN curl -fsSL https://github.com/wagoodman/dive/releases/download/v0.13.1/dive_0.13.1_linux_amd64.tar.gz \
    | tar xz -C /usr/local/bin dive

# Install Semgrep (SAST scanner) — needs setuptools<74 for pkg_resources (removed in 74+)
RUN pip install --no-cache-dir "setuptools<74" semgrep==1.114.0

# Install TruffleHog (secret scanner)
RUN curl -fsSL https://github.com/trufflesecurity/trufflehog/releases/download/v3.94.3/trufflehog_3.94.3_linux_amd64.tar.gz \
    | tar xz -C /usr/local/bin trufflehog

# Enable all Syft catalogers including binary detection
ENV SYFT_DEFAULT_CATALOGERS=all

# Disable Semgrep telemetry to reduce log noise and disk usage
ENV SEMGREP_SEND_METRICS=off

WORKDIR /scanner

# Install Python dependencies via Poetry
COPY pyproject.toml ./
RUN poetry config virtualenvs.create false \
    && poetry install --no-interaction --no-ansi --no-root --only main

# Copy application
COPY app ./app

# Install entrypoint that extends the system CA store with a user-supplied
# PEM (via HTTP_CA_BUNDLE) so git and the Go-based scanners trust it too.
COPY entrypoint.sh /scanner/entrypoint.sh
RUN chmod +x /scanner/entrypoint.sh

EXPOSE 8080

ENTRYPOINT ["/scanner/entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
