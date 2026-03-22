FROM aquasec/trivy:latest AS trivy
FROM anchore/grype:latest AS grype
FROM anchore/syft:latest AS syft

FROM python:3.13-slim

# Install git for source repo cloning and Poetry for dependency management
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir poetry

# Copy scanner binaries from official images
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=grype /grype /usr/local/bin/grype
COPY --from=syft /syft /usr/local/bin/syft

# Install osv-scanner
RUN curl -fsSL https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_amd64 \
    -o /usr/local/bin/osv-scanner && chmod +x /usr/local/bin/osv-scanner

# Enable all Syft catalogers including binary detection
ENV SYFT_DEFAULT_CATALOGERS=all

WORKDIR /scanner

# Install Python dependencies via Poetry
COPY pyproject.toml ./
RUN poetry config virtualenvs.create false \
    && poetry install --no-interaction --no-ansi --no-root --only main

# Copy application
COPY app ./app

EXPOSE 8080

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
