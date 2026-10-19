FROM aquasec/trivy:0.72.0 AS trivy
FROM anchore/grype:v0.120.1 AS grype
FROM anchore/syft:v1.54.1 AS syft
# .NET 10 (LTS) has no GA Debian image; only /usr/share/dotnet (a portable,
# distro-agnostic linux-x64 build) is copied, so the Ubuntu-based tag is fine.
FROM mcr.microsoft.com/dotnet/runtime:10.0-noble AS dotnet
FROM python:3.14-slim

# Install git for source repo cloning, skopeo for image fetching, and Poetry for dependency management
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates curl skopeo unzip \
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
RUN curl -fsSL https://github.com/google/osv-scanner/releases/download/v2.7.0/osv-scanner_linux_amd64 \
    -o /usr/local/bin/osv-scanner && chmod +x /usr/local/bin/osv-scanner

# Install Dive (Docker image layer analysis)
RUN curl -fsSL https://github.com/wagoodman/dive/releases/download/v0.13.1/dive_0.13.1_linux_amd64.tar.gz \
    | tar xz -C /usr/local/bin dive

# Install Semgrep (SAST scanner) into its own venv. Semgrep pins its deps tightly
# (opentelemetry-api ~=1.37, click ~=8.1); installed into the system
# site-packages, the app's `poetry install` below upgraded them underneath it
# (FastAPI >= 0.14x requires opentelemetry-api >= 1.44) and semgrep failed to
# import (`cannot import name '_ExtendedAttributes'`). semgrep>=1.16x no longer
# imports pkg_resources, so no setuptools pin is needed.
RUN python -m venv /opt/semgrep \
    && /opt/semgrep/bin/pip install --no-cache-dir semgrep==1.164.0 \
    && ln -s /opt/semgrep/bin/semgrep /usr/local/bin/semgrep

# Install TruffleHog (secret scanner)
RUN curl -fsSL https://github.com/trufflesecurity/trufflehog/releases/download/v3.99.2/trufflehog_3.99.2_linux_amd64.tar.gz \
    | tar xz -C /usr/local/bin trufflehog

# Install .NET 10 runtime (required for DevSkim CLI — framework-dependent build)
# Globalization-invariant mode avoids needing libicu (DevSkim is pattern-matching, locale-agnostic)
COPY --from=dotnet /usr/share/dotnet /usr/share/dotnet
ENV DOTNET_ROOT=/usr/share/dotnet \
    PATH="/usr/share/dotnet:${PATH}" \
    DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_NOLOGO=1 \
    DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1

# Install DevSkim (Microsoft SAST scanner — no-build, native SARIF output)
# GitHub releases after v1.0.59 ship no binaries; the CLI is published only as
# the `Microsoft.CST.DevSkim.CLI` dotnet tool on NuGet. A dotnet-tool .nupkg is
# a zip holding a framework-dependent build (`dotnet devskim.dll`), so the .NET 10
# runtime above is enough — no SDK. We take the net10.0 build, keep only the
# linux-x64 native libs (libgit2), and expose it via a `devskim` wrapper so the
# scanner's argv is unchanged. The package hash is pinned.
ARG DEVSKIM_VERSION=1.0.100
ARG DEVSKIM_SHA256=11a08ca73ef1020c4dd8efaf4e34ce0d59df75eed4fcef478724bc6be28f04fd
RUN curl -fsSL "https://api.nuget.org/v3-flatcontainer/microsoft.cst.devskim.cli/${DEVSKIM_VERSION}/microsoft.cst.devskim.cli.${DEVSKIM_VERSION}.nupkg" \
    -o /tmp/devskim.nupkg \
    && echo "${DEVSKIM_SHA256}  /tmp/devskim.nupkg" | sha256sum -c - \
    && mkdir -p /tmp/devskim-extract \
    && unzip -q /tmp/devskim.nupkg 'tools/net10.0/any/*' -d /tmp/devskim-extract \
    && mv /tmp/devskim-extract/tools/net10.0/any /usr/local/lib/devskim \
    && find /usr/local/lib/devskim/runtimes -mindepth 1 -maxdepth 1 ! -name linux-x64 -exec rm -rf {} + \
    && printf '#!/bin/sh\nexec /usr/share/dotnet/dotnet /usr/local/lib/devskim/devskim.dll "$@"\n' > /usr/local/bin/devskim \
    && chmod +x /usr/local/bin/devskim \
    && rm -rf /tmp/devskim.nupkg /tmp/devskim-extract

# Enable all Syft catalogers including binary detection
ENV SYFT_DEFAULT_CATALOGERS=all

# Disable Semgrep telemetry to reduce log noise and disk usage
ENV SEMGREP_SEND_METRICS=off

WORKDIR /scanner

# Install Python dependencies via Poetry. The lock file is copied too, so the
# image gets the locked versions instead of whatever is newest at build time.
COPY pyproject.toml poetry.lock ./
RUN poetry config virtualenvs.create false \
    && poetry install --no-interaction --no-ansi --no-root --only main

# Copy application
COPY app ./app

# Install entrypoint that extends the system CA store with a user-supplied
# PEM (via HTTP_CA_BUNDLE) so git and the Go-based scanners trust it too.
COPY entrypoint.sh /scanner/entrypoint.sh
RUN chmod +x /scanner/entrypoint.sh

# Bake the build SHA into the image so the runtime can self-report via
# /version. Same mechanism as backend/Dockerfile.
ARG HECATE_BUILD_SHA=
RUN printf '%s' "${HECATE_BUILD_SHA}" > /scanner/app/.build_sha

EXPOSE 8080

ENTRYPOINT ["/scanner/entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
