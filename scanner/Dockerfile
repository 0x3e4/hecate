FROM aquasec/trivy:0.76.1 AS trivy
FROM anchore/grype:v0.121.1 AS grype
FROM anchore/syft:v1.56.0 AS syft

# dive and dockle have had no release since early 2025, and their release
# binaries carry Go 1.24.1 / 1.22.10 and old x/net, compress and xz modules.
# osv-scanner v2.7.0 ships with Go 1.27.0. All three are built here from their
# release tag (checked against the commit, so a moved tag fails the build) with
# a current Go and the dependency fixes that still compile. Left out on
# purpose: docker/docker 28.5 and selinux 1.13 for dockle, which break its
# containers/image and filepath-securejoin.
FROM golang:1.27.3-trixie AS gotools
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-trimpath
WORKDIR /src
ARG DIVE_VERSION=0.13.1
ARG DIVE_COMMIT=fe98c8a2eb08c443a36e3cc7568078909e298433
RUN git -c advice.detachedHead=false clone -q --depth 1 --branch v${DIVE_VERSION} https://github.com/wagoodman/dive.git dive \
    && cd dive && test "$(git rev-parse HEAD)" = "${DIVE_COMMIT}" \
    && go get golang.org/x/net@v0.62.0 golang.org/x/text@v0.43.0 golang.org/x/sys@v0.49.0 \
        github.com/klauspost/compress@v1.18.7 github.com/go-viper/mapstructure/v2@v2.4.0 \
        github.com/docker/docker@v28.5.2+incompatible github.com/docker/cli@v29.2.0+incompatible \
    && go mod tidy \
    && go build -ldflags "-s -w -X main.version=${DIVE_VERSION}" -o /out/dive .
ARG DOCKLE_VERSION=0.4.15
ARG DOCKLE_COMMIT=54368575d2a0c34a82fb05c904b8207284a64891
RUN git -c advice.detachedHead=false clone -q --depth 1 --branch v${DOCKLE_VERSION} https://github.com/goodwithtech/dockle.git dockle \
    && cd dockle && test "$(git rev-parse HEAD)" = "${DOCKLE_COMMIT}" \
    && go get golang.org/x/net@v0.62.0 golang.org/x/text@v0.43.0 golang.org/x/sys@v0.49.0 golang.org/x/oauth2@v0.27.0 \
        github.com/klauspost/compress@v1.18.7 github.com/ulikunitz/xz@v0.5.15 github.com/moby/sys/user@v0.4.1 \
    && go mod tidy \
    && go build -ldflags "-s -w -X github.com/goodwithtech/dockle/pkg.version=${DOCKLE_VERSION}" -o /out/dockle ./cmd/dockle
ARG OSV_SCANNER_VERSION=2.7.0
ARG OSV_SCANNER_COMMIT=bfe2f84abd2f09fe0b83ba7f6dad40d296762f40
RUN git -c advice.detachedHead=false clone -q --depth 1 --branch v${OSV_SCANNER_VERSION} https://github.com/google/osv-scanner.git osv-scanner \
    && cd osv-scanner && test "$(git rev-parse HEAD)" = "${OSV_SCANNER_COMMIT}" \
    && go get golang.org/x/net@v0.62.0 \
    && go mod tidy \
    && go build -ldflags "-s -w -X github.com/google/osv-scanner/v2/internal/version.OSVVersion=${OSV_SCANNER_VERSION}" \
        -o /out/osv-scanner ./cmd/osv-scanner

# .NET 10 (LTS) has no GA Debian image; only /usr/share/dotnet (a portable,
# distro-agnostic linux-x64 build) is copied, so the Ubuntu-based tag is fine.
FROM mcr.microsoft.com/dotnet/runtime:10.0-noble AS dotnet
FROM python:3.14-slim

# Install git for source repo cloning and skopeo for image fetching, plus the
# Debian security fixes that landed after the python image was built
RUN apt-get update && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends git ca-certificates curl skopeo unzip \
    && rm -rf /var/lib/apt/lists/*

# Copy scanner binaries from official images
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=grype /grype /usr/local/bin/grype
COPY --from=syft /syft /usr/local/bin/syft

# Dockle, osv-scanner and Dive (Docker image layer analysis), built above
COPY --from=gotools /out/dockle /out/osv-scanner /out/dive /usr/local/bin/

# Install Semgrep (SAST scanner) into its own venv. Semgrep pins its deps tightly
# (opentelemetry-api ~=1.37, click ~=8.1); installed into the system
# site-packages, the app's `poetry install` below upgraded them underneath it
# (FastAPI >= 0.14x requires opentelemetry-api >= 1.44) and semgrep failed to
# import (`cannot import name '_ExtendedAttributes'`). semgrep>=1.16x no longer
# imports pkg_resources, so no setuptools pin is needed. 1.183 pins PyJWT >= 2.15
# and mcp 1.29 (1.164: PyJWT 2.12, mcp 1.23). pip leaves the venv afterwards:
# nothing runs it, and its vendored urllib3 / msgpack showed up as findings.
RUN python -m venv /opt/semgrep \
    && /opt/semgrep/bin/pip install --no-cache-dir semgrep==1.183.0 \
    && /opt/semgrep/bin/python -m pip uninstall -y -q pip \
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
# Poetry runs from a throwaway venv (with virtualenvs.create=false it installs
# into the base interpreter) and leaves with it, together with the system pip:
# virtualenv's bundled wheels and pip's vendored urllib3 / msgpack / setuptools
# were findings, and the sidecar never installs anything at runtime.
COPY pyproject.toml poetry.lock ./
RUN python -m venv /opt/poetry \
    && /opt/poetry/bin/pip install --no-cache-dir -q poetry==2.3.3 \
    && /opt/poetry/bin/poetry config virtualenvs.create false \
    && /opt/poetry/bin/poetry install --no-interaction --no-ansi --no-root --only main \
    && rm -rf /opt/poetry /root/.config/pypoetry /root/.cache \
    && python -m pip uninstall -y -q pip

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
