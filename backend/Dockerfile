FROM python:3.13-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    POETRY_VIRTUALENVS_CREATE=false \
    POETRY_NO_INTERACTION=1 \
    PYTHONPATH=/

WORKDIR /workspace

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN curl -sSL https://install.python-poetry.org | python -
ENV PATH="/root/.local/bin:${PATH}"

COPY pyproject.toml poetry.lock* ./
RUN poetry install --no-root

FROM python:3.13-slim AS runtime

ARG HECATE_BUILD_SHA=

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/

WORKDIR /

COPY --from=builder /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY app /app
# Carry pyproject.toml into the runtime image so /api/v1/version can read the
# package version directly (poetry install --no-root never registers the
# project as a package, so importlib_metadata would fail and return the
# hardcoded fallback).
COPY --from=builder /workspace/pyproject.toml /app/pyproject.toml
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Bake the build SHA into the image as a file so the runtime can report
# its identity to /api/v1/version. Using a file (not ENV) makes the value
# immune to docker-compose env_file overrides — the SHA is artifact
# identity, not user-tunable config.
RUN printf '%s' "${HECATE_BUILD_SHA}" > /app/.build_sha

EXPOSE 8000

ENTRYPOINT ["/entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
