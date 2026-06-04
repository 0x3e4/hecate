# Configuration

All configuration is via environment variables (read by the backend through
`backend/app/core/config.py`). `.env.example` documents the full set; this page covers the most
operationally relevant. The authoritative defaults always live in `config.py`.

## Core

| Variable | Default | Description |
| --- | --- | --- |
| `TZ` | `UTC` | Container timezone; used for day-bucket boundaries and notification timestamps. |
| `API_PREFIX` | `/api/v1` | REST API path prefix. |
| `MONGO_URL` | `mongodb://mongo:27017` | MongoDB connection string. |
| `OPENSEARCH_URL` | `https://opensearch:9200` | OpenSearch endpoint. |

## Access control

| Variable | Default | Description |
| --- | --- | --- |
| `SYSTEM_PASSWORD` | (unset) | Admin password. When set, **all REST writes** require it (header `X-System-Password`), and it unlocks the System page. See [Security & Access Control](security-access-control.md). |
| `AI_ANALYSIS_PASSWORD` | (unset) | Required (header `X-AI-Analysis-Password`) to trigger any AI analysis when set — the final layer on top of the write gate. |
| `SCA_API_KEY` | (unset) | API key (header `X-API-Key`) for the CI/CD scan-submission endpoint `POST /api/v1/scans`. |

!!! warning "Fail-open by design"
    When `SYSTEM_PASSWORD` is unset the write gate is a no-op so existing deployments keep working.
    For any shared or internet-reachable instance, **set it**.

## AI providers (optional)

Set any one to enable AI features:

| Variable | Description |
| --- | --- |
| `OPENAI_API_KEY` | OpenAI (Responses API, reasoning + web search). |
| `ANTHROPIC_API_KEY` | Anthropic Messages API. |
| `GOOGLE_GEMINI_API_KEY` | Google Gemini. |
| `OPENAI_COMPATIBLE_BASE_URL` + `OPENAI_COMPATIBLE_MODEL` | Generic OpenAI-compatible endpoint (Ollama, vLLM, OpenRouter, LocalAI, LM Studio). |

## SCA scanning

| Variable | Default | Description |
| --- | --- | --- |
| `SCA_ENABLED` | `false` | Master switch for scanning. |
| `SCA_AUTO_SCAN_ENABLED` | `false` | Enable the auto-scan scheduler. |
| `SCA_MAX_CONCURRENT_SCANS` | `2` | Cap on simultaneous scans. |
| `<SCANNER>_TIMEOUT_SECONDS` | per-scanner | Per-scanner subprocess timeout (e.g. `DEVSKIM_TIMEOUT_SECONDS`); the backend derives its sidecar HTTP timeout from these. |

## TLS / corporate proxy

| Variable | Description |
| --- | --- |
| `HTTP_CA_BUNDLE` | Path to a PEM bundle inside the container, trusted for all outbound HTTPS (ingestion, AI, notifications, scanner tools). For MITM proxies with a self-signed root CA. |

## MCP server (optional)

See the in-app MCP info page (`/info/mcp`) for the full OAuth setup. Key switches:
`MCP_ENABLED`, `MCP_OAUTH_PROVIDER`, `MCP_OAUTH_CLIENT_ID`, `MCP_OAUTH_CLIENT_SECRET`,
`MCP_WRITE_IP_SAFELIST` (grants `mcp:write`).
