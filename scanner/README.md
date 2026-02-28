# Hecate Scanner Sidecar

Scanner-Sidecar fuer die SCA-Funktionalität (Software Composition Analysis) von Hecate. Führt Schwachstellen-Scans und SBOM-Generierung fuer Container-Images und Source-Repositories durch.

## Installierte Scanner-Tools

| Tool | Zweck | Output-Format |
|------|-------|---------------|
| [Trivy](https://github.com/aquasecurity/trivy) | Schwachstellen-Scan + SBOM | `trivy-json` |
| [Grype](https://github.com/anchore/grype) | Schwachstellen-Scan | `grype-json` |
| [Syft](https://github.com/anchore/syft) | SBOM-Generierung | `cyclonedx-json` |
| [OSV Scanner](https://github.com/google/osv-scanner) | Schwachstellen-Scan (OSV DB) | `osv-json` |

Alle Tools werden als Binaries im Docker-Image installiert (jeweils `latest`-Version).

## API

### `GET /health`

Health Check.

**Response:** `{"status": "ok"}`

### `POST /scan`

Fuehrt einen oder mehrere Scanner gegen ein Ziel aus.

**Request:**
```json
{
  "target": "github.com/hecate/hecate-backend:latest",
  "type": "container_image",
  "scanners": ["trivy", "grype", "syft"]
}
```

| Feld | Typ | Beschreibung |
|------|-----|-------------|
| `target` | string | Container-Image-Referenz oder Source-Repo-URL |
| `type` | string | `container_image` oder `source_repo` |
| `scanners` | string[] | Liste der Scanner (`trivy`, `grype`, `syft`, `osv-scanner`) |

**Response:**
```json
{
  "target": "github.com/hecate/hecate-backend:latest",
  "type": "container_image",
  "results": [
    {
      "scanner": "trivy",
      "format": "trivy-json",
      "report": { ... },
      "error": null
    }
  ]
}
```

## Authentifizierung

Fuer private Container-Registries und Git-Repositories wird die Authentifizierung ueber eine einzige Umgebungsvariable `SCANNER_AUTH` konfiguriert:

```
SCANNER_AUTH=git.nohub.lol:mein-api-token
```

Mehrere Hosts kommagetrennt:
```
SCANNER_AUTH=git.nohub.lol:token1,ghcr.io:ghp_abc
```

Der Sidecar konfiguriert beim Start:
- `~/.docker/config.json` — fuer Container-Image-Pulls (Trivy, Grype, Syft)
- `~/.git-credentials` — fuer HTTPS-Clones privater Repositories

**Wichtig:** Kein Docker-Socket-Mounting. Die Scanner-Tools ziehen Container-Images direkt ueber die Registry-API.

## Source-Repository-Scans

Bei `type: "source_repo"` klont der Sidecar das Repository ueber `git clone --depth 1` in ein temporaeres Verzeichnis und fuehrt die Scanner darauf aus (`trivy fs`, `grype dir:`, `osv-scanner -r`).

## Ressourcen

Der Scanner-Sidecar benoetigt ausreichend Speicher fuer das Scannen grosser Images:

```yaml
deploy:
  resources:
    limits:
      memory: 4G
```

## Entwicklung

### Abhaengigkeiten (Poetry)

```bash
cd scanner
poetry install
```

### Lokaler Start

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8080
```

### Docker Build

```bash
docker build -t hecate-scanner ./scanner
docker run -p 8080:8080 hecate-scanner
```
