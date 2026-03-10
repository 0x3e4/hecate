# Hecate Scanner Sidecar

Scanner-Sidecar für die SCA-Funktionalität (Software Composition Analysis) von Hecate. Führt Schwachstellen-Scans und SBOM-Generierung für Container-Images und Source-Repositories durch.

## Installierte Scanner-Tools

| Tool | Zweck | Output-Format |
|------|-------|---------------|
| [Trivy](https://github.com/aquasecurity/trivy) | Schwachstellen-Scan + SBOM | `trivy-json` |
| [Grype](https://github.com/anchore/grype) | Schwachstellen-Scan | `grype-json` |
| [Syft](https://github.com/anchore/syft) | SBOM-Generierung | `cyclonedx-json` |
| [OSV Scanner](https://github.com/google/osv-scanner) | Schwachstellen-Scan (OSV DB) | `osv-json` |

Alle Tools werden als Binaries im Docker-Image installiert (jeweils `latest`-Version).

## Einbindung in das Gesamtsystem

```
CI/CD oder Frontend
        │
        v
  +-----------+          +-----------+
  |  Backend  |  ------> |  Scanner  |
  |  :8000    |  POST    |  :8080    |
  |           |  /scan   |           |
  |  Scan-    | <------  |  Trivy    |
  |  Service  |  JSON    |  Grype    |
  |           |  Results |  Syft     |
  +-----------+          |  OSV      |
        │                +-----------+
        v
  +-----------+
  |  MongoDB  |
  |  Findings |
  |  SBOM     |
  +-----------+
```

1. Ein Scan wird über die Backend-API eingereicht (`POST /api/v1/scans` oder `/scans/manual`).
2. Der `ScanService` im Backend leitet die Anfrage an den Scanner-Sidecar weiter (`POST /scan`).
3. Der Sidecar führt die angeforderten Scanner aus und gibt die Rohergebnisse zurück.
4. Der `ScanParser` im Backend normalisiert die Ergebnisse und speichert Findings und SBOM-Komponenten in MongoDB.

## API

### `GET /health`

Health Check.

**Response:** `{"status": "ok"}`

### `POST /scan`

Führt einen oder mehrere Scanner gegen ein Ziel aus.

**Request:**
```json
{
  "target": "git.nohub.lol/rk/hecate-backend:latest",
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
  "target": "git.nohub.lol/rk/hecate-backend:latest",
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

Für private Container-Registries und Git-Repositories wird die Authentifizierung über die Umgebungsvariable `SCANNER_AUTH` konfiguriert:

```
SCANNER_AUTH=git.nohub.lol:mein-api-token
```

Mehrere Hosts kommagetrennt:
```
SCANNER_AUTH=git.nohub.lol:token1,ghcr.io:ghp_abc
```

Der Sidecar konfiguriert beim Start:
- `~/.docker/config.json` — für Container-Image-Pulls (Trivy, Grype, Syft)
- `~/.git-credentials` — für HTTPS-Clones privater Repositories

**Wichtig:** Kein Docker-Socket-Mounting. Die Scanner-Tools ziehen Container-Images direkt über die Registry-API.

## Source-Repository-Scans

Bei `type: "source_repo"` klont der Sidecar das Repository über `git clone --depth 1` in ein temporäres Verzeichnis und führt die Scanner darauf aus (`trivy fs`, `grype dir:`, `osv-scanner -r`).

## Ressourcen

Der Scanner-Sidecar benötigt ausreichend Speicher für das Scannen großer Images:

```yaml
deploy:
  resources:
    limits:
      memory: 4G
```

## Konfiguration

| Variable | Default | Beschreibung |
|----------|---------|-------------|
| `SCANNER_AUTH` | — | Authentifizierung für Registries und Git-Repos (`host:token`, kommagetrennt) |

Die Backend-seitige Konfiguration des Sidecar erfolgt über:

| Variable | Default | Beschreibung |
|----------|---------|-------------|
| `SCA_SCANNER_URL` | `http://scanner:8080` | URL des Scanner-Sidecar |
| `SCA_SCANNER_TIMEOUT_SECONDS` | `600` | Timeout für Scan-Anfragen |
| `SCA_DEFAULT_SCANNERS` | `trivy,grype,syft,osv-scanner` | Standard-Scanner für automatische Scans |

## Entwicklung

### Abhängigkeiten (Poetry)

```bash
cd scanner
poetry install
```

### Lokaler Start

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8080
```

**Voraussetzung:** Trivy, Grype, Syft und OSV Scanner müssen lokal installiert sein, oder der Scanner wird im Docker-Container betrieben.

### Docker Build

Basierend auf `python:3.13-slim`. Scanner-Binaries werden aus den offiziellen Container-Images kopiert (Trivy, Grype, Syft). OSV Scanner wird als GitHub-Release heruntergeladen.

```bash
docker build -t hecate-scanner ./scanner
docker run -p 8080:8080 hecate-scanner
```

## Technologie-Stack

| Technologie | Zweck |
|------------|-------|
| Python 3.13 | Laufzeitumgebung |
| FastAPI | HTTP-API |
| Uvicorn | ASGI-Server |
| Trivy | Schwachstellen-Scanner |
| Grype | Schwachstellen-Scanner |
| Syft | SBOM-Generator (CycloneDX) |
| OSV Scanner | Schwachstellen-Scanner (OSV DB) |
