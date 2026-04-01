# Hecate Scanner Sidecar

Scanner-Sidecar für die SCA-Funktionalität (Software Composition Analysis) von Hecate. Führt Schwachstellen-Scans und SBOM-Generierung für Container-Images und Source-Repositories durch.

## Installierte Scanner-Tools

| Tool | Zweck | Output-Format |
|------|-------|---------------|
| [Trivy](https://github.com/aquasecurity/trivy) | Schwachstellen-Scan + SBOM | `trivy-json` |
| [Grype](https://github.com/anchore/grype) | Schwachstellen-Scan | `grype-json` |
| [Syft](https://github.com/anchore/syft) | SBOM-Generierung | `cyclonedx-json` |
| [OSV Scanner](https://github.com/google/osv-scanner) | Schwachstellen-Scan (OSV DB) | `osv-json` |
| Hecate Analyzer | SBOM-Extraktion (18 Parser, 12 Ökosysteme) + Malware-Erkennung | `hecate-json` |
| [Dockle](https://github.com/goodwithtech/dockle) | CIS Docker Benchmark Linter (nur Container-Images) | `dockle-json` |
| [Dive](https://github.com/wagoodman/dive) | Docker-Image-Schichtanalyse (nur Container-Images) | `dive-json` |
| [Semgrep](https://github.com/semgrep/semgrep) | SAST-Scanner (nur Source-Repos) | `semgrep-json` |
| [TruffleHog](https://github.com/trufflesecurity/trufflehog) | Secret-Scanner (nur Source-Repos) | `trufflehog-json` |

Trivy, Grype, Syft, Dockle und OSV Scanner werden als Binaries im Docker-Image installiert. Dive und TruffleHog werden als GitHub-Releases heruntergeladen. Semgrep wird via pip installiert. Der Hecate Analyzer ist ein nativer Python-Scanner ohne externe Abhängigkeiten.

**Hinweis:** Dockle und Dive sind nur für Container-Image-Scans verfügbar. Semgrep, TruffleHog, OSV Scanner und Hecate Analyzer sind nur für Source-Repo-Scans verfügbar.

### Erweiterte Erkennung
- **Trivy:** `--list-all-pkgs` für vollständige Paketlistung (inkl. nicht-vulnerabler Pakete)
- **Syft:** `SYFT_DEFAULT_CATALOGERS=all` aktiviert alle Katalogisierer inkl. Binary-Erkennung (erkennt Binaries wie Trivy, Grype etc. die via Dockerfile `COPY --from=` installiert wurden)

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
        │                |  Hecate   |
        │                |  Dockle   |
        │                |  Dive     |
        │                |  Semgrep  |
        │                |  TruffleH.|
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
| `scanners` | string[] | Liste der Scanner (`trivy`, `grype`, `syft`, `osv-scanner`, `hecate`, `dockle`, `dive`) |

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

## Hecate Analyzer & Malware-Erkennung

### SBOM-Extraktion

Der Hecate Analyzer (`scanner/app/hecate_analyzer.py`) extrahiert SBOM-Komponenten aus 18 Manifest-Typen über 12 Ökosysteme. Lockfiles werden bevorzugt (exakte Versionen), Manifest-Fallback für deklarierte Abhängigkeiten.

| Ökosystem | Manifest-Dateien | PURL-Typ |
|-----------|-----------------|----------|
| Docker | `Dockerfile*`, `docker-compose*.yml` | `pkg:docker` |
| npm | `package.json` | `pkg:npm` |
| Python | `requirements*.txt`, `pyproject.toml`, `Pipfile`, `setup.cfg` | `pkg:pypi` |
| Go | `go.mod` | `pkg:golang` |
| Rust | `Cargo.toml` | `pkg:cargo` |
| Ruby | `Gemfile.lock` (bevorzugt), `Gemfile` | `pkg:gem` |
| PHP | `composer.lock` (bevorzugt), `composer.json` | `pkg:composer` |
| Java | `pom.xml` (inkl. Property-Auflösung), `build.gradle(.kts)` | `pkg:maven` |
| .NET | `*.csproj` (PackageReference), `packages.config` | `pkg:nuget` |
| Swift | `Package.resolved` (v1/v2/v3) | `pkg:swift` |
| Elixir | `mix.lock` | `pkg:hex` |
| Dart/Flutter | `pubspec.lock` (bevorzugt), `pubspec.yaml` | `pkg:pub` |
| CocoaPods | `Podfile.lock` | `pkg:cocoapods` |

**Besonderheiten:**
- Dockerfiles: ARG-Variablen-Auflösung (`${VAR:-default}`), unauflösbare Platzhalter werden übersprungen
- Java/Maven: `${property}`-Platzhalter in Versionen werden über `<properties>` aufgelöst
- Deduplizierung über PURL (Package URL) — identische Pakete aus verschiedenen Manifests werden nur einmal erfasst
- Übersprungene Verzeichnisse: `node_modules/`, `.git/`, `vendor/`, `dist/`, `build/`, `__pycache__/`, `.venv/`

### Malware-Erkennung

Der Malware-Detektor (`scanner/app/malware_detector/`) erkennt potenziell bösartige Pakete über statische Heuristiken. Keine externen Abhängigkeiten — alles in reinem Python implementiert.

#### Detection Rules (34 Rules)

The malware detector implements 34 detection rules across 14 categories, informed by real-world supply chain attacks from 2020-2026.

| Regel-ID | Name | Severity | Kategorie | Quelle / Angriff |
|----------|------|----------|-----------|-----------------|
| HEC-001 | npm install script detected | medium | `install_hook` | — (Standard-Heuristik) |
| HEC-002 | npm install script with suspicious payload | critical | `install_hook` | — (Standard-Heuristik) |
| HEC-003 | Python setup.py cmdclass override | medium | `install_hook` | — (Standard-Heuristik) |
| HEC-004 | Python setup.py cmdclass with suspicious payload | critical | `install_hook` | — (Standard-Heuristik) |
| HEC-010 | Potential credential exfiltration | critical | `exfiltration` | — (Standard-Heuristik) |
| HEC-011 | Dynamic code execution with network access | high | `suspicious_api` | — (Standard-Heuristik) |
| HEC-012 | Encoded payload with network access | high | `suspicious_api` | — (Standard-Heuristik) |
| HEC-013 | Suspicious API usage | low | `suspicious_api` | — (Standard-Heuristik) |
| HEC-020 | Obfuscated code detected | medium | `obfuscation` | — (Standard-Heuristik) |
| HEC-021 | Heavily obfuscated code | high | `obfuscation` | — (Standard-Heuristik) |
| HEC-022 | Multi-layer encoded payload | high | `obfuscation` | [LiteLLM v1.82.8](https://snyk.io/articles/poisoned-security-scanner-backdooring-litellm/) (double-base64), [s1ngularity/Nx](https://orca.security/resources/blog/s1ngularity-supply-chain-attack/) (triple-base64) |
| HEC-023 | Invisible Unicode characters in source code | high | `unicode_obfuscation` | [Glassworm](https://arstechnica.com/security/2026/03/supply-chain-attack-using-invisible-code-hits-github-and-other-repositories/) (151+ packages, Variation Selectors, PUA) |
| HEC-024 | Invisible Unicode payload with code execution | critical | `unicode_obfuscation` | [Glassworm](https://arstechnica.com/security/2026/03/supply-chain-attack-using-invisible-code-hits-github-and-other-repositories/) (eval + .codePointAt decoder) |
| HEC-030 | Potential typosquatting package | high | `typosquatting` | [DIMVA 2020 Study](https://pmc.ncbi.nlm.nih.gov/articles/PMC7338168/) (61% of malicious packages) |
| HEC-031 | Potential scope squatting | medium | `typosquatting` | — (Standard-Heuristik) |
| HEC-040 | Python .pth file with executable code | medium | `pth_backdoor` | [LiteLLM v1.82.8](https://snyk.io/articles/poisoned-security-scanner-backdooring-litellm/) (.pth fires on every python startup) |
| HEC-041 | Python .pth file with suspicious payload | critical | `pth_backdoor` | [LiteLLM v1.82.8](https://snyk.io/articles/poisoned-security-scanner-backdooring-litellm/) (34KB .pth, credential theft + systemd C2) |
| HEC-050 | GitHub Action pinned to mutable tag | high | `cicd` | [tj-actions/changed-files CVE-2025-30066](https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-tj-actionschanged-files-cve-2025-30066-and-reviewdogaction) (tag poisoning, 23K repos) |
| HEC-051 | Dangerous pull_request_target workflow | critical | `cicd` | [Trivy v0.69.4](https://www.paloaltonetworks.com/blog/cloud-security/trivy-supply-chain-attack/) (PAT theft via misconfigured workflow) |
| HEC-052 | Process memory access in CI workflow | critical | `cicd` | [Trivy v0.69.4](https://www.paloaltonetworks.com/blog/cloud-security/trivy-supply-chain-attack/), [tj-actions](https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-tj-actionschanged-files-cve-2025-30066-and-reviewdogaction) (/proc/mem harvesting) |
| HEC-053 | curl/wget piped to shell in CI workflow | high | `cicd` | — (CI-Security Best Practice) |
| HEC-054 | Unpinned third-party GitHub Action | medium | `cicd` | [tj-actions/changed-files CVE-2025-30066](https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-tj-actionschanged-files-cve-2025-30066-and-reviewdogaction) |
| HEC-055 | Direct process memory access | critical | `suspicious_api` | [Trivy v0.69.4](https://www.paloaltonetworks.com/blog/cloud-security/trivy-supply-chain-attack/) (/proc/pid/mem, bypasses log masking) |
| HEC-060 | System persistence mechanism detected | high | `persistence` | [Trivy v0.69.4](https://www.paloaltonetworks.com/blog/cloud-security/trivy-supply-chain-attack/) (blockchain canister C2), [LiteLLM](https://snyk.io/articles/poisoned-security-scanner-backdooring-litellm/) (sysmon.service), [Telnyx SDK](https://telnyx.com/resources/telnyx-python-sdk-supply-chain-security-notice-march-2026) (Windows Startup folder) |
| HEC-061 | Persistence mechanism with suspicious payload | critical | `persistence` | [Trivy v0.69.4](https://www.paloaltonetworks.com/blog/cloud-security/trivy-supply-chain-attack/), [LiteLLM v1.82.8](https://snyk.io/articles/poisoned-security-scanner-backdooring-litellm/) (systemd + network C2) |
| HEC-070 | Kubernetes privilege escalation | critical | `kubernetes` | [LiteLLM v1.82.8](https://snyk.io/articles/poisoned-security-scanner-backdooring-litellm/) (privileged pods in kube-system) |
| HEC-075 | Package self-propagation detected | critical | `worm` | [Shai-Hulud V2](https://about.gitlab.com/blog/gitlab-discovers-widespread-npm-supply-chain-attack/) (npm publish worm, 47+ packages in <60s) |
| HEC-076 | Destructive file operations detected | critical | `worm` | [Shai-Hulud V2](https://about.gitlab.com/blog/gitlab-discovers-widespread-npm-supply-chain-attack/) (dead man's switch: shred, cipher /W:, del) |
| HEC-077 | External runtime/tool download in install script | high | `install_hook` | [Shai-Hulud V2](https://about.gitlab.com/blog/gitlab-discovers-widespread-npm-supply-chain-attack/) (Bun installer disguise, weaponized Trufflehog) |
| HEC-078 | AI tool bypass flags detected | critical | `ai_abuse` | [s1ngularity/Nx](https://orca.security/resources/blog/s1ngularity-supply-chain-attack/) (first AI CLI tool abuse: --yolo, --trust-all-tools) |
| HEC-079 | Conditional execution based on environment detection | medium | `sandbox_evasion` | [DIMVA 2020 Study](https://pmc.ncbi.nlm.nih.gov/articles/PMC7338168/) (41% of malicious packages use conditional execution) |
| HEC-080 | Sandbox evasion with suspicious payload | high | `sandbox_evasion` | [DIMVA 2020 Study](https://pmc.ncbi.nlm.nih.gov/articles/PMC7338168/) (CI env check + credential theft) |
| HEC-081 | Platform-specific payload delivery | high | `suspicious_api` | [Telnyx SDK](https://telnyx.com/resources/telnyx-python-sdk-supply-chain-security-notice-march-2026) (sys.platform + subprocess per OS) |
| HEC-082 | Media file steganography pattern | high | `obfuscation` | [Telnyx SDK](https://telnyx.com/resources/telnyx-python-sdk-supply-chain-security-notice-march-2026) (WAV steganography C2, XOR decode) |
| HEC-090 | Known compromised package version | critical | `known_compromised` | Blocklist: [LiteLLM 1.82.7/1.82.8](https://snyk.io/articles/poisoned-security-scanner-backdooring-litellm/), [nx 20.9-20.12/21.5-21.8](https://orca.security/resources/blog/s1ngularity-supply-chain-attack/), [telnyx 4.87.1/4.87.2](https://telnyx.com/resources/telnyx-python-sdk-supply-chain-security-notice-march-2026), [axios 1.14.1/0.30.4](https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan), [Shai-Hulud @ctrl/tinycolor + 37 packages](https://unit42.paloaltonetworks.com/npm-supply-chain-attack/), [TeamPCP: trivy-action, setup-trivy, kics-github-action, ast-github-action](https://www.wiz.io/blog/tracking-teampcp-investigating-post-compromise-attacks-seen-in-the-wild) |

#### Kategorien-Zusammenfassung

| Kategorie | Regel-IDs | Beschreibung |
|-----------|-----------|-------------|
| `install_hook` | HEC-001–004, HEC-077 | npm preinstall/postinstall-Skripte, Python setup.py cmdclass, Runtime-Downloads |
| `suspicious_api` | HEC-010–013, HEC-055 | Gefährliche API-Kombinationen, Prozessspeicher-Zugriff |
| `exfiltration` | HEC-010 | Credential-Zugriff + Network-Calls |
| `obfuscation` | HEC-020–022 | Base64-Blöcke, Hex-Strings, Multi-Layer-Encoding |
| `unicode_obfuscation` | HEC-023–024 | Unsichtbare Unicode-Zeichen (Variation Selectors, PUA, Homoglyphen) |
| `typosquatting` | HEC-030–031 | Levenshtein-Distanz gegen Top-200 npm/PyPI + Scope-Squatting |
| `pth_backdoor` | HEC-040–041 | Python .pth-Dateien mit ausführbarem Code |
| `cicd` | HEC-050–054 | GitHub Actions, CI/CD-Pipeline-Sicherheit |
| `persistence` | HEC-060–061 | systemd, cron, launchd, Windows Startup/Registry Run Keys, xdg-autostart |
| `kubernetes` | HEC-070 | Privilegierte Pods, kube-system, RBAC-Eskalation |
| `worm` | HEC-075–076 | Selbstverbreitung, destruktive Payloads |
| `ai_abuse` | HEC-078 | KI-Tool-Missbrauch (Bypass-Flags) |
| `sandbox_evasion` | HEC-079–080 | Bedingte Ausführung basierend auf Umgebungserkennung |
| `known_compromised` | HEC-090 | Blocklist bekannter kompromittierter Paketversionen und GitHub Actions (LiteLLM, Nx, Telnyx, Axios, Shai-Hulud, TeamPCP) |

#### Kombinations-Scoring

Einzelne Pattern-Matches erzeugen `low`/`medium`-Severity. Kombinationen im selben File eskalieren:

| Kombination | Severity |
|-------------|----------|
| Credential-Zugriff + Network-Zugriff | `critical` |
| Code-Execution + Network-Zugriff | `high` |
| Data-Encoding + Network-Zugriff | `high` |
| .pth-Datei + Netzwerk/Credentials/Encoding | `critical` |
| Persistenz + Network/Encoding | `critical` |
| Unsichtbares Unicode + eval/Function/exec | `critical` |
| CI-Umgebungserkennung + Payload | `high` |
| Platform-Detection + Subprocess/Network | `high` |
| Media-Download + XOR-Decode + Network | `high` |

#### Confidence-Level

- **high**: Kombination mehrerer verdächtiger Patterns, bekannte kompromittierte Version, oder Typosquatting mit Levenshtein-Distanz 1
- **medium**: Install-Hook mit verdächtigem Payload, einzelne gefährliche API-Kombination, oder unsichtbare Unicode-Zeichen ohne Code-Execution
- **low**: Einzelnes verdächtiges Pattern ohne Kontext

#### False-Positive-Schutz

- Übersprungene Verzeichnisse: `node_modules/`, `.git/`, `vendor/`, `dist/`, `build/`, `__pycache__/`, `.venv/`
- Übersprungene Dateien: minifizierte Dateien (durchschnittliche Zeilenlänge > 500), Dateien > 1MB
- Paket-Allowlist via `HECATE_MALWARE_ALLOWLIST` Env-Var (kommagetrennt)
- Typosquatting: 3-Tier-Validierung (Lockfile → Registry → Levenshtein)
- Unicode: BOM am Dateianfang wird ignoriert, Schwellenwert ≥ 5 unsichtbare Zeichen
- Unicode/Homoglyphen: Locale-Awareness — Dateien in locale/i18n/translations-Verzeichnissen und Dateien mit >1% Cyrillic-Dichte werden übersprungen
- Credentials: Generische Env-Variablen (SECRET_KEY, DATABASE_URL, PRIVATE_KEY) werden nicht mehr als Credential-Zugriff gewertet

#### Quellen und Referenzen

Die Detection Rules basieren auf der Analyse folgender realer Supply-Chain-Angriffe:

| Angriff | Datum | Hauptvektor | Referenz |
|---------|-------|-------------|----------|
| Trivy v0.69.4 (TeamPCP) | März 2026 | pull_request_target, /proc/mem, systemd C2 via Blockchain | [Palo Alto Unit 42](https://www.paloaltonetworks.com/blog/cloud-security/trivy-supply-chain-attack/) |
| LiteLLM v1.82.7/1.82.8 | März 2026 | .pth-Backdoor, double-base64, K8s Lateral Movement | [Snyk](https://snyk.io/articles/poisoned-security-scanner-backdooring-litellm/) |
| Glassworm | Okt 2025 – März 2026 | Unsichtbares Unicode, LLM-generierte Cover-Commits | [Ars Technica](https://arstechnica.com/security/2026/03/supply-chain-attack-using-invisible-code-hits-github-and-other-repositories/) |
| Shai-Hulud V2 | Nov 2025 | npm-Wurm, Bun-Tarnung, Dead Man's Switch | [GitLab](https://about.gitlab.com/blog/gitlab-discovers-widespread-npm-supply-chain-attack/) |
| s1ngularity/Nx | Aug 2025 | AI-Tool-Missbrauch, Triple-Base64 | [Orca Security](https://orca.security/resources/blog/s1ngularity-supply-chain-attack/) |
| tj-actions/changed-files (CVE-2025-30066) | März 2025 | Tag-Poisoning, Runner-Memory-Dump | [CISA](https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-tj-actionschanged-files-cve-2025-30066-and-reviewdogaction) |
| Telnyx SDK v4.87.1/4.87.2 (TeamPCP) | März 2026 | WAV-Steganografie, plattformspezifische Payloads, Windows Startup Persistence | [Telnyx](https://telnyx.com/resources/telnyx-python-sdk-supply-chain-security-notice-march-2026) |
| Axios v1.14.1/v0.30.4 | März 2026 | Gestohlene Maintainer-Credentials, RAT-Dropper via plain-crypto-js, Self-Cleaning | [StepSecurity](https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan) |
| Shai-Hulud (V1 + V2) | Sep–Nov 2025 | npm-Wurm, preinstall credential theft, self-propagation via npm publish, destructive fallback | [Unit 42](https://unit42.paloaltonetworks.com/npm-supply-chain-attack/) |
| TeamPCP/KICS GitHub Actions | März 2026 | GitHub Action Tag-Hijacking, Credential Harvesting | [Checkmarx](https://checkmarx.com/blog/checkmarx-security-update/), [Wiz](https://www.wiz.io/blog/tracking-teampcp-investigating-post-compromise-attacks-seen-in-the-wild) |
| Backstabber's Knife Collection | 2020 (Studie) | Taxonomie von 174 bösartigen Paketen | [PMC/DIMVA](https://pmc.ncbi.nlm.nih.gov/articles/PMC7338168/) |

#### Output-Format (`hecate-json`)

```json
{
  "components": [
    {"type": "container", "name": "python", "version": "3.13-slim", ...}
  ],
  "findings": [
    {
      "ruleId": "HEC-001",
      "ruleName": "npm postinstall script with suspicious payload",
      "severity": "critical",
      "category": "install_hook",
      "packageName": "evil-package",
      "packageVersion": "1.0.0",
      "filePath": "package.json",
      "evidence": "\"postinstall\": \"node -e 'require(\\\"child_process\\\")...'\"",
      "confidence": "high",
      "description": "..."
    }
  ],
  "bomFormat": "CycloneDX",
  "specVersion": "1.5"
}
```

### Provenance-Verifikation

Nach der SBOM-Extraktion prüft der Hecate Analyzer optional die Provenance (Herkunft/Attestierung) jeder Komponente über Registry-APIs. Unterstützte Ökosysteme:

| Ökosystem | Registry | Prüfung |
|-----------|----------|---------|
| npm | `registry.npmjs.org` | Sigstore-Attestierungen, GitHub Actions Build-Provenance |
| PyPI | `pypi.org/integrity/` | PEP 740 Attestations (Trusted Publishers, Sigstore) |
| Go | `sum.golang.org` | Go Checksum Database (Transparency Log) |
| Maven | `search.maven.org` | PGP-Signaturen, Sigstore |
| RubyGems | `rubygems.org/api/v2/` | SHA-Checksums, Sigstore |
| Cargo | `crates.io/api/v1/` | Checksum-Verifikation |
| NuGet | `api.nuget.org/v3/` | Package-Signatur-Validierung |
| Docker | Registry v2 API | Cosign-Signaturen, Content Trust |

- Inspiriert von [who-touched-my-packages](https://github.com/Point-Wild/who-touched-my-packages)
- Async httpx mit 5s Timeout pro Request, `asyncio.Semaphore(10)` für Concurrency
- In-Memory Cache pro Scan (keine doppelten Lookups)
- Best-effort: Fehler werden ignoriert, unterbrechen nie den Scan
- Ergebnisse werden als `provenance`-Objekt auf SBOM-Komponenten gespeichert (verified, source_repo, build_system, attestation_type)
- Frontend zeigt Provenance-Status in SBOM-Tabelle: ✓ (verified), ⚠ (unverified), — (unknown)

### Scan-Metadaten

- **Source-Repos**: Git-Commit-SHA wird aus dem geklonten Repository extrahiert
- **Container-Images**: Image-Digest via `docker inspect` oder `skopeo inspect`

## Sandbox-Hardening

Der Scanner-Container ist gehärtet, da er beliebigen Code (geklonte Repos) verarbeitet:

```yaml
scanner:
  security_opt:
    - no-new-privileges:true
  read_only: true
  tmpfs:
    - /tmp:size=10G
  cap_drop:
    - ALL
  deploy:
    resources:
      limits:
        memory: 12G
```

- Scans laufen in temporären Verzeichnissen unter `/tmp`
- Kein Docker-Socket-Mounting — Image-Pulls erfolgen über die Registry-API
- Ressourcen-Limit: 12 GB Memory, 10 GB tmpfs (notwendig für große Container-Images wenn Trivy DB + Grype DB + Dive tar + Schicht-Extraktion gleichzeitig laufen)

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
      memory: 12G
```

## Konfiguration

| Variable | Default | Beschreibung |
|----------|---------|-------------|
| `SCANNER_AUTH` | — | Authentifizierung für Registries und Git-Repos (`host:token`, kommagetrennt) |
| `SYFT_DEFAULT_CATALOGERS` | `all` | Syft-Katalogisierer (im Dockerfile gesetzt, aktiviert Binary-Erkennung) |
| `HECATE_MALWARE_ALLOWLIST` | — | Kommagetrennte Paketnamen, die bei der Malware-Erkennung ignoriert werden |

Die Backend-seitige Konfiguration des Sidecar erfolgt über:

| Variable | Default | Beschreibung |
|----------|---------|-------------|
| `SCA_SCANNER_URL` | `http://scanner:8080` | URL des Scanner-Sidecar |
| `SCA_SCANNER_TIMEOUT_SECONDS` | `600` | Timeout für Scan-Anfragen |

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
| Hecate Analyzer | SBOM-Extraktor + Malware-Detektor |
| Dockle | CIS Docker Benchmark Linter |
| Dive | Docker-Image-Schichtanalyse |
