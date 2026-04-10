# Hecate Security Scan Action

Composite GitHub/Gitea Action that submits a vulnerability scan to a [Hecate](https://hecate.pw) instance, polls for completion, enforces severity thresholds, and optionally exports findings in SonarQube external issues format.

## Usage

### Basic (container image)

```yaml
- name: Scan image via Hecate
  uses: rk/hecate/actions/hecate-scan@main
  with:
    hecate-url: ${{ secrets.HECATE_URL }}
    api-key: ${{ secrets.SCA_API_KEY }}
    target: ghcr.io/my-org/my-app:latest
```

### With quality gate

```yaml
- name: Scan image via Hecate
  uses: rk/hecate/actions/hecate-scan@main
  with:
    hecate-url: ${{ secrets.HECATE_URL }}
    api-key: ${{ secrets.SCA_API_KEY }}
    target: ghcr.io/my-org/my-app:latest
    scanners: trivy,grype,syft,hecate
    fail-on: critical
```

### Source repository scan

```yaml
- name: Create source archive
  run: |
    zip -r /tmp/source.zip . -x ".git/*" "node_modules/*" "dist/*"
    echo "archive=$(base64 -w0 /tmp/source.zip)" >> $GITHUB_OUTPUT
  id: archive

- name: Scan source via Hecate
  uses: rk/hecate/actions/hecate-scan@main
  with:
    hecate-url: ${{ secrets.HECATE_URL }}
    api-key: ${{ secrets.SCA_API_KEY }}
    target: ${{ github.repository }}
    type: source_repo
    source-archive: ${{ steps.archive.outputs.archive }}
    scanners: trivy,grype,syft,hecate,semgrep,trufflehog
```

### With SonarQube export

```yaml
- name: Scan via Hecate
  id: scan
  uses: rk/hecate/actions/hecate-scan@main
  with:
    hecate-url: ${{ secrets.HECATE_URL }}
    api-key: ${{ secrets.SCA_API_KEY }}
    target: ghcr.io/my-org/my-app:latest
    sonarqube-export: true
    sonarqube-output-file: hecate-sonar.json

- name: Upload to SonarQube
  run: |
    sonar-scanner \
      -Dsonar.host.url="${{ secrets.SONARQUBE_HOST }}" \
      -Dsonar.token="${{ secrets.SONARQUBE_TOKEN }}" \
      -Dsonar.projectKey=my-project \
      -Dsonar.sources=. \
      -Dsonar.externalIssuesReportPaths="${{ steps.scan.outputs.sonarqube-report-file }}"
```

### Local reference (same repo)

```yaml
- uses: ./actions/hecate-scan
  with:
    hecate-url: ${{ secrets.HECATE_URL }}
    api-key: ${{ secrets.SCA_API_KEY }}
    target: my-image:latest
```

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `hecate-url` | **yes** | | Hecate instance URL |
| `api-key` | **yes** | | SCA API key |
| `target` | **yes** | | Image ref or repo URL |
| `type` | no | `container_image` | `container_image` or `source_repo` |
| `scanners` | no | server defaults | Comma-separated scanner list |
| `source-archive` | no | | Base64-encoded ZIP for private source repos |
| `wait` | no | `true` | Wait for scan completion |
| `poll-interval` | no | `10` | Seconds between polls |
| `timeout` | no | `600` | Max wait seconds |
| `fail-on` | no | | Severity threshold: `critical`, `high`, `medium`, `low` |
| `sonarqube-export` | no | `false` | Export SonarQube external issues |
| `sonarqube-output-file` | no | `hecate-sonar-issues.json` | Output filename |
| `commit-sha` | no | `${{ github.sha }}` | Commit SHA |
| `branch` | no | `${{ github.ref_name }}` | Branch name |

## Outputs

| Output | Description |
|--------|-------------|
| `scan-id` | Hecate scan ID |
| `status` | Final status: `completed`, `failed`, `timeout` |
| `findings-total` | Total findings |
| `findings-critical` | Critical findings |
| `findings-high` | High findings |
| `sonarqube-report-file` | Path to SonarQube report (if exported) |

## Available Scanners

| Scanner | Type | Targets |
|---------|------|---------|
| `trivy` | Vulnerability | Images + Repos |
| `grype` | Vulnerability | Images + Repos |
| `syft` | SBOM | Images + Repos |
| `osv-scanner` | Vulnerability | Images + Repos |
| `hecate` | Malware + SBOM | Images + Repos |
| `semgrep` | SAST | Repos only |
| `trufflehog` | Secrets | Repos only |
| `dockle` | Compliance | Images only |
| `dive` | Layer Analysis | Images only |

## Prerequisites

- Hecate instance with `SCA_ENABLED=true` and `SCA_API_KEY` configured
- Scanner sidecar running alongside Hecate backend
- Runner with `curl` and `jq` available (standard on `ubuntu-latest`)
