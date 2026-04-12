import { useEffect } from "react";
import { useI18n } from "../i18n/context";

export const CiCdInfoPage = () => {
  const { t } = useI18n();

  useEffect(() => {
    document.title = `CI/CD – Hecate`;
  }, []);

  return (
    <div className="page cicd-info-page">
      {/* Overview */}
      <section className="card">
        <h2>{t("CI/CD Integration", "CI/CD-Integration")}</h2>
        <p className="muted">
          {t(
            "Use the Hecate REST API to automatically scan container images and source repositories for vulnerabilities directly from your CI/CD pipelines.",
            "Verwenden Sie die Hecate REST-API, um Container-Images und Source-Repositories automatisch auf Schwachstellen zu scannen — direkt aus Ihren CI/CD-Pipelines."
          )}
        </p>
      </section>

      {/* Prerequisites */}
      <section className="card">
        <h2>{t("Prerequisites", "Voraussetzungen")}</h2>
        <p>
          {t(
            "Ensure the following environment variables are configured on the Hecate backend:",
            "Stellen Sie sicher, dass die folgenden Umgebungsvariablen im Hecate-Backend konfiguriert sind:"
          )}
        </p>
        <table>
          <thead>
            <tr>
              <th>{t("Variable", "Variable")}</th>
              <th>{t("Description", "Beschreibung")}</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><code>SCA_ENABLED=true</code></td>
              <td>{t("Enables the SCA scanning feature", "Aktiviert die SCA-Scan-Funktion")}</td>
            </tr>
            <tr>
              <td><code>SCA_API_KEY</code></td>
              <td>{t("Secret API key for authenticating CI/CD requests", "Geheimer API-Schlüssel zur Authentifizierung von CI/CD-Anfragen")}</td>
            </tr>
            <tr>
              <td><code>SCA_SCANNER_URL</code></td>
              <td>{t("Scanner sidecar URL (default: http://scanner:8080)", "Scanner-Sidecar-URL (Standard: http://scanner:8080)")}</td>
            </tr>
            <tr>
              <td><code>SCA_SCANNER_TIMEOUT_SECONDS</code></td>
              <td>{t("Scan timeout in seconds (default: 600)", "Scan-Timeout in Sekunden (Standard: 600)")}</td>
            </tr>
          </tbody>
        </table>
      </section>

      {/* Available Scanners */}
      <section className="card">
        <h2>{t("Available Scanners", "Verfügbare Scanner")}</h2>
        <table>
          <thead>
            <tr>
              <th>{t("Scanner", "Scanner")}</th>
              <th>{t("Type", "Typ")}</th>
              <th>{t("Description", "Beschreibung")}</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><code>trivy</code></td>
              <td>{t("Vulnerability", "Schwachstellen")}</td>
              <td>{t("Comprehensive vulnerability scanner for OS packages and language dependencies", "Umfassender Schwachstellen-Scanner für OS-Pakete und Sprachabhängigkeiten")}</td>
            </tr>
            <tr>
              <td><code>grype</code></td>
              <td>{t("Vulnerability", "Schwachstellen")}</td>
              <td>{t("Fast vulnerability scanner by Anchore", "Schneller Schwachstellen-Scanner von Anchore")}</td>
            </tr>
            <tr>
              <td><code>syft</code></td>
              <td>SBOM</td>
              <td>{t("Software Bill of Materials generator (CycloneDX)", "Software-Stücklisten-Generator (CycloneDX)")}</td>
            </tr>
            <tr>
              <td><code>osv-scanner</code></td>
              <td>{t("Vulnerability", "Schwachstellen")}</td>
              <td>{t("Google OSV database scanner", "Google-OSV-Datenbank-Scanner")}</td>
            </tr>
            <tr>
              <td><code>hecate</code></td>
              <td>{t("Malware + SBOM", "Malware + SBOM")}</td>
              <td>{t("Custom SBOM extractor with supply-chain malware detection (35 rules)", "Eigener SBOM-Extraktor mit Supply-Chain-Malware-Erkennung (35 Regeln)")}</td>
            </tr>
            <tr>
              <td><code>semgrep</code></td>
              <td>SAST</td>
              <td>{t("Static analysis for source repositories only", "Statische Analyse nur für Source-Repositories")}</td>
            </tr>
            <tr>
              <td><code>trufflehog</code></td>
              <td>{t("Secrets", "Secrets")}</td>
              <td>{t("Secret detection for source repositories only", "Secret-Erkennung nur für Source-Repositories")}</td>
            </tr>
            <tr>
              <td><code>dockle</code></td>
              <td>{t("Compliance", "Compliance")}</td>
              <td>{t("CIS Docker Benchmark linter for container images only", "CIS-Docker-Benchmark-Linter nur für Container-Images")}</td>
            </tr>
            <tr>
              <td><code>dive</code></td>
              <td>{t("Layer Analysis", "Schichtanalyse")}</td>
              <td>{t("Docker image layer efficiency analysis for container images only", "Docker-Image-Schichtanalyse nur für Container-Images")}</td>
            </tr>
          </tbody>
        </table>
        <p className="muted" style={{ marginTop: "0.5rem" }}>
          {t(
            "If no scanners are specified, the defaults (trivy, grype, syft) are used.",
            "Wenn keine Scanner angegeben werden, werden die Standards (trivy, grype, syft) verwendet."
          )}
        </p>
      </section>

      {/* Pipeline Examples */}
      <section className="card">
        <h2>{t("Pipeline Examples", "Pipeline-Beispiele")}</h2>

        <h3>Shell / cURL</h3>
        <pre><code>{`#!/bin/bash
set -euo pipefail

HECATE_URL="https://hecate.example.com"
API_KEY="\${SCA_API_KEY}"

# 1. Submit scan
RESPONSE=$(curl -sS -X POST "\${HECATE_URL}/api/v1/scans" \\
  -H "X-API-Key: \${API_KEY}" \\
  -H "Content-Type: application/json" \\
  -d '{
    "target": "ghcr.io/my-org/my-app:latest",
    "type": "container_image",
    "scanners": ["trivy", "grype", "syft", "hecate"],
    "commitSha": "'"\${GITHUB_SHA:-}"'",
    "branch": "'"\${GITHUB_REF_NAME:-}"'",
    "pipelineUrl": "'"\${CI_PIPELINE_URL:-}"'",
    "source": "ci_cd"
  }')

SCAN_ID=$(echo "\${RESPONSE}" | jq -r '.scanId')
echo "Scan started: \${SCAN_ID}"

# 2. Poll until complete
while true; do
  STATUS=$(curl -sS "\${HECATE_URL}/api/v1/scans/\${SCAN_ID}" \\
    -H "X-API-Key: \${API_KEY}" | jq -r '.status')
  [ "\${STATUS}" != "running" ] && break
  sleep 5
done

# 3. Check results
RESULT=$(curl -sS "\${HECATE_URL}/api/v1/scans/\${SCAN_ID}" \\
  -H "X-API-Key: \${API_KEY}")
CRITICAL=$(echo "\${RESULT}" | jq '.summary.critical')
HIGH=$(echo "\${RESULT}" | jq '.summary.high')

echo "Scan complete — Critical: \${CRITICAL}, High: \${HIGH}"

if [ "\${CRITICAL}" -gt 0 ]; then
  echo "::error::Critical vulnerabilities found!"
  exit 1
fi`}</code></pre>

        <h3 style={{ marginTop: "1.5rem" }}>GitHub / Gitea Actions</h3>
        <p className="muted" style={{ marginBottom: "0.5rem" }}>
          {t(
            "Use the Hecate Scan Action for a streamlined integration — it handles scan submission, polling, quality gates, and optional SonarQube export in a single step.",
            "Verwenden Sie die Hecate Scan Action für eine vereinfachte Integration — sie übernimmt Scan-Übermittlung, Polling, Quality Gates und optionalen SonarQube-Export in einem Schritt."
          )}
        </p>
        <pre><code>{`name: Security Scan
on:
  push:
    branches: [main]
  pull_request:

jobs:
  hecate-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Scan image via Hecate
        id: scan
        uses: 0x3e4/hecate-scan-action@v1
        with:
          hecate-url: \${{ secrets.HECATE_URL }}
          api-key: \${{ secrets.SCA_API_KEY }}
          target: "ghcr.io/\${{ github.repository }}:latest"
          scanners: trivy,grype,syft,hecate
          fail-on: critical
          sonarqube-export: true`}</code></pre>
        <p className="muted" style={{ marginTop: "0.5rem" }}>
          {t(
            "Action inputs: hecate-url, api-key, target, type (container_image / source_repo), scanners, fail-on (critical / high / medium / low), sonarqube-export, source-archive (base64 ZIP for private repos), timeout, poll-interval.",
            "Action-Inputs: hecate-url, api-key, target, type (container_image / source_repo), scanners, fail-on (critical / high / medium / low), sonarqube-export, source-archive (Base64-ZIP für private Repos), timeout, poll-interval."
          )}
        </p>
        <p className="muted" style={{ marginTop: "0.25rem" }}>
          {t(
            "Outputs: scan-id, status, findings-total, findings-critical, findings-high, sonarqube-report-file.",
            "Outputs: scan-id, status, findings-total, findings-critical, findings-high, sonarqube-report-file."
          )}
        </p>

        <h3 style={{ marginTop: "1.5rem" }}>GitLab CI</h3>
        <pre><code>{`hecate-scan:
  stage: test
  image: curlimages/curl:latest
  variables:
    HECATE_URL: "https://hecate.example.com"
  script:
    - |
      RESPONSE=$(curl -sS -X POST "\${HECATE_URL}/api/v1/scans" \\
        -H "X-API-Key: \${HECATE_API_KEY}" \\
        -H "Content-Type: application/json" \\
        -d '{
          "target": "'\${CI_REGISTRY_IMAGE}:\${CI_COMMIT_SHA}'",
          "type": "container_image",
          "scanners": ["trivy", "grype", "syft", "hecate"],
          "commitSha": "'\${CI_COMMIT_SHA}'",
          "branch": "'\${CI_COMMIT_REF_NAME}'",
          "pipelineUrl": "'\${CI_PIPELINE_URL}'",
          "source": "ci_cd"
        }')
      SCAN_ID=$(echo "\${RESPONSE}" | jq -r '.scanId')
      echo "Scan ID: \${SCAN_ID}"
    - |
      while true; do
        STATUS=$(curl -sS "\${HECATE_URL}/api/v1/scans/\${SCAN_ID}" \\
          -H "X-API-Key: \${HECATE_API_KEY}" | jq -r '.status')
        [ "\${STATUS}" != "running" ] && break
        sleep 5
      done
    - |
      CRITICAL=$(curl -sS "\${HECATE_URL}/api/v1/scans/\${SCAN_ID}" \\
        -H "X-API-Key: \${HECATE_API_KEY}" | jq '.summary.critical')
      if [ "\${CRITICAL}" -gt 0 ]; then
        echo "Critical vulnerabilities found!"
        exit 1
      fi`}</code></pre>
      </section>

      {/* Source Repo Scanning */}
      <section className="card">
        <h2>{t("Source Repository Scanning", "Source-Repository-Scanning")}</h2>
        <p>
          {t(
            "To scan a source repository, set the type to source_repo and provide the repository URL as the target. Hecate will clone the repository and run the selected scanners. For private repositories or local code, you can upload a base64-encoded ZIP archive:",
            "Um ein Source-Repository zu scannen, setzen Sie den Typ auf source_repo und geben Sie die Repository-URL als Target an. Hecate klont das Repository und führt die ausgewählten Scanner aus. Für private Repositories oder lokalen Code können Sie ein Base64-kodiertes ZIP-Archiv hochladen:"
          )}
        </p>
        <pre><code>{`# Create archive (exclude unnecessary files)
zip -r source.zip . -x "node_modules/*" ".git/*" "dist/*" "build/*"

# Encode and submit
BASE64=$(base64 < source.zip | tr -d '\\n')

curl -sS -X POST "\${HECATE_URL}/api/v1/scans" \\
  -H "X-API-Key: \${API_KEY}" \\
  -H "Content-Type: application/json" \\
  -d '{
    "target": "https://github.com/my-org/my-app",
    "type": "source_repo",
    "scanners": ["trivy", "grype", "syft", "hecate", "semgrep", "trufflehog"],
    "sourceArchiveBase64": "'"\${BASE64}"'",
    "source": "ci_cd"
  }'`}</code></pre>
        <p className="muted" style={{ marginTop: "0.5rem" }}>
          {t(
            "Maximum archive size: 50 MB. The archive must be a valid ZIP file.",
            "Maximale Archivgröße: 50 MB. Das Archiv muss eine gültige ZIP-Datei sein."
          )}
        </p>
      </section>

      {/* Quality Gate */}
      <section className="card">
        <h2>{t("Quality Gate", "Qualitäts-Gate")}</h2>
        <p>
          {t(
            "Use the scan summary to enforce security policies in your pipeline. The response includes severity counts that you can use to fail builds:",
            "Verwenden Sie die Scan-Zusammenfassung, um Sicherheitsrichtlinien in Ihrer Pipeline durchzusetzen. Die Antwort enthält Schweregrad-Zähler, die Sie zum Abbrechen von Builds verwenden können:"
          )}
        </p>
        <pre><code>{`RESULT=$(curl -sS "\${HECATE_URL}/api/v1/scans/\${SCAN_ID}" \\
  -H "X-API-Key: \${API_KEY}")

CRITICAL=$(echo "\${RESULT}" | jq '.summary.critical')
HIGH=$(echo "\${RESULT}" | jq '.summary.high')

# Fail on critical vulnerabilities
[ "\${CRITICAL}" -gt 0 ] && exit 1

# Fail if critical + high exceeds threshold
TOTAL_SEVERE=$((CRITICAL + HIGH))
[ "\${TOTAL_SEVERE}" -gt 10 ] && exit 1

echo "Security gate passed."`}</code></pre>
      </section>
    </div>
  );
};
