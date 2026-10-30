import "../screens/info.css";

import { useEffect, useState } from "react";
import { LuCheck, LuCopy } from "react-icons/lu";

import { useToastContext } from "../components/ToastProvider";
import { useI18n } from "../i18n/context";
import { IconButton, PageHeader, Section } from "../ui/primitives";

/** A code sample with its copy control. Shared by the three documentation screens. */
export const InfoCodeBlock = ({ code }: { code: string }) => {
  const { t } = useI18n();
  const { showToast } = useToastContext();
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!copied) return;
    const timer = setTimeout(() => setCopied(false), 1500);
    return () => clearTimeout(timer);
  }, [copied]);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
    } catch {
      showToast(t("Failed to copy to clipboard", "Fehler beim Kopieren in die Zwischenablage"), "error");
    }
  };

  return (
    <div className="info-code">
      <pre><code>{code}</code></pre>
      <IconButton
        label={copied ? t("Copied", "Kopiert") : t("Copy code", "Code kopieren")}
        className="info-code-copy"
        onClick={() => void handleCopy()}
      >
        {copied ? <LuCheck aria-hidden="true" /> : <LuCopy aria-hidden="true" />}
      </IconButton>
      <span className="visually-hidden" role="status">{copied ? t("Copied", "Kopiert") : ""}</span>
    </div>
  );
};

export const CiCdInfoPage = () => {
  const { t } = useI18n();

  useEffect(() => {
    document.title = `CI/CD - Hecate`;
  }, []);

  return (
    <div className="page info-doc">
      <PageHeader
        title={t("CI/CD integration", "CI/CD-Integration")}
        description={t(
          "Use the Hecate REST API to automatically scan container images and source repositories for vulnerabilities directly from your CI/CD pipelines.",
          "Verwenden Sie die Hecate REST-API, um Container-Images und Source-Repositories automatisch auf Schwachstellen zu scannen, direkt aus Ihren CI/CD-Pipelines."
        )}
      />

      {/* Prerequisites */}
      <Section title={t("Prerequisites", "Voraussetzungen")} className="info-section">
        <p>
          {t(
            "Ensure the following environment variables are configured on the Hecate backend:",
            "Stellen Sie sicher, dass die folgenden Umgebungsvariablen im Hecate-Backend konfiguriert sind:"
          )}
        </p>
        <div className="table-scroll">
          <table className="info-table">
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
                <td>{t("Scan timeout in seconds (default: 2060)", "Scan-Timeout in Sekunden (Standard: 2060)")}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </Section>

      {/* Pipeline Examples */}
      <Section title={t("Pipeline examples", "Pipeline-Beispiele")} className="info-section">

        <h3>Shell / cURL</h3>
        <InfoCodeBlock code={`#!/bin/bash
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

echo "Scan complete. Critical: \${CRITICAL}, High: \${HIGH}"

if [ "\${CRITICAL}" -gt 0 ]; then
  echo "::error::Critical vulnerabilities found!"
  exit 1
fi`} />

        <h3>GitHub / Gitea Actions</h3>
        <p>
          {t(
            "Use the Hecate Scan Action for a streamlined integration: it handles scan submission, polling, quality gates, and optional SonarQube export in a single step.",
            "Verwenden Sie die Hecate Scan Action für eine vereinfachte Integration: sie übernimmt Scan-Übermittlung, Polling, Quality Gates und optionalen SonarQube-Export in einem Schritt."
          )}
        </p>
        <InfoCodeBlock code={`name: Security Scan
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
          sonarqube-export: true`} />
        <p className="info-note">
          {t("Action inputs: ", "Action-Inputs: ")}
          <code>hecate-url</code>, <code>api-key</code>, <code>target</code>, <code>type</code> (<code>container_image</code> / <code>source_repo</code>), <code>scanners</code>, <code>fail-on</code> (<code>critical</code> / <code>high</code> / <code>medium</code> / <code>low</code>), <code>sonarqube-export</code>, <code>source-archive</code> ({t("base64 ZIP for private repos", "Base64-ZIP für private Repos")}), <code>timeout</code>, <code>poll-interval</code>.
        </p>
        <p className="info-note">
          Outputs: <code>scan-id</code>, <code>status</code>, <code>findings-total</code>, <code>findings-critical</code>, <code>findings-high</code>, <code>sonarqube-report-file</code>.
        </p>

        <h3>GitLab CI</h3>
        <InfoCodeBlock code={`hecate-scan:
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
      fi`} />
      </Section>

      {/* Source Repo Scanning */}
      <Section title={t("Source repository scanning", "Source-Repository-Scanning")} className="info-section">
        <p>
          {t("To scan a source repository, set the type to ", "Um ein Source-Repository zu scannen, setzen Sie den Typ auf ")}
          <code>source_repo</code>
          {t(
            " and provide the repository URL as the target. Hecate will clone the repository and run the selected scanners. For private repositories or local code, you can upload a base64-encoded ZIP archive:",
            " und geben Sie die Repository-URL als Target an. Hecate klont das Repository und führt die ausgewählten Scanner aus. Für private Repositories oder lokalen Code können Sie ein Base64-kodiertes ZIP-Archiv hochladen:"
          )}
        </p>
        <InfoCodeBlock code={`# Create archive (exclude unnecessary files)
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
  }'`} />
        <p className="info-note">
          {t(
            "Maximum archive size: 50 MB. The archive must be a valid ZIP file.",
            "Maximale Archivgröße: 50 MB. Das Archiv muss eine gültige ZIP-Datei sein."
          )}
        </p>
      </Section>

      {/* Version reports */}
      <Section title={t("Report deployed versions", "Ausgerollte Versionen melden")} className="info-section">
        <p>
          {t(
            "After a rollout, tell Hecate which version now runs, so the inventory and its CVE matches stay current without manual edits. The endpoint accepts the same ",
            "Melden Sie Hecate nach einem Rollout, welche Version jetzt läuft, damit das Inventar und seine CVE-Treffer ohne manuelle Pflege aktuell bleiben. Der Endpunkt akzeptiert denselben ",
          )}
          <code>X-API-Key</code>
          {t(" as scan submission.", " wie die Scan-Einreichung.")}
        </p>
        <InfoCodeBlock code={`curl -sS -X POST "\${HECATE_URL}/api/v1/inventory/report" \
  -H "X-API-Key: \${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "reportedBy": "deploy-prod",
    "items": [
      { "productSlug": "nginx", "environment": "prod", "version": "1.30.1" }
    ]
  }'`} />
        <p>
          {t(
            "Each entry has to identify exactly one existing item by itemId, or by any combination of productSlug, vendorSlug, environment and name. The response answers per entry: updated, unchanged, ambiguous when several items fit, not_found when none does. Reports never create items, and every change appears in the item's history.",
            "Jeder Eintrag muss genau einen bestehenden Inventar-Eintrag bezeichnen, über itemId oder eine Kombination aus productSlug, vendorSlug, environment und name. Die Antwort kommt pro Eintrag: updated, unchanged, ambiguous wenn mehrere passen, not_found wenn keiner passt. Meldungen legen nie Einträge an, und jede Änderung erscheint im Verlauf des Eintrags.",
          )}
        </p>
      </Section>

      {/* Quality Gate */}
      <Section title={t("Quality gate", "Qualitäts-Gate")} className="info-section">
        <p>
          {t(
            "Use the scan summary to enforce security policies in your pipeline. The response includes severity counts that you can use to fail builds:",
            "Verwenden Sie die Scan-Zusammenfassung, um Sicherheitsrichtlinien in Ihrer Pipeline durchzusetzen. Die Antwort enthält Schweregrad-Zähler, die Sie zum Abbrechen von Builds verwenden können:"
          )}
        </p>
        <InfoCodeBlock code={`RESULT=$(curl -sS "\${HECATE_URL}/api/v1/scans/\${SCAN_ID}" \\
  -H "X-API-Key: \${API_KEY}")

CRITICAL=$(echo "\${RESULT}" | jq '.summary.critical')
HIGH=$(echo "\${RESULT}" | jq '.summary.high')

# Fail on critical vulnerabilities
[ "\${CRITICAL}" -gt 0 ] && exit 1

# Fail if critical + high exceeds threshold
TOTAL_SEVERE=$((CRITICAL + HIGH))
[ "\${TOTAL_SEVERE}" -gt 10 ] && exit 1

echo "Security gate passed."`} />
      </Section>

      {/* Available Scanners */}
      <Section title={t("Available scanners", "Verfügbare Scanner")} className="info-section">
        <div className="table-scroll">
          <table className="info-table">
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
                <td><code>devskim</code></td>
                <td>SAST</td>
                <td>{t("Microsoft SAST scanner with strong .NET / ASP.NET coverage (source repos only, no build required)", "Microsoft SAST-Scanner mit starker .NET-/ASP.NET-Abdeckung (nur Source-Repos, kein Build nötig)")}</td>
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
                <td>{t("Layer analysis", "Schichtanalyse")}</td>
                <td>{t("Docker image layer efficiency analysis for container images only", "Docker-Image-Schichtanalyse nur für Container-Images")}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <p className="info-note">
          {t(
            "If no scanners are specified, the defaults (trivy, grype, syft) are used.",
            "Wenn keine Scanner angegeben werden, werden die Standards (trivy, grype, syft) verwendet."
          )}
        </p>
      </Section>
    </div>
  );
};
