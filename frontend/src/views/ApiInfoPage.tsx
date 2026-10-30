import "../screens/info.css";

import { useEffect } from "react";
import { LuExternalLink } from "react-icons/lu";

import { useI18n } from "../i18n/context";
import { PageHeader, Section } from "../ui/primitives";
import { InfoCodeBlock } from "./CiCdInfoPage";

export const ApiInfoPage = () => {
  const { t } = useI18n();
  const apiBase = import.meta.env.VITE_API_BASE_URL ?? "/api";
  const docsUrl = `${apiBase}/docs`;
  const redocUrl = `${apiBase}/redoc`;

  useEffect(() => {
    document.title = `API - Hecate`;
  }, []);

  return (
    <div className="page info-doc">
      <PageHeader
        title={t("API documentation", "API-Dokumentation")}
        description={
          <>
            {t("Hecate provides a REST API under ", "Hecate stellt eine REST-API unter ")}
            <code>/api/v1</code>
            {t(
              ". All endpoints accept and return JSON with camelCase field names.",
              " bereit. Alle Endpunkte akzeptieren und liefern JSON mit camelCase-Feldnamen."
            )}
          </>
        }
        actions={
          <>
            <a className="btn-primary" href={docsUrl} target="_blank" rel="noopener noreferrer">
              Swagger UI
              <LuExternalLink aria-hidden="true" />
            </a>
            <a className="btn-secondary" href={redocUrl} target="_blank" rel="noopener noreferrer">
              ReDoc
              <LuExternalLink aria-hidden="true" />
            </a>
          </>
        }
      />

      {/* Key Endpoints */}
      <Section title={t("Key endpoints", "Wichtige Endpunkte")} className="info-section">
        <div className="table-scroll">
          <table className="info-table">
            <thead>
              <tr>
                <th>{t("Method", "Methode")}</th>
                <th>{t("Endpoint", "Endpunkt")}</th>
                <th>{t("Description", "Beschreibung")}</th>
              </tr>
            </thead>
            <tbody>
              <tr><td><code>GET</code></td><td><code>/api/v1/status</code></td><td>{t("Health check and version info", "Health-Check und Versionsinformationen")}</td></tr>
              <tr><td><code>GET</code></td><td><code>/api/v1/vulnerabilities</code></td><td>{t("Search vulnerabilities (DQL, pagination, sorting)", "Schwachstellen suchen (DQL, Paginierung, Sortierung)")}</td></tr>
              <tr><td><code>GET</code></td><td><code>/api/v1/vulnerabilities/{"{id}"}</code></td><td>{t("Get vulnerability details", "Schwachstellen-Details abrufen")}</td></tr>
              <tr><td><code>POST</code></td><td><code>/api/v1/inventory/report</code></td><td>{t("Report deployed versions (CI/CD)", "Ausgerollte Versionen melden (CI/CD)")}</td></tr>
              <tr><td><code>GET</code></td><td><code>/api/v1/stats</code></td><td>{t("Aggregated statistics", "Aggregierte Statistiken")}</td></tr>
              <tr><td><code>POST</code></td><td><code>/api/v1/scans</code></td><td>{t("Submit a scan (CI/CD)", "Scan einreichen (CI/CD)")}</td></tr>
              <tr><td><code>GET</code></td><td><code>/api/v1/scans/{"{scanId}"}</code></td><td>{t("Get scan status and summary", "Scan-Status und Zusammenfassung abrufen")}</td></tr>
              <tr><td><code>GET</code></td><td><code>/api/v1/scans/{"{scanId}"}/findings</code></td><td>{t("List scan findings", "Scan-Findings auflisten")}</td></tr>
              <tr><td><code>GET</code></td><td><code>/api/v1/scans/{"{scanId}"}/sbom</code></td><td>{t("List SBOM components", "SBOM-Komponenten auflisten")}</td></tr>
              <tr><td><code>GET</code></td><td><code>/api/v1/scans/{"{scanId}"}/sbom/export</code></td><td>{t("Export SBOM (CycloneDX / SPDX)", "SBOM exportieren (CycloneDX / SPDX)")}</td></tr>
              <tr><td><code>GET</code></td><td><code>/api/v1/changelog</code></td><td>{t("Vulnerability changelog", "Schwachstellen-Changelog")}</td></tr>
              <tr><td><code>GET</code></td><td><code>/api/v1/audit</code></td><td>{t("Audit log", "Audit-Log")}</td></tr>
            </tbody>
          </table>
        </div>
      </Section>

      {/* Authentication */}
      <Section title={t("Authentication", "Authentifizierung")} className="info-section">
        <p>
          {t(
            "Pipelines authenticate with an API token from System, Access Control, sent via the ",
            "Pipelines authentifizieren sich mit einem API-Token aus System, Zugriffskontrolle, im "
          )}
          <code>X-API-Key</code>
          {t(
            " header. The scope scan:submit opens scan submission, inventory:report the version report. Scan submission also accepts the ",
            "-Header. Der Scope scan:submit öffnet die Scan-Einreichung, inventory:report die Versionsmeldung. Die Scan-Einreichung akzeptiert auch die Umgebungsvariable "
          )}
          <code>SCA_API_KEY</code>
          {t(" environment variable.", ".")}
        </p>
        <InfoCodeBlock code={`curl -X POST /api/v1/scans \\
  -H "X-API-Key: your-secret-key" \\
  -H "Content-Type: application/json" \\
  -d '{ "target": "nginx:latest", "type": "container_image" }'`} />
        <p className="info-note">
          {t(
            "Reads are not authenticated. Writes need the X-System-Password header when SYSTEM_PASSWORD is set; a protected scan target also accepts X-Target-Password, and AI actions X-AI-Analysis-Password. This is a shared-secret gate, not user authentication: use TLS and network-level access controls (VPN, firewall) to restrict access to your Hecate instance.",
            "Lesezugriffe sind nicht authentifiziert. Schreibzugriffe brauchen den Header X-System-Password, wenn SYSTEM_PASSWORD gesetzt ist; ein geschütztes Scan-Target akzeptiert auch X-Target-Password, KI-Aktionen X-AI-Analysis-Password. Das ist ein Shared-Secret-Schutz, keine Benutzer-Authentifizierung: Verwenden Sie TLS und netzwerkbasierte Zugriffskontrollen (VPN, Firewall), um den Zugang zu Ihrer Hecate-Instanz einzuschränken."
          )}
        </p>
      </Section>

      {/* Response Format */}
      <Section title={t("Response format", "Antwortformat")} className="info-section">
        <p>
          {t(
            "Paginated endpoints return a standard envelope with items, total count, and pagination metadata:",
            "Paginierte Endpunkte liefern ein Standard-Format mit Einträgen, Gesamtanzahl und Paginierungs-Metadaten:"
          )}
        </p>
        <InfoCodeBlock code={`{
  "items": [ ... ],
  "total": 1542,
  "limit": 50,
  "offset": 0
}`} />
        <p className="info-note">
          {t(
            "All field names use camelCase on the wire (e.g. ",
            "Alle Feldnamen verwenden camelCase auf der Leitung (z. B. "
          )}
          <code>scanId</code>, <code>commitSha</code>, <code>pipelineUrl</code>).
        </p>
      </Section>
    </div>
  );
};
