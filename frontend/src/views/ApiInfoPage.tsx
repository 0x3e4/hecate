import { useEffect } from "react";
import { useI18n } from "../i18n/context";

export const ApiInfoPage = () => {
  const { t } = useI18n();
  const apiBase = import.meta.env.VITE_API_BASE_URL ?? "/api";
  const docsUrl = `${apiBase}/docs`;
  const redocUrl = `${apiBase}/redoc`;

  useEffect(() => {
    document.title = `API – Hecate`;
  }, []);

  return (
    <div className="page api-info-page">
      <section className="card">
        <h2>{t("API Documentation", "API-Dokumentation")}</h2>
        <p className="muted">
          {t(
            "Hecate provides a REST API under /api/v1. All endpoints accept and return JSON with camelCase field names.",
            "Hecate stellt eine REST-API unter /api/v1 bereit. Alle Endpunkte akzeptieren und liefern JSON mit camelCase-Feldnamen."
          )}
        </p>
        <div style={{ display: "flex", gap: "0.5rem", marginTop: "0.75rem" }}>
          <a href={docsUrl} target="_blank" rel="noopener noreferrer"
            style={{ color: "#ffd43b", textDecoration: "none", fontSize: "0.8rem", padding: "0.25rem 0.6rem", borderRadius: "4px", background: "rgba(255,193,7,0.1)", border: "1px solid rgba(255,193,7,0.2)" }}>
            Swagger UI ↗
          </a>
          <a href={redocUrl} target="_blank" rel="noopener noreferrer"
            style={{ color: "#a78bfa", textDecoration: "none", fontSize: "0.8rem", padding: "0.25rem 0.6rem", borderRadius: "4px", background: "rgba(167,139,250,0.1)", border: "1px solid rgba(167,139,250,0.2)" }}>
            ReDoc ↗
          </a>
        </div>
      </section>

      {/* Key Endpoints */}
      <section className="card">
        <h2>{t("Key Endpoints", "Wichtige Endpunkte")}</h2>
        <table>
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
      </section>

      {/* Authentication */}
      <section className="card">
        <h2>{t("Authentication", "Authentifizierung")}</h2>
        <p>
          {t(
            "The scan submission endpoint requires an API key sent via the X-API-Key header. Configure the key on the backend with the SCA_API_KEY environment variable.",
            "Der Scan-Einreichungsendpunkt erfordert einen API-Schlüssel im X-API-Key-Header. Konfigurieren Sie den Schlüssel im Backend über die Umgebungsvariable SCA_API_KEY."
          )}
        </p>
        <pre><code>{`curl -X POST /api/v1/scans \\
  -H "X-API-Key: your-secret-key" \\
  -H "Content-Type: application/json" \\
  -d '{ "target": "nginx:latest", "type": "container_image" }'`}</code></pre>
        <p className="muted" style={{ marginTop: "0.5rem" }}>
          {t(
            "All other endpoints are currently unauthenticated. Use network-level access controls (VPN, firewall) to restrict access to your Hecate instance.",
            "Alle anderen Endpunkte sind derzeit nicht authentifiziert. Verwenden Sie netzwerkbasierte Zugriffskontrollen (VPN, Firewall), um den Zugang zu Ihrer Hecate-Instanz einzuschränken."
          )}
        </p>
      </section>

      {/* Response Format */}
      <section className="card">
        <h2>{t("Response Format", "Antwortformat")}</h2>
        <p>
          {t(
            "Paginated endpoints return a standard envelope with items, total count, and pagination metadata:",
            "Paginierte Endpunkte liefern ein Standard-Format mit Einträgen, Gesamtanzahl und Paginierungs-Metadaten:"
          )}
        </p>
        <pre><code>{`{
  "items": [ ... ],
  "total": 1542,
  "limit": 50,
  "offset": 0
}`}</code></pre>
        <p className="muted" style={{ marginTop: "0.5rem" }}>
          {t(
            "All field names use camelCase on the wire (e.g. scanId, commitSha, pipelineUrl).",
            "Alle Feldnamen verwenden camelCase auf der Leitung (z. B. scanId, commitSha, pipelineUrl)."
          )}
        </p>
      </section>
    </div>
  );
};
