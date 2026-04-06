import { useEffect } from "react";
import { useI18n } from "../i18n/context";

export const McpInfoPage = () => {
  const { t } = useI18n();
  const domain = import.meta.env.VITE_DOMAIN ?? window.location.hostname;
  const mcpUrl = `https://${domain}/mcp`;

  useEffect(() => {
    document.title = "Hecate Cyber Defense - MCP";
  }, []);

  return (
    <div className="page">
      {/* What is MCP */}
      <section className="card">
        <h2>{t("MCP Server", "MCP Server")}</h2>
        <p className="muted">
          {t(
            "Hecate provides a Model Context Protocol (MCP) server that allows AI assistants like Claude, Cursor, or VS Code Copilot to query the vulnerability database using natural language.",
            "Hecate stellt einen Model Context Protocol (MCP) Server bereit, der es KI-Assistenten wie Claude, Cursor oder VS Code Copilot ermöglicht, die Schwachstellen-Datenbank in natürlicher Sprache abzufragen."
          )}
        </p>
        <div style={{ marginTop: "1rem", display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
          <span style={{ ...badgeStyle, background: "rgba(255,212,59,0.1)", color: "#ffd43b", border: "1px solid rgba(255,212,59,0.2)" }}>
            11 Tools
          </span>
          <span style={{ ...badgeStyle, background: "rgba(139,250,167,0.1)", color: "#8bfaa7", border: "1px solid rgba(139,250,167,0.2)" }}>
            OAuth 2.0 + PKCE
          </span>
          <span style={{ ...badgeStyle, background: "rgba(167,139,250,0.1)", color: "#a78bfa", border: "1px solid rgba(167,139,250,0.2)" }}>
            {t("Rate Limited", "Rate-Limitiert")}
          </span>
          <span style={{ ...badgeStyle, background: "rgba(96,165,250,0.1)", color: "#60a5fa", border: "1px solid rgba(96,165,250,0.2)" }}>
            {t("Audit Logged", "Audit-Protokolliert")}
          </span>
        </div>
      </section>

      {/* Connection URL */}
      <section className="card">
        <h2>{t("Server URL", "Server-URL")}</h2>
        <pre><code>{mcpUrl}</code></pre>
        <p className="muted" style={{ marginTop: "0.5rem", fontSize: "0.85rem" }}>
          {t(
            "This URL is used to connect your AI client to Hecate's MCP server.",
            "Diese URL wird verwendet, um Ihren KI-Client mit dem MCP-Server von Hecate zu verbinden."
          )}
        </p>
      </section>

      {/* Claude Desktop Setup */}
      <section className="card">
        <h2>{t("Setup: Claude Desktop", "Einrichtung: Claude Desktop")}</h2>
        <p>
          {t(
            "Claude Desktop connects natively via OAuth. No API key needs to be pasted into the config file.",
            "Claude Desktop verbindet sich nativ über OAuth. Es muss kein API-Key in die Konfigurationsdatei eingefügt werden."
          )}
        </p>
        <h3 style={{ marginTop: "1rem", fontSize: "1rem" }}>{t("Steps", "Schritte")}</h3>
        <ol style={{ paddingLeft: "1.5rem", lineHeight: 1.8 }}>
          <li>{t("Open Claude Desktop Settings", "Claude Desktop Einstellungen öffnen")}</li>
          <li>{t('Go to "Connectors" and click "Add custom connector"', '"Konnektoren" öffnen und "Benutzerdefinierten Connector hinzufügen" klicken')}</li>
          <li>
            {t("Enter name ", "Name eingeben: ")}<code>Hecate</code>{t(" and URL ", " und URL ")}<code>{mcpUrl}</code>
          </li>
          <li>{t("Leave OAuth Client ID and Secret empty", "OAuth Client ID und Secret leer lassen")}</li>
          <li>{t('Click "Add"', '"Hinzufügen" klicken')}</li>
          <li>{t("A browser window opens — enter your MCP API key", "Ein Browserfenster öffnet sich — MCP API Key eingeben")}</li>
          <li>{t("Done! Claude can now query Hecate.", "Fertig! Claude kann jetzt Hecate abfragen.")}</li>
        </ol>
      </section>

      {/* Alternative: mcp-remote */}
      <section className="card">
        <h2>{t("Alternative: Direct API Key", "Alternative: Direkter API Key")}</h2>
        <p className="muted">
          {t(
            "If OAuth doesn't work in your client, you can use mcp-remote as a bridge. Add this to your claude_desktop_config.json:",
            "Falls OAuth in Ihrem Client nicht funktioniert, können Sie mcp-remote als Brücke verwenden. Fügen Sie dies in Ihre claude_desktop_config.json ein:"
          )}
        </p>
        <pre style={{ marginTop: "0.75rem" }}><code>{`{
  "mcpServers": {
    "hecate": {
      "command": "npx",
      "args": [
        "-y", "mcp-remote",
        "${mcpUrl}",
        "--header",
        "Authorization: Bearer YOUR_MCP_API_KEY"
      ]
    }
  }
}`}</code></pre>
        <p className="muted" style={{ marginTop: "0.5rem", fontSize: "0.85rem" }}>
          {t("Requires Node.js installed on your machine.", "Erfordert Node.js auf Ihrem Rechner.")}
        </p>
      </section>

      {/* Available Tools */}
      <section className="card">
        <h2>{t("Available Tools", "Verfügbare Tools")}</h2>
        <p className="muted" style={{ marginBottom: "1rem" }}>
          {t(
            "The AI assistant automatically picks the right tool based on your question. You don't need to call them manually.",
            "Der KI-Assistent wählt automatisch das richtige Tool basierend auf Ihrer Frage. Sie müssen diese nicht manuell aufrufen."
          )}
        </p>
        <table>
          <thead>
            <tr>
              <th>Tool</th>
              <th>{t("Description", "Beschreibung")}</th>
            </tr>
          </thead>
          <tbody>
            <tr><td><code>search_vulnerabilities</code></td><td>{t("Search by keyword, vendor, product, version, severity", "Suche nach Keyword, Hersteller, Produkt, Version, Schweregrad")}</td></tr>
            <tr><td><code>get_vulnerability</code></td><td>{t("Full details for a CVE/GHSA/OSV ID", "Vollständige Details zu einer CVE/GHSA/OSV-ID")}</td></tr>
            <tr><td><code>search_cpe</code></td><td>{t("Search CPE entries (standardized software IDs)", "CPE-Einträge suchen (standardisierte Software-IDs)")}</td></tr>
            <tr><td><code>search_vendors</code></td><td>{t("Search vendor catalog", "Hersteller-Katalog durchsuchen")}</td></tr>
            <tr><td><code>search_products</code></td><td>{t("Search product catalog", "Produkt-Katalog durchsuchen")}</td></tr>
            <tr><td><code>get_vulnerability_stats</code></td><td>{t("Database statistics and severity distribution", "Datenbank-Statistiken und Schweregrad-Verteilung")}</td></tr>
            <tr><td><code>get_cwe</code></td><td>{t("CWE weakness details", "CWE-Schwachstellentyp-Details")}</td></tr>
            <tr><td><code>get_capec</code></td><td>{t("CAPEC attack pattern details", "CAPEC-Angriffsmuster-Details")}</td></tr>
            <tr><td><code>get_scan_findings</code></td><td>{t("Query SCA scan findings", "SCA-Scan-Findings abfragen")}</td></tr>
            <tr><td><code>trigger_scan</code></td><td>{t("Submit an SCA scan (write key required)", "SCA-Scan starten (Schreib-Key erforderlich)")}</td></tr>
            <tr><td><code>trigger_sync</code></td><td>{t("Trigger data sync from upstream source (write key required)", "Daten-Sync von Upstream-Quelle auslösen (Schreib-Key erforderlich)")}</td></tr>
          </tbody>
        </table>
      </section>

      {/* Example Prompts */}
      <section className="card">
        <h2>{t("Example Prompts", "Beispiel-Prompts")}</h2>
        <p className="muted" style={{ marginBottom: "1rem" }}>
          {t(
            "Just ask in natural language — the AI decides which tools to use.",
            "Einfach in natürlicher Sprache fragen — die KI entscheidet, welche Tools verwendet werden."
          )}
        </p>
        <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
          {[
            { en: "I use OpenClaw version 2026.02.24 — am I affected by any vulnerabilities?", de: "Ich benutze OpenClaw Version 2026.02.24 — bin ich von Schwachstellen betroffen?" },
            { en: "Show me all critical Apache Tomcat vulnerabilities", de: "Zeig mir alle kritischen Apache Tomcat Schwachstellen" },
            { en: "What is CVE-2024-1234?", de: "Was ist CVE-2024-1234?" },
            { en: "Are there any actively exploited vulnerabilities right now?", de: "Gibt es gerade aktiv ausgenutzte Schwachstellen?" },
            { en: "Explain CWE-79 and its attack patterns", de: "Erkläre CWE-79 und die zugehörigen Angriffsmuster" },
            { en: "How many vulnerabilities are in the database?", de: "Wie viele Schwachstellen sind in der Datenbank?" },
            { en: "Search for log4j vulnerabilities with CRITICAL severity", de: "Suche nach log4j Schwachstellen mit Schweregrad CRITICAL" },
          ].map((prompt, i) => (
            <div key={i} style={{ padding: "0.6rem 1rem", background: "rgba(255,255,255,0.03)", borderRadius: "6px", border: "1px solid rgba(255,255,255,0.06)", fontSize: "0.9rem" }}>
              {t(prompt.en, prompt.de)}
            </div>
          ))}
        </div>
      </section>

      {/* Configuration */}
      <section className="card">
        <h2>{t("Configuration", "Konfiguration")}</h2>
        <table>
          <thead>
            <tr>
              <th>{t("Variable", "Variable")}</th>
              <th>{t("Default", "Standard")}</th>
              <th>{t("Description", "Beschreibung")}</th>
            </tr>
          </thead>
          <tbody>
            <tr><td><code>MCP_ENABLED</code></td><td><code>false</code></td><td>{t("Enable/disable the MCP server", "MCP-Server aktivieren/deaktivieren")}</td></tr>
            <tr><td><code>MCP_API_KEY</code></td><td>—</td><td>{t("API key for authentication (required)", "API-Key für Authentifizierung (erforderlich)")}</td></tr>
            <tr><td><code>MCP_WRITE_API_KEY</code></td><td>—</td><td>{t("Separate key for write operations (scan, sync)", "Separater Key für Schreiboperationen (Scan, Sync)")}</td></tr>
            <tr><td><code>MCP_RATE_LIMIT_PER_MINUTE</code></td><td><code>60</code></td><td>{t("Max requests per minute per client", "Max. Anfragen pro Minute pro Client")}</td></tr>
            <tr><td><code>MCP_MAX_RESULTS</code></td><td><code>50</code></td><td>{t("Max results per query", "Max. Ergebnisse pro Abfrage")}</td></tr>
            <tr><td><code>MCP_MAX_CONCURRENT_CONNECTIONS</code></td><td><code>20</code></td><td>{t("Max concurrent connections", "Max. gleichzeitige Verbindungen")}</td></tr>
          </tbody>
        </table>
      </section>
    </div>
  );
};

const badgeStyle: React.CSSProperties = {
  fontSize: "0.8rem",
  padding: "0.25rem 0.6rem",
  borderRadius: "4px",
  fontWeight: 500,
};
