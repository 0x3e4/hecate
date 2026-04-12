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

      {/* IdP Setup */}
      <section className="card">
        <h2>{t("Identity Provider Setup", "Identity Provider Einrichtung")}</h2>
        <p className="muted">
          {t(
            "Hecate delegates user authentication to an upstream identity provider (IdP). No shared API keys are used — every MCP session is tied to a real user identity. Pick one provider below and register an OAuth app with the callback URL shown.",
            "Hecate delegiert die Benutzer-Authentifizierung an einen Upstream Identity Provider (IdP). Es gibt keine gemeinsamen API-Keys — jede MCP-Sitzung ist an eine echte Benutzeridentität gebunden. Wählen Sie unten einen Provider und registrieren Sie eine OAuth-App mit der angezeigten Callback-URL."
          )}
        </p>
        <p style={{ marginTop: "0.75rem" }}>
          <strong>{t("Redirect / Callback URL", "Redirect / Callback URL")}:</strong>
        </p>
        <pre><code>{`https://${domain}/mcp/oauth/idp/callback`}</code></pre>

        <h3 style={{ marginTop: "1.25rem", fontSize: "1rem" }}>{t("Option A: GitHub OAuth App", "Option A: GitHub OAuth App")}</h3>
        <ol style={{ paddingLeft: "1.5rem", lineHeight: 1.7, fontSize: "0.9rem" }}>
          <li>{t("Go to ", "Öffnen Sie ")}<a href="https://github.com/settings/developers" target="_blank" rel="noopener noreferrer">github.com/settings/developers</a>{t(" → OAuth Apps → New OAuth App", " → OAuth Apps → New OAuth App")}</li>
          <li>{t("Application name: ", "Application name: ")}<code>Hecate</code>, {t("Homepage URL: ", "Homepage URL: ")}<code>{`https://${domain}`}</code></li>
          <li>{t("Authorization callback URL: ", "Authorization callback URL: ")}<code>{`https://${domain}/mcp/oauth/idp/callback`}</code></li>
          <li>{t("Click Register application, copy the Client ID, then Generate a new client secret and copy it", "Register application klicken, Client ID kopieren, dann Generate a new client secret klicken und kopieren")}</li>
          <li>{t("Set the env vars: ", "Env-Variablen setzen: ")}<code>MCP_OAUTH_PROVIDER=github</code>, <code>MCP_OAUTH_CLIENT_ID=...</code>, <code>MCP_OAUTH_CLIENT_SECRET=...</code></li>
        </ol>

        <h3 style={{ marginTop: "1.25rem", fontSize: "1rem" }}>{t("Option B: Microsoft Entra ID", "Option B: Microsoft Entra ID")}</h3>
        <ol style={{ paddingLeft: "1.5rem", lineHeight: 1.7, fontSize: "0.9rem" }}>
          <li>{t("Go to Entra admin center → App registrations → New registration", "Entra Admin Center → App-Registrierungen → Neue Registrierung")}</li>
          <li>{t("Supported account types: your choice. Redirect URI (Web): ", "Unterstützte Kontotypen: frei wählbar. Redirect-URI (Web): ")}<code>{`https://${domain}/mcp/oauth/idp/callback`}</code></li>
          <li>{t("Under Certificates & secrets → New client secret, copy the value", "Unter Zertifikate & Geheimnisse → Neues Clientgeheimnis, Wert kopieren")}</li>
          <li>{t("Set env vars: ", "Env-Variablen setzen: ")}<code>MCP_OAUTH_PROVIDER=microsoft</code>, <code>MCP_OAUTH_CLIENT_ID=...</code>, <code>MCP_OAUTH_CLIENT_SECRET=...</code>, <code>{`MCP_OAUTH_ISSUER=https://login.microsoftonline.com/<tenant>/v2.0`}</code></li>
        </ol>

        <h3 style={{ marginTop: "1.25rem", fontSize: "1rem" }}>{t("Option C: Generic OIDC", "Option C: Generisches OIDC")}</h3>
        <ol style={{ paddingLeft: "1.5rem", lineHeight: 1.7, fontSize: "0.9rem" }}>
          <li>{t("Any OIDC-compliant provider: Authentik, Keycloak, Auth0, Zitadel, Okta, Google Workspace, etc.", "Jeder OIDC-konforme Provider: Authentik, Keycloak, Auth0, Zitadel, Okta, Google Workspace usw.")}</li>
          <li>{t("Register a client / application with the redirect URI above and the openid email profile scopes", "Einen Client / eine Anwendung mit obiger Redirect-URI und den Scopes openid email profile registrieren")}</li>
          <li>{t("Set env vars: ", "Env-Variablen setzen: ")}<code>MCP_OAUTH_PROVIDER=oidc</code>, <code>MCP_OAUTH_CLIENT_ID=...</code>, <code>MCP_OAUTH_CLIENT_SECRET=...</code>, <code>MCP_OAUTH_ISSUER=https://your-idp/</code></li>
          <li>{t("Hecate fetches the discovery document at ", "Hecate lädt das Discovery-Dokument unter ")}<code>{"{issuer}/.well-known/openid-configuration"}</code>{t(" at startup.", " beim Start.")}</li>
        </ol>

        <h3 style={{ marginTop: "1.25rem", fontSize: "1rem" }}>{t("Read vs. write access", "Lese- vs. Schreibzugriff")}</h3>
        <ul style={{ paddingLeft: "1.5rem", lineHeight: 1.7, fontSize: "0.9rem" }}>
          <li>{t("Read tools (search, get_vulnerability, etc.) are available to anyone who successfully authenticates with the configured IdP.", "Lese-Tools (search, get_vulnerability usw.) stehen jedem zur Verfügung, der sich erfolgreich beim konfigurierten IdP authentifiziert.")}</li>
          <li>{t("Optionally narrow read access with ", "Optional kann der Lesezugriff über ")}<code>MCP_ALLOWED_USERS</code>{t(" (CSV of usernames/emails).", " (CSV von Benutzernamen/E-Mails) eingegrenzt werden.")}</li>
          <li>{t("Write tools (trigger_scan, trigger_sync) require the caller's source IP to be in ", "Schreib-Tools (trigger_scan, trigger_sync) erfordern, dass die Quell-IP in ")}<code>MCP_WRITE_IP_SAFELIST</code>{t(" (CSV of IPs or CIDR blocks) — only then is the mcp:write scope granted and re-validated at request time.", " (CSV von IPs oder CIDR-Blöcken) enthalten ist — nur dann wird der mcp:write Scope erteilt und zur Aufrufzeit erneut geprüft.")}</li>
          <li>{t("All OAuth events and tool invocations are recorded in the ", "Alle OAuth-Events und Tool-Aufrufe werden im ")}<a href="/audit">{t("audit log", "Audit-Log")}</a>{t(" with identity, email, source IP, and granted scope.", " mit Identität, E-Mail, Quell-IP und erteiltem Scope protokolliert.")}</li>
        </ul>
      </section>

      {/* Claude Desktop Setup */}
      <section className="card">
        <h2>{t("Setup: Claude Desktop", "Einrichtung: Claude Desktop")}</h2>
        <p className="muted">
          {t(
            "Claude Desktop uses the claude.ai connector backend to validate and register remote MCP servers. The first click will redirect you to sign in to your Anthropic account — that is normal.",
            "Claude Desktop nutzt das claude.ai Connector-Backend, um entfernte MCP-Server zu validieren und zu registrieren. Der erste Klick leitet Sie zur Anmeldung bei Ihrem Anthropic-Konto weiter — das ist normal."
          )}
        </p>
        <h3 style={{ marginTop: "1rem", fontSize: "1rem" }}>{t("Steps", "Schritte")}</h3>
        <ol style={{ paddingLeft: "1.5rem", lineHeight: 1.8 }}>
          <li>{t("Open Claude Desktop Settings → Connectors → Add custom connector", "Claude Desktop Einstellungen → Konnektoren → Benutzerdefinierten Connector hinzufügen")}</li>
          <li>
            {t("Enter name ", "Name eingeben: ")}<code>Hecate</code>{t(" and URL ", " und URL ")}<code>{mcpUrl}</code>
          </li>
          <li>{t("Leave the OAuth Client ID and Client Secret fields empty — Hecate registers itself via Dynamic Client Registration", "OAuth Client ID und Client Secret leer lassen — Hecate registriert sich selbst via Dynamic Client Registration")}</li>
          <li>{t('Click "Add"', '"Hinzufügen" klicken')}</li>
          <li>{t("A browser opens at claude.ai, then redirects to the Hecate-configured identity provider (GitHub / Microsoft / OIDC). Sign in with your account.", "Ein Browser öffnet sich bei claude.ai und leitet dann zum in Hecate konfigurierten Identity Provider weiter (GitHub / Microsoft / OIDC). Mit Ihrem Konto anmelden.")}</li>
          <li>{t("Done! Claude can now query Hecate.", "Fertig! Claude kann jetzt Hecate abfragen.")}</li>
        </ol>
      </section>

      {/* Alternative: mcp-remote */}
      <section className="card">
        <h2>{t("Alternative: mcp-remote bridge", "Alternative: mcp-remote Brücke")}</h2>
        <p className="muted">
          {t(
            "If your client doesn't speak OAuth natively, mcp-remote will run the OAuth flow itself and open a browser. Add this to your claude_desktop_config.json:",
            "Falls Ihr Client OAuth nicht nativ unterstützt, führt mcp-remote den OAuth-Flow selbst aus und öffnet einen Browser. Fügen Sie dies in Ihre claude_desktop_config.json ein:"
          )}
        </p>
        <pre style={{ marginTop: "0.75rem" }}><code>{`{
  "mcpServers": {
    "hecate": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "${mcpUrl}"]
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
            <tr><td><code>trigger_scan</code></td><td>{t("Submit an SCA scan (write scope: source IP must be in MCP_WRITE_IP_SAFELIST)", "SCA-Scan starten (Schreib-Scope: Quell-IP muss in MCP_WRITE_IP_SAFELIST sein)")}</td></tr>
            <tr><td><code>trigger_sync</code></td><td>{t("Trigger data sync from upstream source (write scope: source IP must be in MCP_WRITE_IP_SAFELIST)", "Daten-Sync von Upstream-Quelle auslösen (Schreib-Scope: Quell-IP muss in MCP_WRITE_IP_SAFELIST sein)")}</td></tr>
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
            <tr><td><code>MCP_OAUTH_PROVIDER</code></td><td>—</td><td>{t("Identity provider: github, microsoft, or oidc", "Identity Provider: github, microsoft oder oidc")}</td></tr>
            <tr><td><code>MCP_OAUTH_CLIENT_ID</code></td><td>—</td><td>{t("OAuth client ID issued by the IdP", "OAuth Client ID vom IdP")}</td></tr>
            <tr><td><code>MCP_OAUTH_CLIENT_SECRET</code></td><td>—</td><td>{t("OAuth client secret issued by the IdP", "OAuth Client Secret vom IdP")}</td></tr>
            <tr><td><code>MCP_OAUTH_ISSUER</code></td><td>—</td><td>{t("OIDC issuer URL (Microsoft tenant URL or OIDC discovery base)", "OIDC Issuer URL (Microsoft Tenant URL oder OIDC Discovery Basis)")}</td></tr>
            <tr><td><code>MCP_OAUTH_SCOPES</code></td><td>—</td><td>{t("Override the default IdP scopes (space-separated)", "Standard-IdP-Scopes überschreiben (durch Leerzeichen getrennt)")}</td></tr>
            <tr><td><code>MCP_WRITE_IP_SAFELIST</code></td><td>—</td><td>{t("CSV of IPs/CIDRs allowed to call trigger_scan and trigger_sync. Empty = no write access.", "CSV von IPs/CIDRs, die trigger_scan und trigger_sync aufrufen dürfen. Leer = kein Schreibzugriff.")}</td></tr>
            <tr><td><code>MCP_ALLOWED_USERS</code></td><td>—</td><td>{t("Optional CSV of allowed identities/emails. Empty = any IdP-authenticated user.", "Optionale CSV erlaubter Identitäten/E-Mails. Leer = jeder IdP-authentifizierte Benutzer.")}</td></tr>
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
