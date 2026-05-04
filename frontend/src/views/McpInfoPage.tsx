import { useEffect } from "react";
import { useI18n } from "../i18n/context";

export const McpInfoPage = () => {
  const { t } = useI18n();
  const domain = globalThis.location.hostname;
  const mcpUrl = `${globalThis.location.origin}/mcp`;

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
            30 Tools
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
          <li>{t("Write tools (trigger_scan, trigger_sync, and all save_*_ai_analysis tools) require the caller's source IP to be in ", "Schreib-Tools (trigger_scan, trigger_sync und alle save_*_ai_analysis Tools) erfordern, dass die Quell-IP in ")}<code>MCP_WRITE_IP_SAFELIST</code>{t(" (CSV of IPs or CIDR blocks) — only then is the mcp:write scope granted and re-validated at request time.", " (CSV von IPs oder CIDR-Blöcken) enthalten ist — nur dann wird der mcp:write Scope erteilt und zur Aufrufzeit erneut geprüft.")}</li>
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

      {/* Local: Claude Code CLI without OAuth */}
      <section className="card" style={{ borderLeft: "3px solid #ffd43b" }}>
        <h2>{t("Local setup: Claude Code CLI (no OAuth)", "Lokales Setup: Claude Code CLI (ohne OAuth)")}</h2>
        <p className="muted">
          {t(
            "For a single-user local Hecate (no public exposure), you can skip the IdP entirely. Hecate ships with a dev-mode bypass that stamps every request with a synthetic ",
            "Für eine lokale Single-User-Hecate-Instanz (nicht öffentlich erreichbar) kann der IdP komplett übersprungen werden. Hecate hat einen Dev-Mode-Bypass, der jeden Request mit einer synthetischen "
          )}
          <code>local-dev</code>
          {t(
            " identity carrying both mcp:read and mcp:write scopes. Every bypassed request still shows up in the audit log as a WARNING.",
            "-Identität mit beiden Scopes (mcp:read + mcp:write) versieht. Jeder bypasste Request erscheint weiterhin im Audit-Log als WARNING."
          )}
        </p>

        <h3 style={{ marginTop: "1rem", fontSize: "1rem" }}>{t("1. Enable dev mode on the backend", "1. Dev-Mode im Backend aktivieren")}</h3>
        <p style={{ marginTop: "0.5rem", fontSize: "0.9rem" }}>
          {t("In your ", "In ")}<code>.env</code>{t(" (or compose env block), set:", " (oder im Compose-Env-Block):")}
        </p>
        <pre style={{ marginTop: "0.5rem" }}><code>{`MCP_ENABLED=true
MCP_AUTH_DISABLED=true`}</code></pre>
        <p className="muted" style={{ marginTop: "0.5rem", fontSize: "0.85rem" }}>
          {t(
            "Restart the backend container. With MCP_AUTH_DISABLED=true, the OAuth env vars (MCP_OAUTH_PROVIDER / CLIENT_ID / CLIENT_SECRET) are not required.",
            "Backend-Container neu starten. Mit MCP_AUTH_DISABLED=true sind die OAuth-Env-Variablen (MCP_OAUTH_PROVIDER / CLIENT_ID / CLIENT_SECRET) nicht erforderlich."
          )}
        </p>

        <h3 style={{ marginTop: "1.25rem", fontSize: "1rem" }}>{t("2. Register the server with Claude Code", "2. Server in Claude Code registrieren")}</h3>
        <pre style={{ marginTop: "0.5rem" }}><code>{`claude mcp add --transport http hecate ${mcpUrl}`}</code></pre>
        <p className="muted" style={{ marginTop: "0.5rem", fontSize: "0.85rem" }}>
          {t(
            "Default scope is local (this project only). Use --scope user to make Hecate available across every project, or --scope project to commit a shared .mcp.json.",
            "Standard-Scope ist local (nur dieses Projekt). Mit --scope user wird Hecate in allen Projekten verfügbar; --scope project schreibt eine geteilte .mcp.json ins Repo."
          )}
        </p>

        <h3 style={{ marginTop: "1.25rem", fontSize: "1rem" }}>{t("3. Verify", "3. Überprüfen")}</h3>
        <pre style={{ marginTop: "0.5rem" }}><code>{`claude mcp list
claude mcp get hecate`}</code></pre>
        <p className="muted" style={{ marginTop: "0.5rem", fontSize: "0.85rem" }}>
          {t("Inside a Claude Code session, the slash command ", "Innerhalb einer Claude-Code-Sitzung zeigt der Slash-Befehl ")}
          <code>/mcp</code>
          {t(" shows live connection status and the list of registered tools.", " den Verbindungsstatus und die registrierten Tools live an.")}
        </p>

        <h3 style={{ marginTop: "1.25rem", fontSize: "1rem", color: "#ffd43b" }}>
          {t("⚠ Security notes", "⚠ Sicherheitshinweise")}
        </h3>
        <ul style={{ paddingLeft: "1.5rem", lineHeight: 1.7, fontSize: "0.9rem" }}>
          <li>{t("Never enable MCP_AUTH_DISABLED on a publicly reachable instance — every caller gets full read+write access.", "MCP_AUTH_DISABLED niemals auf einer öffentlich erreichbaren Instanz aktivieren — jeder Aufrufer erhält Voll-Zugriff (Read+Write).")}</li>
          <li>{t("Bind the backend to localhost (or a private network) when running in this mode. There is no IP gate built into the bypass.", "Backend in diesem Modus an localhost (oder ein privates Netz) binden. Der Bypass selbst hat kein IP-Gate.")}</li>
          <li>{t("Tool invocations are still recorded with identity ", "Tool-Aufrufe werden weiterhin mit Identität ")}<code>local-dev</code>{t(" in the audit log so you can see which tools were exercised.", " im Audit-Log protokolliert, sodass nachvollziehbar bleibt, welche Tools aufgerufen wurden.")}</li>
        </ul>
      </section>

      {/* AI analysis via your assistant */}
      <section className="card">
        <h2>{t("AI analysis via your assistant", "KI-Analyse über deinen Assistenten")}</h2>
        <p className="muted">
          {t(
            "Ask your assistant to analyze a vulnerability or scan — it uses Hecate's predefined prompts and its own reasoning, then writes the result back to Hecate. The analysis is stored on the vulnerability or scan document with an attribution tag like ",
            "Bitte deinen Assistenten, eine Schwachstelle oder einen Scan zu analysieren — er verwendet die vordefinierten Prompts von Hecate und sein eigenes Reasoning und schreibt das Ergebnis anschließend zurück. Die Analyse wird am Schwachstellen- oder Scan-Dokument mit einer Attribution wie "
          )}
          <code>Claude - MCP</code>
          {t(" so you can see later who produced it.", " gespeichert, damit später nachvollziehbar ist, von wem sie stammt.")}
        </p>
        <h3 style={{ marginTop: "1rem", fontSize: "1rem" }}>{t("Tool pairs", "Tool-Paare")}</h3>
        <ul style={{ paddingLeft: "1.5rem", lineHeight: 1.7, fontSize: "0.9rem" }}>
          <li><code>prepare_vulnerability_ai_analysis</code> → <code>save_vulnerability_ai_analysis</code> — {t("single CVE/GHSA/EUVD", "einzelne CVE/GHSA/EUVD")}</li>
          <li><code>prepare_vulnerabilities_ai_batch_analysis</code> → <code>save_vulnerabilities_ai_batch_analysis</code> — {t("up to 10 vulnerabilities combined", "bis zu 10 Schwachstellen kombiniert")}</li>
          <li><code>prepare_scan_ai_analysis</code> → <code>save_scan_ai_analysis</code> — {t("SCA scan risk triage", "SCA-Scan-Risiko-Triage")}</li>
        </ul>
        <p className="muted" style={{ marginTop: "0.75rem", fontSize: "0.85rem" }}>
          {t(
            "Saving results requires write scope (source IP must be in MCP_WRITE_IP_SAFELIST).",
            "Das Speichern der Ergebnisse erfordert Schreibzugriff (Quell-IP muss in MCP_WRITE_IP_SAFELIST enthalten sein)."
          )}
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
            <tr><td><code>get_scan_findings</code></td><td>{t("Query consolidated SCA findings across all targets (latest scan per target)", "Konsolidierte SCA-Findings über alle Targets abfragen (neuester Scan pro Target)")}</td></tr>
            <tr><td><code>get_scan_findings_by_scan</code></td><td>{t("Findings of a single scan, optionally filtered by package_type (library, sast-finding, secret-finding, malicious-indicator, compliance-check)", "Findings eines einzelnen Scans, optional gefiltert nach package_type (library, sast-finding, secret-finding, malicious-indicator, compliance-check)")}</td></tr>
            <tr><td><code>get_security_alerts</code></td><td>{t("Malicious-indicator findings (Hecate malware rules + MAL-* hits) — the Security Alerts tab data", "Malicious-Indicator-Findings (Hecate Malware-Regeln + MAL-*-Treffer) — die Daten des Security-Alerts-Tabs")}</td></tr>
            <tr><td><code>get_scan_sbom</code></td><td>{t("SBOM components for a single scan (deduped by name+version)", "SBOM-Komponenten eines einzelnen Scans (dedupliziert nach Name+Version)")}</td></tr>
            <tr><td><code>get_sbom_components</code></td><td>{t("Consolidated SBOM components across the latest scan of each target", "Konsolidierte SBOM-Komponenten über den neuesten Scan jedes Targets")}</td></tr>
            <tr><td><code>get_sbom_facets</code></td><td>{t("Ecosystem / license / type facet counts across SBOMs", "Ökosystem-/Lizenz-/Typ-Facet-Zählungen über SBOMs")}</td></tr>
            <tr><td><code>get_target_scan_history</code></td><td>{t("Historical completed scans for a target with severity summaries (timeline view)", "Historische abgeschlossene Scans für ein Target mit Severity-Summaries (Timeline-Ansicht)")}</td></tr>
            <tr><td><code>compare_scans</code></td><td>{t("Diff two scans: added / removed / changed / unchanged findings", "Zwei Scans diffen: hinzugefügte / entfernte / geänderte / unveränderte Findings")}</td></tr>
            <tr><td><code>get_layer_analysis</code></td><td>{t("Dive container-image layer analysis (per-layer command, size, digest)", "Dive Container-Image-Schichtanalyse (pro Layer Command, Size, Digest)")}</td></tr>
            <tr><td><code>list_scan_targets</code></td><td>{t("List registered scan targets — used to discover target_ids for other tools", "Registrierte Scan-Targets auflisten — zum Auffinden von target_ids für andere Tools")}</td></tr>
            <tr><td><code>list_target_groups</code></td><td>{t("List application groups with rolled-up severity totals", "Anwendungs-Gruppen mit aufsummierten Severity-Totals auflisten")}</td></tr>
            <tr><td><code>list_scans</code></td><td>{t("List recent scans (newest first), optionally filtered by target or status", "Aktuelle Scans auflisten (neueste zuerst), optional gefiltert nach Target oder Status")}</td></tr>
            <tr><td><code>find_findings_by_cve</code></td><td>{t("Find scan findings tied to a specific CVE/GHSA/OSV ID across all scans", "Scan-Findings zu einer bestimmten CVE/GHSA/OSV-ID über alle Scans finden")}</td></tr>
            <tr><td><code>trigger_scan</code></td><td>{t("Submit an SCA scan (write scope: source IP must be in MCP_WRITE_IP_SAFELIST)", "SCA-Scan starten (Schreib-Scope: Quell-IP muss in MCP_WRITE_IP_SAFELIST sein)")}</td></tr>
            <tr><td><code>trigger_sync</code></td><td>{t("Trigger data sync from upstream source (write scope: source IP must be in MCP_WRITE_IP_SAFELIST)", "Daten-Sync von Upstream-Quelle auslösen (Schreib-Scope: Quell-IP muss in MCP_WRITE_IP_SAFELIST sein)")}</td></tr>
            <tr><td><code>get_sca_scan</code></td><td>{t("Look up SCA scans by scan_id, target name, or group", "SCA-Scans per scan_id, Target-Name oder Gruppe abrufen")}</td></tr>
            <tr><td><code>prepare_vulnerability_ai_analysis</code></td><td>{t("Return the prompt + context for analyzing a single CVE", "Liefert Prompt + Kontext zur Analyse einer einzelnen CVE")}</td></tr>
            <tr><td><code>save_vulnerability_ai_analysis</code></td><td>{t("Save an assistant-generated analysis onto the vulnerability (write scope)", "Speichert eine vom Assistenten erzeugte Analyse an der Schwachstelle (Schreib-Scope)")}</td></tr>
            <tr><td><code>prepare_vulnerabilities_ai_batch_analysis</code></td><td>{t("Return the prompt + context for analyzing up to 10 vulnerabilities together", "Liefert Prompt + Kontext für die gemeinsame Analyse von bis zu 10 Schwachstellen")}</td></tr>
            <tr><td><code>save_vulnerabilities_ai_batch_analysis</code></td><td>{t("Save an assistant-generated batch analysis (write scope)", "Speichert eine vom Assistenten erzeugte Batch-Analyse (Schreib-Scope)")}</td></tr>
            <tr><td><code>prepare_scan_ai_analysis</code></td><td>{t("Return the prompt + context for triaging an SCA scan", "Liefert Prompt + Kontext zur Triage eines SCA-Scans")}</td></tr>
            <tr><td><code>save_scan_ai_analysis</code></td><td>{t("Save an assistant-generated scan triage onto the scan (write scope)", "Speichert eine vom Assistenten erzeugte Scan-Triage am Scan (Schreib-Scope)")}</td></tr>
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
            { en: "Show me the latest SCA scan for target hecate-backend", de: "Zeig mir den neuesten SCA-Scan für das Target hecate-backend" },
            { en: "Summarize all scans in the group 'production'", de: "Fasse alle Scans der Gruppe 'production' zusammen" },
            { en: "List my registered scan targets and their auto-scan status", de: "Liste meine registrierten Scan-Targets samt Auto-Scan-Status auf" },
            { en: "Show me the scan history of target hecate-frontend over the last 30 days", de: "Zeige die Scan-History von Target hecate-frontend für die letzten 30 Tage" },
            { en: "Compare the two latest scans of target hecate-backend and highlight regressions", de: "Vergleiche die zwei neuesten Scans von Target hecate-backend und zeige Regressionen" },
            { en: "What malicious-package alerts came up across all my scans this week?", de: "Welche Malicious-Package-Alerts gab es diese Woche über alle Scans?" },
            { en: "List all SBOM components of scan abc123 that ship under GPL-3.0", de: "Liste alle SBOM-Komponenten von Scan abc123 auf, die unter GPL-3.0 stehen" },
            { en: "Show the ecosystem and license breakdown across all my latest scans", de: "Zeige Ökosystem- und Lizenz-Verteilung über alle neuesten Scans" },
            { en: "Which of my scanned images are affected by CVE-2024-1234?", de: "Welche meiner gescannten Images sind von CVE-2024-1234 betroffen?" },
            { en: "Show me the layer breakdown of my latest container image scan", de: "Zeig mir den Layer-Aufbau meines neuesten Container-Image-Scans" },
            { en: "List the SAST findings of scan abc123 (semgrep results only)", de: "Liste die SAST-Findings von Scan abc123 (nur Semgrep-Ergebnisse)" },
            { en: "Analyze CVE-2024-1234 with your own reasoning and save the result to Hecate", de: "Analysiere CVE-2024-1234 mit deinem eigenen Reasoning und speichere das Ergebnis in Hecate" },
            { en: "Triage the latest scan of target frontend and write the summary back to the scan", de: "Mache eine Triage des neuesten Scans von Target frontend und schreibe die Zusammenfassung zurück an den Scan" },
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
            <tr><td><code>MCP_PUBLIC_URL</code></td><td>—</td><td>{t("Pin the base URL advertised in OAuth metadata (resource/issuer/endpoints) and in the 401 WWW-Authenticate hint. Set this when the reverse proxy doesn't reliably forward Host / X-Forwarded-Host or when multiple hostnames point to the same backend. Example: ", "Pinnt die Basis-URL, die in OAuth-Metadaten (resource/issuer/endpoints) und im 401-WWW-Authenticate-Hint angegeben wird. Setzen, wenn der Reverse-Proxy Host / X-Forwarded-Host nicht zuverlässig weitergibt oder mehrere Hostnames auf dasselbe Backend zeigen. Beispiel: ")}<code>https://sec.example.org</code></td></tr>
            <tr><td><code>MCP_AUTH_DISABLED</code></td><td><code>false</code></td><td>{t("DEV ONLY: bypass OAuth completely and stamp every request with a synthetic local-dev identity carrying mcp:read + mcp:write. Logs every bypassed request as WARNING. Never enable on a publicly reachable instance.", "NUR DEV: bypasst OAuth komplett und versieht jeden Request mit einer synthetischen local-dev-Identität (mcp:read + mcp:write). Loggt jeden bypassten Request als WARNING. Niemals auf einer öffentlich erreichbaren Instanz aktivieren.")}</td></tr>
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
