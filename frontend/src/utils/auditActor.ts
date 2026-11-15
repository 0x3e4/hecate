// Who an audit entry names. The backend stamps `metadata.actor` on every entry
// written during a request (see backend/app/core/auth_context.py, AuthContext.actor);
// MCP entries carry `metadata.identity` instead.

type Translate = (english: string, german: string) => string;

export interface AuditActorView {
  /** Short text for the table cell. */
  label: string;
  /** Longer text for the tooltip (e-mail, credential), if any. */
  title?: string;
  /** "user" for a person, "credential" for a shared secret, "none" otherwise. */
  kind: "user" | "credential" | "none";
}

const credentialLabel = (type: string, t: Translate): string | null => {
  switch (type) {
    case "system_password":
      return t("System password", "System-Passwort");
    case "target_password":
      return t("Target password", "Ziel-Passwort");
    case "api_token":
      return t("API token", "API-Token");
    case "sca_api_key":
      return t("SCA API key", "SCA-API-Key");
    case "ai_password":
      return t("AI password", "AI-Passwort");
    case "session":
      return t("Session", "Sitzung");
    default:
      return null;
  }
};

const roleLabel = (role: string, t: Translate): string => {
  switch (role) {
    case "admin":
      return "Admin";
    case "editor":
      return "Editor";
    case "viewer":
      return t("Viewer", "Leser");
    default:
      return role;
  }
};

const str = (value: unknown): string | null => (typeof value === "string" && value.trim() ? value.trim() : null);

export const describeAuditActor = (
  metadata: Record<string, unknown> | null | undefined,
  t: Translate,
): AuditActorView | null => {
  const meta = metadata ?? {};
  const actor = meta.actor;
  if (actor && typeof actor === "object") {
    const a = actor as Record<string, unknown>;
    const type = str(a.type) ?? "";
    if (type === "user") {
      const name = str(a.name) ?? str(a.email) ?? t("Unknown user", "Unbekannter Benutzer");
      const role = str(a.role);
      const via = str(a.via);
      const viaLabel = via ? credentialLabel(via, t) : null;
      const titleParts = [str(a.email), viaLabel ? t(`via ${viaLabel}`, `über ${viaLabel}`) : null].filter(Boolean);
      return {
        label: role ? `${name} (${roleLabel(role, t)})` : name,
        title: titleParts.length ? titleParts.join(" · ") : undefined,
        kind: "user",
      };
    }
    if (type === "session_refused") {
      // A write with someone's session cookie but without Hecate's request header:
      // refused, and not signed in. Possibly a forged cross-site request.
      const name = str(a.name) ?? str(a.email) ?? t("Unknown user", "Unbekannter Benutzer");
      return {
        label: t(`${name} (session refused)`, `${name} (Sitzung abgelehnt)`),
        title: [
          str(a.email),
          t("Cross-site request: the session was not accepted", "Cross-Site-Anfrage: Sitzung nicht akzeptiert"),
        ]
          .filter(Boolean)
          .join(" · "),
        kind: "none",
      };
    }
    if (type === "anonymous") {
      return { label: t("Anonymous", "Anonym"), kind: "none" };
    }
    const base = credentialLabel(type, t) ?? str(a.label) ?? type;
    if (type === "target_password" && str(a.target)) {
      return { label: base, title: str(a.target) ?? undefined, kind: "credential" };
    }
    if (type === "api_token" && str(a.name)) {
      return { label: `${base} ${str(a.name)}`, kind: "credential" };
    }
    return { label: base, kind: "credential" };
  }
  const identity = str(meta.identity);
  if (identity) {
    return { label: identity, title: str(meta.email) ?? undefined, kind: "user" };
  }
  return null;
};
