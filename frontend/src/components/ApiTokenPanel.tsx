import { useEffect, useState } from "react";
import type { AxiosError } from "axios";
import { LuCheck, LuCopy } from "react-icons/lu";

import "../screens/api-tokens.css";
import "../screens/scan-target.css";

import { createApiToken, fetchApiTokens, revokeApiToken } from "../api/apiTokens";
import { useI18n } from "../i18n/context";
import type { ApiToken, ApiTokenCreated, ApiTokenScope } from "../types";
import { EmptyState, ErrorState, IconButton } from "../ui/primitives";
import { formatDateOnly, formatDateTime } from "../utils/dateFormat";
import { SkeletonBlock } from "./Skeleton";
import { useToastContext } from "./ToastProvider";

const DEFAULT_EXPIRY = "365";

/**
 * Admin manager for API tokens (System, Access Control). A token carries scopes
 * and opens only the routes of those scopes, so a pipeline never needs the admin
 * password, and one leaked token can be revoked without touching the others.
 */
export const ApiTokenPanel = () => {
  const { t } = useI18n();
  const { showToast } = useToastContext();
  const [tokens, setTokens] = useState<ApiToken[]>([]);
  const [status, setStatus] = useState<"loading" | "ready" | "unavailable" | "error">("loading");
  const [name, setName] = useState("");
  const [scopes, setScopes] = useState<ApiTokenScope[]>(["scan:submit"]);
  const [expiry, setExpiry] = useState(DEFAULT_EXPIRY);
  const [created, setCreated] = useState<ApiTokenCreated | null>(null);
  const [copied, setCopied] = useState(false);
  const [creating, setCreating] = useState(false);
  const [confirmingId, setConfirmingId] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  useEffect(() => {
    fetchApiTokens()
      .then((items) => {
        setTokens(items);
        setStatus("ready");
      })
      .catch((error: AxiosError) => {
        setStatus(error.response?.status === 403 ? "unavailable" : "error");
      });
  }, []);

  useEffect(() => {
    if (!copied) return;
    const timer = setTimeout(() => setCopied(false), 1500);
    return () => clearTimeout(timer);
  }, [copied]);

  const scopeOptions: { value: ApiTokenScope; label: string }[] = [
    { value: "scan:submit", label: t("Submit scans", "Scans einreichen") },
    { value: "inventory:report", label: t("Report deployed versions", "Ausgerollte Versionen melden") },
  ];

  const toggleScope = (scope: ApiTokenScope) => {
    setScopes((current) => (current.includes(scope) ? current.filter((s) => s !== scope) : [...current, scope]));
  };

  const handleCreate = async () => {
    setCreating(true);
    try {
      const token = await createApiToken({
        name: name.trim(),
        scopes,
        expiresInDays: expiry ? Number(expiry) : null,
      });
      setTokens((current) => [token, ...current]);
      setCreated(token);
      setName("");
      setScopes(["scan:submit"]);
      setExpiry(DEFAULT_EXPIRY);
    } catch {
      showToast(t("Failed to create the token.", "Token konnte nicht erstellt werden."), "error");
    } finally {
      setCreating(false);
    }
  };

  const handleRevoke = async (token: ApiToken) => {
    setBusyId(token.id);
    try {
      await revokeApiToken(token.id);
      setTokens((current) => current.filter((item) => item.id !== token.id));
      if (created?.id === token.id) setCreated(null);
      showToast(t(`Token "${token.name}" revoked.`, `Token „${token.name}“ widerrufen.`), "success");
    } catch {
      showToast(t("Failed to revoke the token.", "Token konnte nicht widerrufen werden."), "error");
    } finally {
      setBusyId(null);
      setConfirmingId(null);
    }
  };

  const handleCopy = async (value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
    } catch {
      showToast(t("Failed to copy to clipboard", "Fehler beim Kopieren in die Zwischenablage"), "error");
    }
  };

  return (
    <div className="scan-target-access api-tokens">
      <h2>{t("API tokens", "API-Tokens")}</h2>
      <p className="scan-target-access-intro">
        {t(
          "A token goes to one pipeline or tool and opens only what its scopes allow. Send it as the X-API-Key header. Revoking one leaves the others working.",
          "Ein Token gehört zu einer Pipeline oder einem Werkzeug und öffnet nur, was seine Scopes erlauben. Es wird im Header X-API-Key gesendet. Wird eines widerrufen, laufen die anderen weiter."
        )}
      </p>

      {status === "loading" && (
        <div className="scan-target-access-skeleton" aria-busy="true">
          {[0, 1].map((i) => (
            <SkeletonBlock key={i} height={36} />
          ))}
        </div>
      )}

      {status === "unavailable" && (
        <EmptyState title={t("API tokens need a system password.", "API-Tokens brauchen ein Systempasswort.")}>
          {t(
            "Without SYSTEM_PASSWORD anyone could create a token. Set it on the backend, then restart.",
            "Ohne SYSTEM_PASSWORD könnte jeder ein Token erstellen. Setze es im Backend und starte neu."
          )}
        </EmptyState>
      )}

      {status === "error" && (
        <ErrorState title={t("Failed to load API tokens.", "API-Tokens konnten nicht geladen werden.")}>
          {t("Unlock with the system password, then reload the page.", "Entsperre mit dem Systempasswort und lade die Seite neu.")}
        </ErrorState>
      )}

      {status === "ready" && (
        <>
          <form
            className="api-tokens-form"
            onSubmit={(event) => {
              event.preventDefault();
              void handleCreate();
            }}
          >
            <label className="api-tokens-field">
              <span>{t("Name", "Name")}</span>
              <input
                className="system-input"
                value={name}
                maxLength={64}
                onChange={(event) => setName(event.target.value)}
                placeholder={t("deploy-prod", "deploy-prod")}
              />
            </label>
            <fieldset className="api-tokens-scopes">
              <legend>{t("Scopes", "Scopes")}</legend>
              {scopeOptions.map((option) => (
                <label key={option.value} className="api-tokens-scope">
                  <input
                    type="checkbox"
                    checked={scopes.includes(option.value)}
                    onChange={() => toggleScope(option.value)}
                  />
                  {option.label}
                </label>
              ))}
            </fieldset>
            <label className="api-tokens-field">
              <span>{t("Expires", "Läuft ab")}</span>
              <select className="system-input" value={expiry} onChange={(event) => setExpiry(event.target.value)}>
                <option value="30">{t("In 30 days", "In 30 Tagen")}</option>
                <option value="90">{t("In 90 days", "In 90 Tagen")}</option>
                <option value="365">{t("In one year", "In einem Jahr")}</option>
                <option value="">{t("Never", "Nie")}</option>
              </select>
            </label>
            <button type="submit" className="btn-primary" disabled={creating || !name.trim() || scopes.length === 0}>
              {t("Create token", "Token erstellen")}
            </button>
          </form>

          {created && (
            <div className="api-tokens-created" role="status">
              <p>
                {t(
                  `Copy "${created.name}" now. It is not shown again.`,
                  `Kopiere „${created.name}“ jetzt. Es wird nicht noch einmal angezeigt.`
                )}
              </p>
              <div className="api-tokens-value">
                <code>{created.token}</code>
                <IconButton
                  label={copied ? t("Copied", "Kopiert") : t("Copy token", "Token kopieren")}
                  onClick={() => void handleCopy(created.token)}
                >
                  {copied ? <LuCheck aria-hidden="true" /> : <LuCopy aria-hidden="true" />}
                </IconButton>
              </div>
              <button type="button" className="btn-secondary" onClick={() => setCreated(null)}>
                {t("Done", "Fertig")}
              </button>
            </div>
          )}

          {tokens.length === 0 ? (
            <EmptyState title={t("No API tokens yet.", "Noch keine API-Tokens.")} />
          ) : (
            <div className="table-scroll scan-target-scroll">
              <table className="scan-target-table scan-target-access-table api-tokens-table">
                <thead>
                  <tr>
                    <th scope="col">{t("Name", "Name")}</th>
                    <th scope="col">{t("Token", "Token")}</th>
                    <th scope="col">{t("Scopes", "Scopes")}</th>
                    <th scope="col">{t("Expires", "Läuft ab")}</th>
                    <th scope="col">{t("Last used", "Zuletzt benutzt")}</th>
                    <th scope="col" className="scan-target-access-actions-head">{t("Actions", "Aktionen")}</th>
                  </tr>
                </thead>
                <tbody>
                  {tokens.map((token) => (
                    <tr key={token.id}>
                      <td className="scan-target-access-name">{token.name}</td>
                      <td className="mono scan-target-access-id">{token.tokenPrefix}…</td>
                      <td className="mono api-tokens-scope-list">
                        {token.scopes.map((scope) => (
                          <span key={scope}>{scope}</span>
                        ))}
                      </td>
                      <td data-label={t("Expires", "Läuft ab")}>
                        {token.expired
                          ? t("Expired", "Abgelaufen")
                          : token.expiresAt
                            ? formatDateOnly(token.expiresAt)
                            : t("Never", "Nie")}
                      </td>
                      <td data-label={t("Last used", "Zuletzt benutzt")}>
                        {token.lastUsedAt ? formatDateTime(token.lastUsedAt) : t("Never", "Nie")}
                      </td>
                      <td>
                        <div className="scan-target-access-actions">
                          {confirmingId === token.id ? (
                            <>
                              <button
                                type="button"
                                className="btn-secondary"
                                disabled={busyId === token.id}
                                onClick={() => void handleRevoke(token)}
                              >
                                {t("Confirm", "Bestätigen")}
                              </button>
                              <button type="button" className="btn-secondary" onClick={() => setConfirmingId(null)}>
                                {t("Cancel", "Abbrechen")}
                              </button>
                            </>
                          ) : (
                            <button type="button" className="btn-secondary" onClick={() => setConfirmingId(token.id)}>
                              {t("Revoke", "Widerrufen")}
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </div>
  );
};
