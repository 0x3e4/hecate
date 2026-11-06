import { useState, type FormEvent } from "react";
import { isRouteErrorResponse, Link, useLocation, useNavigate, useRouteError } from "react-router-dom";
import { LuArrowLeft, LuCopy, LuHouse, LuRefreshCw, LuSearch, LuSearchX, LuTriangleAlert } from "react-icons/lu";

import { version } from "../../package.json";
import { useI18n } from "../i18n/context";
import { isAdvisoryId, normalizeAdvisoryId } from "../utils/advisoryId";
import "../screens/error-page.css";

const SearchForm = () => {
  const { t } = useI18n();
  const navigate = useNavigate();
  const [query, setQuery] = useState("");
  const submit = (event: FormEvent) => {
    event.preventDefault();
    const value = query.trim();
    if (!value) return;
    if (isAdvisoryId(value)) {
      navigate(`/vulnerability/${encodeURIComponent(normalizeAdvisoryId(value))}`);
      return;
    }
    navigate(`/vulnerabilities?${new URLSearchParams({ search: value }).toString()}`);
  };
  return (
    <form className="error-page-search" onSubmit={submit} role="search">
      <label className="visually-hidden" htmlFor="error-page-search">
        {t("Search Hecate", "In Hecate suchen")}
      </label>
      <input
        id="error-page-search"
        type="search"
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        placeholder={t("CVE, package, product…", "CVE, Paket, Produkt…")}
        autoComplete="off"
      />
      <button type="submit" className="btn-primary">
        <LuSearch aria-hidden="true" />
        {t("Search", "Suchen")}
      </button>
    </form>
  );
};

/** Shown for a path no route knows, inside the app shell so the sidebar stays. */
export const NotFoundPage = () => {
  const { t } = useI18n();
  const location = useLocation();
  const navigate = useNavigate();
  return (
    <div className="page error-page">
      <span className="error-page-icon" aria-hidden="true">
        <LuSearchX />
      </span>
      <h1>{t("This page does not exist", "Diese Seite gibt es nicht")}</h1>
      <p className="error-page-text">
        <code className="mono">{location.pathname}</code>{" "}
        {t(
          "is not an address in Hecate. It may be mistyped, or the link is from an older version.",
          "ist keine Adresse in Hecate. Vielleicht ist sie vertippt, oder der Link stammt aus einer älteren Version.",
        )}
      </p>
      <SearchForm />
      <div className="error-page-actions">
        <Link to="/" className="btn-secondary">
          <LuHouse aria-hidden="true" />
          {t("Dashboard", "Dashboard")}
        </Link>
        {window.history.length > 1 && (
          <button type="button" className="btn-secondary" onClick={() => navigate(-1)}>
            <LuArrowLeft aria-hidden="true" />
            {t("Back", "Zurück")}
          </button>
        )}
      </div>
    </div>
  );
};

const describeRouteError = (error: unknown): { message: string; stack: string | null } => {
  if (isRouteErrorResponse(error)) {
    return { message: `${error.status} ${error.statusText}`.trim(), stack: null };
  }
  if (error instanceof Error) return { message: error.message || error.name, stack: error.stack ?? null };
  return { message: String(error), stack: null };
};

/**
 * A page that crashed while rendering. React Router shows this instead of its
 * raw default error. Inside the shell (see router.tsx) the sidebar keeps
 * working, and leaving the page clears the error.
 */
export const RouteErrorPage = () => {
  const { t } = useI18n();
  const error = useRouteError();
  const location = useLocation();
  const [copied, setCopied] = useState(false);

  if (isRouteErrorResponse(error) && error.status === 404) return <NotFoundPage />;

  const { message, stack } = describeRouteError(error);
  const report = [
    `Hecate ${version}`,
    `Path: ${location.pathname}${location.search}`,
    `Time: ${new Date().toISOString()}`,
    `Error: ${message}`,
    stack ? `\n${stack}` : "",
  ].join("\n");

  const copy = async () => {
    try {
      await navigator.clipboard?.writeText(report);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(false);
    }
  };

  return (
    <div className="page error-page" role="alert">
      <span className="error-page-icon error-page-icon--error" aria-hidden="true">
        <LuTriangleAlert />
      </span>
      <h1>{t("Something went wrong on this page", "Auf dieser Seite ist etwas schiefgelaufen")}</h1>
      <p className="error-page-text">
        {t(
          "The rest of Hecate keeps working: use the sidebar or reload the page. If it happens again, copy the details into a bug report.",
          "Der Rest von Hecate läuft weiter: Nimm die Seitenleiste oder lade die Seite neu. Passiert es wieder, kopiere die Details in eine Fehlermeldung.",
        )}
      </p>
      <div className="error-page-actions">
        <button type="button" className="btn-primary" onClick={() => window.location.reload()}>
          <LuRefreshCw aria-hidden="true" />
          {t("Reload page", "Seite neu laden")}
        </button>
        <Link to="/" className="btn-secondary">
          <LuHouse aria-hidden="true" />
          {t("Dashboard", "Dashboard")}
        </Link>
        <button type="button" className="btn-secondary" onClick={copy}>
          <LuCopy aria-hidden="true" />
          {copied ? t("Copied", "Kopiert") : t("Copy details", "Details kopieren")}
        </button>
      </div>
      <details className="error-page-details">
        <summary>{t("Technical details", "Technische Details")}</summary>
        <pre className="mono">{report}</pre>
      </details>
    </div>
  );
};
