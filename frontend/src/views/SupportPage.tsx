import { useEffect, useState } from "react";
import {
  LuCoffee,
  LuExternalLink,
  LuGithub,
  LuHeart,
  LuStar,
  LuCircleCheck,
  LuTriangleAlert,
  LuCircleAlert,
} from "react-icons/lu";

import { fetchVersionInfo } from "../api/version";
import { useI18n } from "../i18n/context";
import type { VersionInfo } from "../types";

const KOFI_RED = "#FF5E5B";
const GITHUB_BG = "#24292f";

const buttonBase: React.CSSProperties = {
  display: "inline-flex",
  alignItems: "center",
  gap: "0.55rem",
  padding: "0.65rem 1.1rem",
  borderRadius: "10px",
  fontSize: "0.95rem",
  fontWeight: 600,
  textDecoration: "none",
  border: "1px solid transparent",
  transition: "transform 120ms ease, box-shadow 120ms ease",
};

const kofiStyle: React.CSSProperties = {
  ...buttonBase,
  background: KOFI_RED,
  color: "#fff",
  boxShadow: "0 6px 18px rgba(255, 94, 91, 0.35)",
};

const githubStyle: React.CSSProperties = {
  ...buttonBase,
  background: GITHUB_BG,
  color: "#fff",
  borderColor: "rgba(255,255,255,0.12)",
};

const releaseLinkStyle: React.CSSProperties = {
  ...buttonBase,
  background: "rgba(252, 196, 25, 0.14)",
  border: "1px solid rgba(252, 196, 25, 0.45)",
  color: "rgba(252, 196, 25)",
};

const badgeBase: React.CSSProperties = {
  display: "inline-flex",
  alignItems: "center",
  gap: "0.4rem",
  padding: "0.35rem 0.7rem",
  borderRadius: "999px",
  fontSize: "0.85rem",
  fontWeight: 600,
};

const upToDateBadge: React.CSSProperties = {
  ...badgeBase,
  background: "rgba(105, 219, 124, 0.14)",
  border: "1px solid rgba(105, 219, 124, 0.35)",
  color: "rgba(105, 219, 124)",
};

const updateBadge: React.CSSProperties = {
  ...badgeBase,
  background: "rgba(252, 196, 25, 0.14)",
  border: "1px solid rgba(252, 196, 25, 0.45)",
  color: "rgba(252, 196, 25)",
};

const unreachableBadge: React.CSSProperties = {
  ...badgeBase,
  background: "rgba(160, 160, 160, 0.12)",
  border: "1px solid rgba(160, 160, 160, 0.3)",
  color: "rgba(200, 200, 200)",
};

export const SupportPage = () => {
  const { t } = useI18n();
  const [info, setInfo] = useState<VersionInfo | null>(null);
  const [loadError, setLoadError] = useState(false);

  useEffect(() => {
    document.title = `${t("Support", "Unterstützung")} – Hecate`;
  }, [t]);

  useEffect(() => {
    let cancelled = false;
    fetchVersionInfo()
      .then((data) => {
        if (!cancelled) setInfo(data);
      })
      .catch(() => {
        if (!cancelled) setLoadError(true);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const formatRelative = (iso: string | null): string | null => {
    if (!iso) return null;
    const then = Date.parse(iso);
    if (Number.isNaN(then)) return null;
    const seconds = Math.max(0, Math.round((Date.now() - then) / 1000));
    if (seconds < 60) return t(`${seconds}s ago`, `vor ${seconds}s`);
    const minutes = Math.round(seconds / 60);
    if (minutes < 60) return t(`${minutes} min ago`, `vor ${minutes} Min.`);
    const hours = Math.round(minutes / 60);
    if (hours < 48) return t(`${hours} h ago`, `vor ${hours} Std.`);
    const days = Math.round(hours / 24);
    return t(`${days} d ago`, `vor ${days} Tagen`);
  };

  // Vite injects VITE_BUILD_SHA into the bundle at build time (see
  // frontend/Dockerfile). Empty in dev / non-baked builds.
  const FRONTEND_SHA: string =
    ((import.meta as { env?: Record<string, string | undefined> }).env
      ?.VITE_BUILD_SHA ?? "")
      .trim()
      .toLowerCase()
      .slice(0, 7);

  type ComponentKey = "backend" | "frontend" | "scanner";
  type Status = "up_to_date" | "build_update" | "running_unknown" | "unreachable";

  const componentStatus = (
    runningSha: string | null,
    latestSha: string | null,
    reachable: boolean
  ): Status => {
    if (!reachable) return "unreachable";
    if (!runningSha) return "running_unknown";
    if (!latestSha) return "running_unknown";
    return runningSha === latestSha ? "up_to_date" : "build_update";
  };

  const renderRowStatus = (status: Status): React.ReactNode => {
    if (status === "up_to_date") {
      return (
        <span style={upToDateBadge}>
          <LuCircleCheck aria-hidden="true" />
          {t("Up to date", "Aktuell")}
        </span>
      );
    }
    if (status === "build_update") {
      return (
        <span style={updateBadge}>
          <LuTriangleAlert aria-hidden="true" />
          {t("New build available", "Neuer Build verfügbar")}
        </span>
      );
    }
    if (status === "unreachable") {
      return (
        <span style={unreachableBadge}>
          <LuCircleAlert aria-hidden="true" />
          {t("Unreachable", "Nicht erreichbar")}
        </span>
      );
    }
    return (
      <span style={unreachableBadge}>
        <LuCircleAlert aria-hidden="true" />
        {t("Build SHA unknown", "Build-SHA unbekannt")}
      </span>
    );
  };

  type Row = {
    key: ComponentKey;
    label: string;
    runningSha: string | null;
    runningVersion: string | null;
    reachable: boolean;
    latestTag: string | null;
    latestSha: string | null;
    publishedAt: string | null;
    packageUrl: string | null;
  };

  const buildRows = (data: VersionInfo): Row[] => [
    {
      key: "backend",
      label: t("Backend", "Backend"),
      runningSha: data.backend.runningSha,
      runningVersion: data.backend.runningVersion,
      reachable: data.backend.reachable,
      latestTag: data.ghcr.backend?.tag ?? null,
      latestSha: data.ghcr.backend?.shortSha ?? null,
      publishedAt: data.ghcr.backend?.publishedAt ?? null,
      packageUrl: data.ghcr.backend?.packageUrl ?? null,
    },
    {
      key: "frontend",
      label: t("Frontend", "Frontend"),
      runningSha: FRONTEND_SHA || null,
      runningVersion: null,
      reachable: true,
      latestTag: data.ghcr.frontend?.tag ?? null,
      latestSha: data.ghcr.frontend?.shortSha ?? null,
      publishedAt: data.ghcr.frontend?.publishedAt ?? null,
      packageUrl: data.ghcr.frontend?.packageUrl ?? null,
    },
    {
      key: "scanner",
      label: t("Scanner", "Scanner"),
      runningSha: data.scanner.runningSha,
      runningVersion: data.scanner.runningVersion,
      reachable: data.scanner.reachable,
      latestTag: data.ghcr.scanner?.tag ?? null,
      latestSha: data.ghcr.scanner?.shortSha ?? null,
      publishedAt: data.ghcr.scanner?.publishedAt ?? null,
      packageUrl: data.ghcr.scanner?.packageUrl ?? null,
    },
  ];

  const overallBadge = (rows: Row[]): React.ReactNode => {
    if (!info) return null;
    const statuses = rows.map((r) =>
      componentStatus(r.runningSha, r.latestSha, r.reachable)
    );
    const allReachable = statuses.every((s) => s !== "unreachable");
    const anyOutdated = statuses.includes("build_update");
    const anyUnknown = statuses.includes("running_unknown");
    if (info.semverTag) {
      return (
        <span style={updateBadge}>
          <LuTriangleAlert aria-hidden="true" />
          {t(
            `Release available — v${info.semverTag.tag.replace(/^v/, "")}`,
            `Release verfügbar — v${info.semverTag.tag.replace(/^v/, "")}`
          )}
        </span>
      );
    }
    if (anyOutdated) {
      const count = statuses.filter((s) => s === "build_update").length;
      return (
        <span style={updateBadge}>
          <LuTriangleAlert aria-hidden="true" />
          {t(
            `${count} component${count === 1 ? "" : "s"} out of date`,
            `${count} Komponente${count === 1 ? "" : "n"} veraltet`
          )}
        </span>
      );
    }
    if (allReachable && !anyUnknown) {
      return (
        <span style={upToDateBadge}>
          <LuCircleCheck aria-hidden="true" />
          {t("All components up to date", "Alle Komponenten aktuell")}
        </span>
      );
    }
    return (
      <span style={unreachableBadge}>
        <LuCircleAlert aria-hidden="true" />
        {t("Status partial", "Status unvollständig")}
      </span>
    );
  };

  const renderVersionBody = () => {
    if (loadError) {
      return (
        <p className="muted">
          {t(
            "Couldn't load version information.",
            "Versionsinformationen konnten nicht geladen werden."
          )}
        </p>
      );
    }
    if (!info) {
      return <p className="muted">{t("Loading…", "Wird geladen…")}</p>;
    }

    const rows = buildRows(info);

    const runningLabel = (row: Row): string => {
      if (!row.reachable) return t("(not reachable)", "(nicht erreichbar)");
      if (!row.runningSha) return t("(SHA unknown)", "(SHA unbekannt)");
      const v = row.runningVersion ? `v${row.runningVersion} · ` : "";
      return `${v}${row.runningSha}`;
    };

    const latestLabel = (row: Row): string => {
      if (!row.latestTag) return t("(no signal)", "(kein Signal)");
      const ago = formatRelative(row.publishedAt);
      return ago ? `${row.latestTag} · ${ago}` : row.latestTag;
    };

    return (
      <>
        <div className="support-version-table">
          <div className="support-version-table-header">
            <div>{t("Component", "Komponente")}</div>
            <div>{t("Running", "Laufend")}</div>
            <div>{t("Latest on GitHub", "Aktuell auf GitHub")}</div>
            <div aria-hidden="true" />
          </div>

          {rows.map((row) => {
            const status = componentStatus(row.runningSha, row.latestSha, row.reachable);
            return (
              <div className="support-version-row" key={row.key}>
                <div className="support-version-name">{row.label}</div>
                <div className="support-version-running">
                  <span className="support-version-mobile-label">
                    {t("Running", "Laufend")}
                  </span>
                  {runningLabel(row)}
                </div>
                <div className="support-version-latest">
                  <span className="support-version-mobile-label">
                    {t("Latest", "Aktuell")}
                  </span>
                  {row.packageUrl && row.latestTag ? (
                    <a href={row.packageUrl} target="_blank" rel="noopener noreferrer">
                      {latestLabel(row)}
                    </a>
                  ) : (
                    latestLabel(row)
                  )}
                </div>
                <div className="support-version-status">{renderRowStatus(status)}</div>
              </div>
            );
          })}
        </div>
        {info.semverTag && (
          <p style={{ marginTop: "1.25rem", marginBottom: 0 }}>
            <a
              href={info.semverTag.releaseUrl}
              target="_blank"
              rel="noopener noreferrer"
              style={releaseLinkStyle}
            >
              <LuExternalLink aria-hidden="true" />
              {t(
                `View release notes — v${info.semverTag.tag.replace(/^v/, "")}`,
                `Release-Notes ansehen — v${info.semverTag.tag.replace(/^v/, "")}`
              )}
            </a>
          </p>
        )}
      </>
    );
  };

  const renderVersionBadge = (): React.ReactNode => {
    if (loadError || !info) return null;
    return overallBadge(buildRows(info));
  };

  const kofiUrl = info?.kofiUrl ?? "https://ko-fi.com/0x3e4";
  const repoUrl = info?.repoUrl ?? "https://github.com/0x3e4/hecate";

  return (
    <div className="page support-page">
      <section className="card">
        <h2>
          <LuHeart aria-hidden="true" style={{ verticalAlign: "-2px", marginRight: "0.4rem", color: KOFI_RED }} />
          {t("Support Hecate", "Hecate unterstützen")}
        </h2>
        <p className="muted">
          {t(
            "Hecate is a free, self-hosted vulnerability-management platform. If it saves you time or helps keep your systems safer, please consider supporting development — it directly funds new data sources, scanner integrations, and feature work.",
            "Hecate ist eine kostenlose, selbst gehostete Schwachstellenmanagement-Plattform. Wenn sie Ihnen Zeit spart oder Ihre Systeme sicherer macht, freuen wir uns über Ihre Unterstützung — sie fließt direkt in neue Datenquellen, Scanner-Integrationen und neue Funktionen."
          )}
        </p>
        <p style={{ marginTop: "1.25rem", marginBottom: 0 }}>
          <a href={kofiUrl} target="_blank" rel="noopener noreferrer" style={kofiStyle}>
            <LuCoffee aria-hidden="true" />
            {t("Donate on Ko-fi", "Auf Ko-fi spenden")}
          </a>
        </p>
      </section>

      <section className="card">
        <h2>
          <LuStar aria-hidden="true" style={{ verticalAlign: "-2px", marginRight: "0.4rem", color: "#fcc419" }} />
          {t("Star us on GitHub", "GitHub-Star vergeben")}
        </h2>
        <p className="muted">
          {t(
            "A star on GitHub helps other defenders discover Hecate and signals which features the community values. It costs nothing and takes ten seconds.",
            "Ein Stern auf GitHub hilft anderen Verteidiger:innen, Hecate zu finden, und zeigt uns, welche Funktionen der Community wichtig sind. Es kostet nichts und dauert zehn Sekunden."
          )}
        </p>
        <p style={{ marginTop: "1.25rem", marginBottom: 0 }}>
          <a href={repoUrl} target="_blank" rel="noopener noreferrer" style={githubStyle}>
            <LuGithub aria-hidden="true" />
            {t("Star on GitHub", "Stern auf GitHub vergeben")}
          </a>
        </p>
      </section>

      <section className="card">
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "flex-start",
            flexWrap: "wrap",
            gap: "0.75rem 1rem",
          }}
        >
          <h2 style={{ marginBottom: 0 }}>{t("Version", "Version")}</h2>
          {renderVersionBadge()}
        </div>
        <p className="muted" style={{ marginTop: "0.5rem" }}>
          {t(
            "Hecate checks GitHub hourly for new version tags and rolling main-<sha> container builds. The first line below shows the running container; the second shows the newest signal upstream.",
            "Hecate prüft stündlich auf neue Versions-Tags und auf rollende main-<sha>-Container-Builds bei GitHub. Die erste Zeile zeigt den laufenden Container; die zweite den neuesten Signalstand auf GitHub."
          )}
        </p>
        {renderVersionBody()}
      </section>
    </div>
  );
};
