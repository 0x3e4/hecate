import { useEffect, useState } from "react";
import { LuCoffee, LuExternalLink, LuGithub } from "react-icons/lu";

import { version as FRONTEND_VERSION } from "../../package.json";
import "../screens/support.css";
import { fetchVersionInfo } from "../api/version";
import { LoadingRegion, SkeletonRows } from "../components/Skeleton";
import { useI18n } from "../i18n/context";
import type { BuildRelation, VersionInfo } from "../types";
import { ErrorState, PageHeader, Section } from "../ui/primitives";
import { safeHref } from "../utils/safeHref";

type StatusTone = "ok" | "info" | "error" | "muted";

/** A state as a word, never colour alone. */
const StatusWord = ({ tone, children }: { tone: StatusTone; children: React.ReactNode }) => (
  <span className={`support-screen-status support-screen-status--${tone}`}>{children}</span>
);

export const SupportPage = () => {
  const { t } = useI18n();
  const [info, setInfo] = useState<VersionInfo | null>(null);
  const [loadError, setLoadError] = useState(false);

  useEffect(() => {
    document.title = `${t("Support", "Unterstützung")} | Hecate`;
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
  type Status = "up_to_date" | "build_update" | "ahead" | "local" | "running_unknown" | "unreachable";

  // The backend asks GitHub how the running commit relates to the newest
  // main-<sha> image; without that answer a different SHA is all we know.
  const componentStatus = (
    runningSha: string | null,
    latestSha: string | null,
    reachable: boolean,
    relation: BuildRelation | null
  ): Status => {
    if (!reachable) return "unreachable";
    if (!runningSha) return "running_unknown";
    if (!latestSha) return "running_unknown";
    if (relation === "identical") return "up_to_date";
    if (relation === "ahead") return "ahead";
    if (relation === "unknown_commit") return "local";
    if (relation === "behind" || relation === "diverged") return "build_update";
    return runningSha === latestSha ? "up_to_date" : "build_update";
  };

  const renderRowStatus = (status: Status): React.ReactNode => {
    if (status === "up_to_date") {
      return <StatusWord tone="ok">{t("Up to date", "Aktuell")}</StatusWord>;
    }
    if (status === "build_update") {
      return <StatusWord tone="info">{t("New build available", "Neuer Build verfügbar")}</StatusWord>;
    }
    if (status === "ahead") {
      return <StatusWord tone="ok">{t("Newer than the latest build", "Neuer als der letzte Build")}</StatusWord>;
    }
    if (status === "local") {
      return <StatusWord tone="muted">{t("Local build, not on GitHub", "Lokaler Build, nicht auf GitHub")}</StatusWord>;
    }
    if (status === "unreachable") {
      return <StatusWord tone="error">{t("Unreachable", "Nicht erreichbar")}</StatusWord>;
    }
    return <StatusWord tone="muted">{t("Build SHA unknown", "Build-SHA unbekannt")}</StatusWord>;
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
    relation: BuildRelation | null;
  };

  // The frontend's SHA lives only in this bundle. Built from the same commit
  // as the backend and compared with the same image commit, it shares the
  // backend's answer; otherwise it falls back to comparing SHAs.
  const frontendRelation = (data: VersionInfo): BuildRelation | null =>
    FRONTEND_SHA &&
    FRONTEND_SHA === data.backend.runningSha &&
    data.ghcr.frontend?.shortSha === data.ghcr.backend?.shortSha
      ? data.buildRelations?.backend ?? null
      : null;

  const buildRows = (data: VersionInfo): Row[] => [
    {
      key: "backend",
      label: t("Backend", "Backend"),
      runningSha: data.backend.runningSha,
      runningVersion: data.backend.runningVersion,
      reachable: data.backend.reachable,
      relation: data.buildRelations?.backend ?? null,
      latestTag: data.ghcr.backend?.tag ?? null,
      latestSha: data.ghcr.backend?.shortSha ?? null,
      publishedAt: data.ghcr.backend?.publishedAt ?? null,
      packageUrl: data.ghcr.backend?.packageUrl ?? null,
    },
    {
      key: "frontend",
      label: t("Frontend", "Frontend"),
      runningSha: FRONTEND_SHA || null,
      runningVersion: FRONTEND_VERSION,
      reachable: true,
      relation: frontendRelation(data),
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
      relation: data.buildRelations?.scanner ?? null,
      latestTag: data.ghcr.scanner?.tag ?? null,
      latestSha: data.ghcr.scanner?.shortSha ?? null,
      publishedAt: data.ghcr.scanner?.publishedAt ?? null,
      packageUrl: data.ghcr.scanner?.packageUrl ?? null,
    },
  ];

  const overallBadge = (rows: Row[]): React.ReactNode => {
    if (!info) return null;
    const statuses = rows.map((r) =>
      componentStatus(r.runningSha, r.latestSha, r.reachable, r.relation)
    );
    const allUpToDate = statuses.every((s) => s === "up_to_date");
    const anyOutdated = statuses.includes("build_update");

    // Only a release newer than the running version is an update: a beta
    // ahead of the latest release is not offered a downgrade.
    if (info.semverTag && info.releaseAvailable) {
      const tag = info.semverTag.tag.replace(/^v/, "");
      return <StatusWord tone="info">{t(`Release available: ${tag}`, `Release verfügbar: ${tag}`)}</StatusWord>;
    }
    if (allUpToDate) {
      return <StatusWord tone="ok">{t("All components up to date", "Alle Komponenten aktuell")}</StatusWord>;
    }
    if (anyOutdated) {
      const count = statuses.filter((s) => s === "build_update").length;
      return (
        <StatusWord tone="info">
          {t(
            `${count} component${count === 1 ? "" : "s"} out of date`,
            `${count} Komponente${count === 1 ? "" : "n"} veraltet`
          )}
        </StatusWord>
      );
    }
    if (statuses.every((s) => s === "up_to_date" || s === "ahead" || s === "local")) {
      return (
        <StatusWord tone="ok">
          {t("Newer than the published builds", "Neuer als die veröffentlichten Builds")}
        </StatusWord>
      );
    }
    if (info.releaseAvailable === false && FRONTEND_VERSION.includes("-")) {
      return <StatusWord tone="muted">{t(`Pre-release ${FRONTEND_VERSION}`, `Vorabversion ${FRONTEND_VERSION}`)}</StatusWord>;
    }
    return <StatusWord tone="muted">{t("Status partial", "Status unvollständig")}</StatusWord>;
  };

  const renderVersionBody = () => {
    if (loadError) {
      return (
        <ErrorState
          title={t(
            "Couldn't load version information.",
            "Versionsinformationen konnten nicht geladen werden."
          )}
        />
      );
    }
    if (!info) {
      return (
        <LoadingRegion label={t("Loading version information", "Versionsinformationen werden geladen")} className="support-screen-skeleton">
          <SkeletonRows rows={3} height={36} />
        </LoadingRegion>
      );
    }

    const rows = buildRows(info);

    const renderRunning = (row: Row): React.ReactNode => {
      if (!row.reachable) return <span className="muted">{t("(not reachable)", "(nicht erreichbar)")}</span>;
      return (
        <span className="support-screen-value">
          {row.runningVersion ? <span className="mono">{row.runningVersion}</span> : null}
          {row.runningSha ? (
            <span className="mono muted">{row.runningSha}</span>
          ) : (
            <span className="muted">{t("(SHA unknown)", "(SHA unbekannt)")}</span>
          )}
        </span>
      );
    };

    const renderLatest = (row: Row): React.ReactNode => {
      if (!row.latestTag) return <span className="muted">{t("(no signal)", "(kein Signal)")}</span>;
      const ago = formatRelative(row.publishedAt);
      return (
        <span className="support-screen-value">
          {row.packageUrl ? (
            <a className="mono" href={safeHref(row.packageUrl)} target="_blank" rel="noopener noreferrer">
              {row.latestTag}
            </a>
          ) : (
            <span className="mono">{row.latestTag}</span>
          )}
          {ago ? <span className="muted">{ago}</span> : null}
        </span>
      );
    };

    return (
      <>
        <div className="table-scroll">
          <table className="support-screen-table">
            <thead>
              <tr>
                <th>{t("Component", "Komponente")}</th>
                <th>{t("Running", "Laufend")}</th>
                <th>{t("Latest on GitHub", "Aktuell auf GitHub")}</th>
                <th>{t("Status", "Status")}</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => {
                const status = componentStatus(row.runningSha, row.latestSha, row.reachable, row.relation);
                return (
                  <tr key={row.key}>
                    <td className="support-screen-component">{row.label}</td>
                    <td data-label={t("Running", "Laufend")}>{renderRunning(row)}</td>
                    <td data-label={t("Latest", "Aktuell")}>{renderLatest(row)}</td>
                    <td className="support-screen-state">{renderRowStatus(status)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        {info.semverTag && (
          <p className="support-screen-release">
            <a
              className="btn btn-secondary"
              href={safeHref(info.semverTag.releaseUrl)}
              target="_blank"
              rel="noopener noreferrer"
            >
              <LuExternalLink aria-hidden="true" />
              {t(
                `Release notes for ${info.semverTag.tag.replace(/^v/, "")}`,
                `Release-Notes für ${info.semverTag.tag.replace(/^v/, "")}`
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
      <PageHeader
        title={t("Support", "Unterstützung")}
        description={t(
          "Hourly check against GitHub for new tags and main-<sha> builds.",
          "Stündlicher GitHub-Abgleich auf neue Tags und main-<sha>-Builds."
        )}
      />

      <Section title={t("Version", "Version")} actions={renderVersionBadge()}>
        {renderVersionBody()}
      </Section>

      <div className="support-screen-ways">
        <section className="support-screen-way">
          <h2>{t("Support Hecate", "Hecate unterstützen")}</h2>
          <p>
            {t(
              "Hecate is a free, self-hosted vulnerability-management platform. If it saves you time or helps keep your systems safer, please consider supporting development. It directly funds new data sources, scanner integrations, and feature work.",
              "Hecate ist eine kostenlose, selbst gehostete Schwachstellenmanagement-Plattform. Wenn sie Ihnen Zeit spart oder Ihre Systeme sicherer macht, freuen wir uns über Ihre Unterstützung. Sie fließt direkt in neue Datenquellen, Scanner-Integrationen und neue Funktionen."
            )}
          </p>
          <a className="btn btn-primary" href={kofiUrl} target="_blank" rel="noopener noreferrer">
            <LuCoffee aria-hidden="true" />
            {t("Donate on Ko-fi", "Auf Ko-fi spenden")}
          </a>
        </section>

        <section className="support-screen-way">
          <h2>{t("Star us on GitHub", "GitHub-Star vergeben")}</h2>
          <p>
            {t(
              "A star on GitHub helps other defenders discover Hecate and signals which features the community values. It costs nothing and takes ten seconds.",
              "Ein Stern auf GitHub hilft anderen Verteidiger:innen, Hecate zu finden, und zeigt uns, welche Funktionen der Community wichtig sind. Es kostet nichts und dauert zehn Sekunden."
            )}
          </p>
          <a className="btn btn-secondary" href={repoUrl} target="_blank" rel="noopener noreferrer">
            <LuGithub aria-hidden="true" />
            {t("Star on GitHub", "Stern auf GitHub vergeben")}
          </a>
        </section>
      </div>
    </div>
  );
};
