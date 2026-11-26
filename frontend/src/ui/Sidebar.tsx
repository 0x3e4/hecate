import { Link, NavLink, useLocation } from "react-router-dom";
import { LuLayoutDashboard, LuRadioTower,
  LuShieldAlert, LuWrench, LuBrain, LuLogs, LuFileChartColumnIncreasing, LuHistory, LuSettings, LuChevronLeft, LuChevronRight, LuScanLine, LuX, LuBookOpen, LuBox, LuHeart, LuLogIn, LuUser, LuSlidersHorizontal } from "react-icons/lu";
import { useEffect, useMemo, useRef, useState } from "react";

import { version } from "../../package.json";
import { useSavedSearches } from "../hooks/useSavedSearches";
import { useRecentlyVisited } from "../hooks/useRecentlyVisited";
import { useI18n } from "../i18n/context";
import { useSSE } from "../hooks/useSSE";
import { useServerConfig } from "../server-config/context";
import { api } from "../api/client";
import { useAuth } from "../auth/context";
import { roleLabel } from "../auth/roleLabel";
import { usePreferences } from "../preferences/context";

type SidebarProps = {
  collapsed: boolean;
  onToggleCollapse: () => void;
  mobileMenuOpen?: boolean;
  onMobileMenuClose?: () => void;
};

type NavItem = { to: string; label: string; icon: typeof LuLayoutDashboard; external?: boolean };
type NavSection = { titleEn: string; titleDe: string; items: NavItem[] };

const buildNavSections = (
  aiEnabled: boolean,
  scaEnabled: boolean,
  supportPageEnabled: boolean,
  docsUrl: string | null,
): NavSection[] => [
  {
    titleEn: "", titleDe: "",
    items: [{ to: "/", label: "Dashboard", icon: LuLayoutDashboard }],
  },
  {
    titleEn: "Vulnerabilities", titleDe: "Schwachstellen",
    items: [
      { to: "/vulnerabilities", label: "Vulnerabilities", icon: LuShieldAlert },
      { to: "/query-builder", label: "Query builder", icon: LuWrench },
      ...(aiEnabled ? [{ to: "/ai-analyse", label: "AI analysis", icon: LuBrain }] : []),
      { to: "/changelog", label: "Changelog", icon: LuHistory },
    ],
  },
  {
    titleEn: "Security", titleDe: "Sicherheit",
    items: [
      ...(scaEnabled ? [
        { to: "/scans", label: "SCA", icon: LuScanLine },
        { to: "/malware-feed", label: "Malware feed", icon: LuShieldAlert },
      ] : []),
      { to: "/advisories", label: "Advisories", icon: LuRadioTower },
    ],
  },
  {
    titleEn: "Environment", titleDe: "Umgebung",
    items: [
      { to: "/inventory", label: "Inventory", icon: LuBox },
    ],
  },
  {
    titleEn: "Analysis", titleDe: "Analyse",
    items: [
      { to: "/stats", label: "Statistics", icon: LuFileChartColumnIncreasing },
      { to: "/audit", label: "Audit log", icon: LuLogs },
    ],
  },
  {
    titleEn: "Administration", titleDe: "Verwaltung",
    items: [{ to: "/system", label: "System", icon: LuSettings }],
  },
  ...(scaEnabled ? [{
    titleEn: "Info", titleDe: "Info",
    items: [
      ...(docsUrl ? [{ to: docsUrl, label: "Documentation", icon: LuBookOpen, external: true }] : []),
      { to: "/info/cicd", label: "CI/CD", icon: LuBookOpen },
      { to: "/info/api", label: "API", icon: LuBookOpen },
      { to: "/info/mcp", label: "MCP", icon: LuBookOpen },
    ],
  }] : []),
  ...(supportPageEnabled ? [{
    titleEn: "Support", titleDe: "Unterstützung",
    items: [
      { to: "/support", label: "Support", icon: LuHeart },
    ],
  }] : []),
];

export const Sidebar = ({ collapsed, onToggleCollapse, mobileMenuOpen, onMobileMenuClose }: SidebarProps) => {
  const { t } = useI18n();
  const { savedSearches } = useSavedSearches();
  const { recentVulnerabilities, removeVisit } = useRecentlyVisited();
  const location = useLocation();
  const currentParamsKey = useMemo(() => normalizeSearchParams(location.search), [location.search]);
  const { jobs, snapshotSeq } = useSSE();
  const auth = useAuth();
  const { triggerProps } = usePreferences();
  const { aiEnabled, scaEnabled, supportPageEnabled, docsUrl } = useServerConfig();
  const navSections = useMemo(
    () => buildNavSections(aiEnabled, scaEnabled, supportPageEnabled, docsUrl),
    [aiEnabled, scaEnabled, supportPageEnabled, docsUrl]
  );

  const aiRunning = useMemo(() => {
    for (const [name, job] of jobs) {
      if (
        name.startsWith("ai_investigation_") || name === "ai_batch_investigation"
        || name.startsWith("ai_scan_analysis_") || name.startsWith("attack_path_")
        || name.startsWith("scan_attack_chain_")
      ) {
        if (job.status === "running") return true;
      }
    }
    return false;
  }, [jobs]);

  // Changes whenever a scan event arrives; only used to trigger a re-check.
  const scaEventKey = useMemo(() => {
    let key = "";
    for (const [name, job] of jobs) {
      if (name.startsWith("sca_scan_")) key += `${name}:${job.eventType};`;
    }
    return key;
  }, [jobs]);

  // The server's scan list is the only source of truth for the dot. SSE events
  // (and every reconnect) just make it ask right away: OR-ing in a "running"
  // event kept the dot on whenever the stream missed the scan's last event.
  const [scaRunning, setScaRunning] = useState(false);
  const scaCheck = useRef<() => void>(() => {});
  useEffect(() => {
    if (!scaEnabled) {
      setScaRunning(false);
      return;
    }
    let cancelled = false;
    let seq = 0;
    const check = async () => {
      const mine = ++seq;
      try {
        const resp = await api.get<{ total: number }>("/v1/scans", { params: { status: "running", limit: 1 } });
        if (!cancelled && mine === seq) setScaRunning(resp.data.total > 0);
      } catch { /* keep the last known state */ }
    };
    scaCheck.current = () => void check();
    check();
    const interval = setInterval(check, 15000);
    const onVisible = () => { if (document.visibilityState === "visible") void check(); };
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      cancelled = true;
      clearInterval(interval);
      document.removeEventListener("visibilitychange", onVisible);
      scaCheck.current = () => {};
    };
  }, [scaEnabled]);

  useEffect(() => {
    if (scaEventKey) scaCheck.current();
  }, [scaEventKey, snapshotSeq]);
  const germanLabels: Record<string, string> = {
    "/": "Dashboard",
    "/vulnerabilities": "Schwachstellen",
    "/query-builder": "Query-Builder",
    "/ai-analyse": "AI-Analyse",
    "/stats": "Statistiken",
    "/changelog": "Changelog",
    "/audit": "Audit-Log",
    "/inventory": "Inventar",
    "/scans": "SCA",
    "/malware-feed": "Malware-Feed",
    "/advisories": "Meldungen",
    "/system": "System",
    "/info/api": "API",
    "/info/cicd": "CI/CD",
    "/info/mcp": "MCP",
    "/support": "Unterstützung",
    ...(docsUrl ? { [docsUrl]: "Dokumentation" } : {}),
  };

  const localizedSections = useMemo(
    () =>
      navSections.map((section) => ({
        title: section.titleEn ? t(section.titleEn, section.titleDe) : "",
        items: section.items.map((item) => ({
          ...item,
          label: t(item.label, germanLabels[item.to] ?? item.label),
        })),
      })),
    [t]
  );

  // The dot says "something is running here"; the link's name has to say it too.
  const busyLabel = (item: { to: string; label: string }) => {
    if (item.to === "/scans" && scaRunning) return `${item.label} · ${t("scan running", "Scan läuft")}`;
    if (item.to === "/ai-analyse" && aiRunning) return `${item.label} · ${t("analysis running", "Analyse läuft")}`;
    return item.label;
  };

  const handleLinkClick = () => {
    if (onMobileMenuClose) {
      onMobileMenuClose();
    }
  };

  return (
    <aside className={`app-sidebar${collapsed ? " collapsed" : ""}${mobileMenuOpen ? " mobile-open" : ""}`}>
      <Link to="/" className="sidebar-brand" title={t("AI-powered vulnerability analysis", "KI-gestützte Schwachstellenanalyse")} aria-label="Hecate Cyber Defense">
        <img src="/logo.png" alt="" width={32} height={32} />
        <span className="sidebar-brand-name">Hecate Cyber Defense</span>
      </Link>
      <nav className="sidebar-nav">
        {localizedSections.map((section, sectionIdx) => (
          <div key={sectionIdx} className="sidebar-section">
            {section.title && !collapsed && (
              <div className="sidebar-section-title">{section.title}</div>
            )}
            {section.title && collapsed && (
              <div className="sidebar-section-divider" />
            )}
            {section.items.map((item) => {
              const Icon = item.icon;
              const isVulnerabilitySection = item.to === "/vulnerabilities";
              return (
                <div key={item.to} className="sidebar-nav-group">
                  {item.external ? (
                    <a
                      href={item.to}
                      target="_blank"
                      rel="noreferrer"
                      title={item.label}
                      aria-label={item.label}
                      className="sidebar-link"
                      onClick={handleLinkClick}
                    >
                      <span className="sidebar-link-short">
                        <Icon aria-hidden="true" focusable="false" />
                      </span>
                      <span className="sidebar-link-text">{item.label}</span>
                    </a>
                  ) : (
                  <NavLink
                    to={item.to}
                    title={busyLabel(item)}
                    aria-label={busyLabel(item)}
                    className={({ isActive }) =>
                      `sidebar-link${isActive ? " active" : ""}`
                    }
                    onClick={handleLinkClick}
                  >
                    <span className="sidebar-link-short">
                      <Icon aria-hidden="true" focusable="false" />
                      {item.to === "/ai-analyse" && aiRunning && <span className="sidebar-pulse" aria-hidden="true" />}
                      {item.to === "/scans" && scaRunning && <span className="sidebar-pulse" aria-hidden="true" />}
                    </span>
                    <span className="sidebar-link-text">{item.label}</span>
                    {item.to === "/ai-analyse" && aiRunning && <span className="sidebar-pulse" aria-hidden="true" />}
                    {item.to === "/scans" && scaRunning && <span className="sidebar-pulse" aria-hidden="true" />}
                  </NavLink>
                  )}
                  {item.to === "/" && !collapsed && recentVulnerabilities.length > 0 && (
                    <div className="sidebar-subnav" aria-label={t("Recently visited vulnerabilities", "Zuletzt besuchte Schwachstellen")}>
                      {recentVulnerabilities.map((visit) => {
                        const visitPath = `/vulnerability/${encodeURIComponent(visit.id)}`;
                        const isActive = decodeURIComponent(location.pathname) === decodeURIComponent(visitPath);
                        return (
                          <span key={visit.id} className={`sidebar-subnav-link sidebar-recent-item${isActive ? " active" : ""}`}>
                            <Link
                              to={visitPath}
                              className="sidebar-subnav-text"
                              title={visit.title}
                              onClick={handleLinkClick}
                            >
                              {visit.id}
                            </Link>
                            <button
                              type="button"
                              className="sidebar-recent-remove"
                              title={t("Remove", "Entfernen")}
                              aria-label={t("Remove", "Entfernen")}
                              onClick={(e) => { e.stopPropagation(); removeVisit(visit.id); }}
                            >
                              <LuX aria-hidden="true" />
                            </button>
                          </span>
                        );
                      })}
                    </div>
                  )}
                  {isVulnerabilitySection && savedSearches.length > 0 && (
                    <div className="sidebar-subnav" aria-label={t("Saved vulnerability searches", "Gespeicherte Schwachstellen-Suchen")}>
                      {savedSearches.map((saved) => {
                        const savedKey = normalizeSearchParams(saved.queryParams);
                        const isActive = savedKey === currentParamsKey;
                        const searchFragment = saved.queryParams ? `?${saved.queryParams}` : "";
                        return (
                          <Link
                            key={saved.id}
                            to={{
                              pathname: "/vulnerabilities",
                              search: searchFragment,
                            }}
                            className={`sidebar-subnav-link${isActive ? " active" : ""}`}
                            title={saved.name}
                            onClick={(event) => {
                              if (isActive) {
                                event.preventDefault();
                              } else {
                                handleLinkClick();
                              }
                            }}
                          >
                            <span className="sidebar-subnav-text">{saved.name}</span>
                          </Link>
                        );
                      })}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        ))}
      </nav>
      {auth.enabled && (
        <div className="sidebar-user">
          {auth.user ? (
            <>
              {/* The whole row opens the account panel: preferences and signing out. */}
              <button
                type="button"
                className="sidebar-user-who"
                {...triggerProps()}
                title={auth.user.email ?? auth.user.name}
                aria-label={t(`Account and preferences of ${auth.user.name}`, `Konto und Einstellungen von ${auth.user.name}`)}
              >
                <LuUser aria-hidden="true" className="sidebar-user-icon" />
                <span className="sidebar-user-text">
                  <span className="sidebar-user-name">{auth.user.name}</span>
                  <span className="sidebar-user-role">{roleLabel(auth.user.role, t)}</span>
                </span>
              </button>
            </>
          ) : (
            <button
              type="button"
              className="sidebar-user-action sidebar-user-signin"
              onClick={() => auth.signIn()}
              title={t(`Sign in with ${auth.providerLabel}`, `Mit ${auth.providerLabel} anmelden`)}
              aria-label={t("Sign in", "Anmelden")}
            >
              <LuLogIn aria-hidden="true" />
              <span className="sidebar-user-action-label">{t("Sign in", "Anmelden")}</span>
            </button>
          )}
        </div>
      )}
      <div className="sidebar-footer">
        <div className="sidebar-version">{collapsed ? `v${version}` : `Hecate v${version}`}</div>
        {/* Signed in, the account row above opens the same panel. */}
        {!auth.user && (
        <button
          type="button"
          className="sidebar-prefs-button"
          {...triggerProps()}
          title={t("Preferences: language, time, dashboard", "Einstellungen: Sprache, Zeit, Dashboard")}
          aria-label={t("Preferences", "Einstellungen")}
        >
          <span aria-hidden="true" className="sidebar-collapse-icon">
            <LuSlidersHorizontal />
          </span>
          <span className="sidebar-prefs-label">{t("Preferences", "Einstellungen")}</span>
        </button>
        )}
        <button
          type="button"
          className="sidebar-collapse-button"
          onClick={onToggleCollapse}
          aria-pressed={collapsed}
          aria-label={collapsed ? t("Expand sidebar", "Sidebar ausklappen") : t("Collapse sidebar", "Sidebar einklappen")}
        >
          <span aria-hidden="true" className="sidebar-collapse-icon">
            {collapsed ? <LuChevronRight /> : <LuChevronLeft />}
          </span>
          <span className="sidebar-collapse-label">{collapsed ? t("Expand", "Ausklappen") : t("Collapse", "Einklappen")}</span>
        </button>
      </div>
    </aside>
  );
};

const normalizeSearchParams = (raw: string): string => {
  const trimmed = raw.startsWith("?") ? raw.slice(1) : raw;
  if (!trimmed) {
    return "";
  }
  const params = new URLSearchParams(trimmed);
  const entries = Array.from(params.entries());
  return JSON.stringify(entries);
};
