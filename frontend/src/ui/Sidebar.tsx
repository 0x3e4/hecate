import { Link, NavLink, useLocation } from "react-router-dom";
import { LuLayoutDashboard, LuShieldAlert, LuWrench, LuBrain, LuLogs, LuFileChartColumnIncreasing, LuHistory, LuSettings, LuChevronLeft, LuChevronRight, LuScanLine, LuX, LuBookOpen, LuBox } from "react-icons/lu";
import { useEffect, useMemo, useState } from "react";

import { version } from "../../package.json";
import { useSavedSearches } from "../hooks/useSavedSearches";
import { useRecentlyVisited } from "../hooks/useRecentlyVisited";
import { useI18n } from "../i18n/context";
import { useSSE } from "../hooks/useSSE";
import { useServerConfig } from "../server-config/context";
import { api } from "../api/client";

type SidebarProps = {
  collapsed: boolean;
  onToggleCollapse: () => void;
  mobileMenuOpen?: boolean;
  onMobileMenuClose?: () => void;
};

type NavItem = { to: string; label: string; icon: typeof LuLayoutDashboard };
type NavSection = { titleEn: string; titleDe: string; items: NavItem[] };

const buildNavSections = (aiEnabled: boolean, scaEnabled: boolean): NavSection[] => [
  {
    titleEn: "", titleDe: "",
    items: [{ to: "/", label: "Dashboard", icon: LuLayoutDashboard }],
  },
  {
    titleEn: "Vulnerabilities", titleDe: "Schwachstellen",
    items: [
      { to: "/vulnerabilities", label: "Vulnerabilities", icon: LuShieldAlert },
      { to: "/query-builder", label: "Query Builder", icon: LuWrench },
      ...(aiEnabled ? [{ to: "/ai-analyse", label: "AI Analysis", icon: LuBrain }] : []),
      { to: "/changelog", label: "Changelog", icon: LuHistory },
    ],
  },
  ...(scaEnabled ? [{
    titleEn: "Security", titleDe: "Sicherheit",
    items: [
      { to: "/scans", label: "SCA Scans", icon: LuScanLine },
      { to: "/malware-feed", label: "Malware Feed", icon: LuShieldAlert },
    ],
  }] : []),
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
      { to: "/audit", label: "Audit Log", icon: LuLogs },
    ],
  },
  {
    titleEn: "Administration", titleDe: "Verwaltung",
    items: [{ to: "/system", label: "System", icon: LuSettings }],
  },
  ...(scaEnabled ? [{
    titleEn: "Info", titleDe: "Info",
    items: [
      { to: "/info/cicd", label: "CI/CD", icon: LuBookOpen },
      { to: "/info/api", label: "API", icon: LuBookOpen },
      { to: "/info/mcp", label: "MCP", icon: LuBookOpen },
    ],
  }] : []),
];

export const Sidebar = ({ collapsed, onToggleCollapse, mobileMenuOpen, onMobileMenuClose }: SidebarProps) => {
  const { t } = useI18n();
  const { savedSearches } = useSavedSearches();
  const { recentVulnerabilities, removeVisit } = useRecentlyVisited();
  const location = useLocation();
  const currentParamsKey = useMemo(() => normalizeSearchParams(location.search), [location.search]);
  const { jobs } = useSSE();
  const { aiEnabled, scaEnabled } = useServerConfig();
  const navSections = useMemo(
    () => buildNavSections(aiEnabled, scaEnabled),
    [aiEnabled, scaEnabled]
  );

  const aiRunning = useMemo(() => {
    for (const [name, job] of jobs) {
      if (name.startsWith("ai_investigation_") || name === "ai_batch_investigation") {
        if (job.status === "running") return true;
      }
    }
    return false;
  }, [jobs]);

  const scaRunningSSE = useMemo(() => {
    for (const [name, job] of jobs) {
      if (name.startsWith("sca_scan_")) {
        if (job.status === "running") return true;
      }
    }
    return false;
  }, [jobs]);

  // Also poll for running scans to catch scans started before SSE connected
  const [scaRunningPoll, setScaRunningPoll] = useState(false);
  useEffect(() => {
    if (!scaEnabled) return;
    let cancelled = false;
    const check = async () => {
      try {
        const resp = await api.get<{ total: number }>("/v1/scans", { params: { status: "running", limit: 1 } });
        if (!cancelled) {
          setScaRunningPoll(resp.data.total > 0);
        }
      } catch { /* ignore */ }
    };
    check();
    const interval = setInterval(check, 10000);
    return () => { cancelled = true; clearInterval(interval); };
  }, [scaEnabled]);

  const scaRunning = scaRunningSSE || scaRunningPoll;
  const germanLabels: Record<string, string> = {
    "/": "Dashboard",
    "/vulnerabilities": "Schwachstellen",
    "/query-builder": "Query-Builder",
    "/ai-analyse": "AI-Analyse",
    "/stats": "Statistiken",
    "/changelog": "Changelog",
    "/audit": "Audit-Log",
    "/inventory": "Inventar",
    "/scans": "SCA-Scans",
    "/malware-feed": "Malware-Feed",
    "/system": "System",
    "/info/api": "API",
    "/info/cicd": "CI/CD",
    "/info/mcp": "MCP",
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

  const handleLinkClick = () => {
    if (onMobileMenuClose) {
      onMobileMenuClose();
    }
  };

  return (
    <aside className={`app-sidebar${collapsed ? " collapsed" : ""}${mobileMenuOpen ? " mobile-open" : ""}`}>
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
                  <NavLink
                    to={item.to}
                    title={item.label}
                    aria-label={item.label}
                    className={({ isActive }) =>
                      `sidebar-link${isActive ? " active" : ""}`
                    }
                    onClick={handleLinkClick}
                  >
                    <span className="sidebar-link-short">
                      <Icon aria-hidden="true" focusable="false" />
                      {item.to === "/ai-analyse" && aiRunning && <span className="sidebar-pulse" />}
                      {item.to === "/scans" && scaRunning && <span className="sidebar-pulse" />}
                    </span>
                    <span className="sidebar-link-text">{item.label}</span>
                    {item.to === "/ai-analyse" && aiRunning && <span className="sidebar-pulse" />}
                    {item.to === "/scans" && scaRunning && <span className="sidebar-pulse" />}
                  </NavLink>
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
                              onClick={(e) => { e.stopPropagation(); removeVisit(visit.id); }}
                            >
                              <LuX />
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
      <div className="sidebar-version">{collapsed ? `v${version}` : `Hecate v${version}`}</div>
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
