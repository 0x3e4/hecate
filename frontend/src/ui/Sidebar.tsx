import { Link, NavLink, useLocation } from "react-router-dom";
import { LuLayoutDashboard, LuShieldAlert, LuWrench, LuBrain, LuLogs, LuFileChartColumnIncreasing, LuHistory, LuSettings, LuChevronLeft, LuChevronRight, LuScanLine } from "react-icons/lu";
import { useMemo } from "react";

import { config } from "../config";
import { useSavedSearches } from "../hooks/useSavedSearches";
import { useI18n } from "../i18n/context";

type SidebarProps = {
  collapsed: boolean;
  onToggleCollapse: () => void;
  mobileMenuOpen?: boolean;
  onMobileMenuClose?: () => void;
};

type NavItem = { to: string; label: string; icon: typeof LuLayoutDashboard };
type NavSection = { titleEn: string; titleDe: string; items: NavItem[] };

const navSections: NavSection[] = [
  {
    titleEn: "", titleDe: "",
    items: [{ to: "/", label: "Dashboard", icon: LuLayoutDashboard }],
  },
  {
    titleEn: "Vulnerabilities", titleDe: "Schwachstellen",
    items: [
      { to: "/vulnerabilities", label: "Vulnerabilities", icon: LuShieldAlert },
      { to: "/query-builder", label: "Query Builder", icon: LuWrench },
      ...(config.aiFeatures.enabled ? [{ to: "/ai-analyse", label: "AI Analysis", icon: LuBrain }] : []),
      { to: "/changelog", label: "Changelog", icon: LuHistory },
    ],
  },
  ...(config.scaFeatures.enabled ? [{
    titleEn: "Security", titleDe: "Sicherheit",
    items: [
      { to: "/scans", label: "SCA Scans", icon: LuScanLine },
    ],
  }] : []),
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
];

export const Sidebar = ({ collapsed, onToggleCollapse, mobileMenuOpen, onMobileMenuClose }: SidebarProps) => {
  const { t } = useI18n();
  const { savedSearches } = useSavedSearches();
  const location = useLocation();
  const currentParamsKey = useMemo(() => normalizeSearchParams(location.search), [location.search]);
  const germanLabels: Record<string, string> = {
    "/": "Dashboard",
    "/vulnerabilities": "Schwachstellen",
    "/query-builder": "Query-Builder",
    "/ai-analyse": "AI-Analyse",
    "/stats": "Statistiken",
    "/changelog": "Changelog",
    "/audit": "Audit-Log",
    "/scans": "SCA-Scans",
    "/system": "System",
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
                    </span>
                    <span className="sidebar-link-text">{item.label}</span>
                  </NavLink>
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
