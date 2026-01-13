import { Link, NavLink, useLocation } from "react-router-dom";
import { LuLayoutDashboard, LuShieldAlert, LuWrench, LuBrain, LuLogs, LuFileChartColumnIncreasing, LuHistory, LuSettings, LuChevronLeft, LuChevronRight } from "react-icons/lu";
import { useMemo } from "react";

import { config } from "../config";
import { useSavedSearches } from "../hooks/useSavedSearches";

type SidebarProps = {
  collapsed: boolean;
  onToggleCollapse: () => void;
  mobileMenuOpen?: boolean;
  onMobileMenuClose?: () => void;
};

const navItems = [
  { to: "/", label: "Dashboard", icon: LuLayoutDashboard },
  { to: "/vulnerabilities", label: "Vulnerabilities", icon: LuShieldAlert },
  { to: "/query-builder", label: "Query Builder", icon: LuWrench },
  ...(config.aiFeatures.enabled ? [{ to: "/ai-analyse", label: "AI-Analyse", icon: LuBrain }] : []),
  { to: "/stats", label: "Statistiken", icon: LuFileChartColumnIncreasing },
  { to: "/changelog", label: "Changelog", icon: LuHistory },
  { to: "/audit", label: "Audit Log", icon: LuLogs },
  { to: "/system", label: "System", icon: LuSettings },
];

export const Sidebar = ({ collapsed, onToggleCollapse, mobileMenuOpen, onMobileMenuClose }: SidebarProps) => {
  const { savedSearches } = useSavedSearches();
  const location = useLocation();
  const currentParamsKey = useMemo(() => normalizeSearchParams(location.search), [location.search]);

  const handleLinkClick = () => {
    if (onMobileMenuClose) {
      onMobileMenuClose();
    }
  };

  return (
    <aside className={`app-sidebar${collapsed ? " collapsed" : ""}${mobileMenuOpen ? " mobile-open" : ""}`}>
      <nav className="sidebar-nav">
        {navItems.map((item) => {
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
                <div className="sidebar-subnav" aria-label="Saved vulnerability searches">
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
      </nav>
      <button
        type="button"
        className="sidebar-collapse-button"
        onClick={onToggleCollapse}
        aria-pressed={collapsed}
        aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
      >
        <span aria-hidden="true" className="sidebar-collapse-icon">
          {collapsed ? <LuChevronRight /> : <LuChevronLeft />}
        </span>
        <span className="sidebar-collapse-label">{collapsed ? "Expand" : "Collapse"}</span>
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
