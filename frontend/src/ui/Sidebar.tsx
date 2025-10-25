import { NavLink } from "react-router-dom";
import { LuLayoutDashboard, LuShieldAlert, LuLogs, LuFileChartColumnIncreasing, LuSettings } from "react-icons/lu";

type SidebarProps = {
  collapsed: boolean;
  onToggleCollapse: () => void;
};

const navItems = [
  { to: "/", label: "Dashboard", shortLabel: LuLayoutDashboard },
  { to: "/vulnerabilities", label: "Vulnerabilities", shortLabel: LuShieldAlert },
  { to: "/audit", label: "Audit Log", shortLabel: LuLogs },
  { to: "/stats", label: "Statistiken", shortLabel: LuFileChartColumnIncreasing },
  { to: "/system", label: "System", shortLabel: LuSettings },
];

export const Sidebar = ({ collapsed, onToggleCollapse }: SidebarProps) => {
  return (
    <aside className={`app-sidebar${collapsed ? " collapsed" : ""}`}>
      <nav className="sidebar-nav">
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            title={item.label}
            aria-label={item.label}
            className={({ isActive }) =>
              `sidebar-link${isActive ? " active" : ""}`
            }
          >
            <span className="sidebar-link-short">{item.shortLabel}</span>
            <span className="sidebar-link-text">{item.label}</span>
          </NavLink>
        ))}
      </nav>
      <button
        type="button"
        className="sidebar-collapse-button"
        onClick={onToggleCollapse}
        aria-pressed={collapsed}
        aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
      >
        <span aria-hidden="true" className="sidebar-collapse-icon">
          {collapsed ? "⮞" : "⮜"}
        </span>
        <span className="sidebar-collapse-label">{collapsed ? "Expand" : "Collapse"}</span>
      </button>
    </aside>
  );
};
