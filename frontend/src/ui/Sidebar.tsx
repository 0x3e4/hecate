import { NavLink } from "react-router-dom";
import { LuLayoutDashboard, LuShieldAlert, LuLogs, LuFileChartColumnIncreasing, LuSettings } from "react-icons/lu";

type SidebarProps = {
  collapsed: boolean;
  onToggleCollapse: () => void;
};

const navItems = [
  { to: "/", label: "Dashboard", icon: LuLayoutDashboard },
  { to: "/vulnerabilities", label: "Vulnerabilities", icon: LuShieldAlert },
  { to: "/audit", label: "Audit Log", icon: LuLogs },
  { to: "/stats", label: "Statistiken", icon: LuFileChartColumnIncreasing },
  { to: "/system", label: "System", icon: LuSettings },
];

export const Sidebar = ({ collapsed, onToggleCollapse }: SidebarProps) => {
  return (
    <aside className={`app-sidebar${collapsed ? " collapsed" : ""}`}>
      <nav className="sidebar-nav">
        {navItems.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.to}
              to={item.to}
              title={item.label}
              aria-label={item.label}
              className={({ isActive }) =>
                `sidebar-link${isActive ? " active" : ""}`
              }
            >
              <span className="sidebar-link-short">
                <Icon aria-hidden="true" focusable="false" />
              </span>
              <span className="sidebar-link-text">{item.label}</span>
            </NavLink>
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
          {collapsed ? "⮞" : "⮜"}
        </span>
        <span className="sidebar-collapse-label">{collapsed ? "Expand" : "Collapse"}</span>
      </button>
    </aside>
  );
};
