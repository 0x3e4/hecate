import { NavLink } from "react-router-dom";

const linkStyle: React.CSSProperties = {
  display: "block",
  padding: "0.75rem 1.25rem",
  borderRadius: "8px",
  color: "rgba(255,255,255,0.85)",
  textDecoration: "none",
  marginBottom: "0.5rem",
  fontWeight: 500
};

export const Sidebar = () => {
  return (
    <aside
      style={{
        width: "260px",
        padding: "2rem 1.5rem",
        background: "#05070d",
        borderRight: "1px solid rgba(255, 255, 255, 0.08)"
      }}
    >
      <nav>
        <NavLink
          to="/"
          style={({ isActive }) => ({
            ...linkStyle,
            backgroundColor: isActive ? "rgba(92,132,255,0.15)" : "transparent"
          })}
        >
          Dashboard
        </NavLink>
        <NavLink
          to="/vulnerabilities/demo"
          style={({ isActive }) => ({
            ...linkStyle,
            backgroundColor: isActive ? "rgba(92,132,255,0.15)" : "transparent"
          })}
        >
          Vulnerability Detail
        </NavLink>
      </nav>
    </aside>
  );
};
