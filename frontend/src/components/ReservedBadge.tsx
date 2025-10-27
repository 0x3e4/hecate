import type { CSSProperties } from "react";

const badgeStyle: CSSProperties = {
  display: "inline-flex",
  alignItems: "center",
  padding: "0.1rem 0.65rem",
  borderRadius: "999px",
  background: "rgba(255, 215, 82, 0.16)",
  color: "#ffe68c",
  fontSize: "0.7rem",
  textTransform: "uppercase",
  letterSpacing: "0.08em",
  border: "1px solid rgba(255, 215, 82, 0.35)",
  fontWeight: 600,
};

interface ReservedBadgeProps {
  label?: string;
}

export const ReservedBadge = ({ label = "Reserved" }: ReservedBadgeProps) => (
  <span style={badgeStyle}>{label}</span>
);
