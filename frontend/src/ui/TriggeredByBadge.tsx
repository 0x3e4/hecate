import type { CSSProperties } from "react";

interface Props {
  triggeredBy?: string | null;
  style?: CSSProperties;
}

export const TriggeredByBadge = ({ triggeredBy, style }: Props) => {
  const label = (triggeredBy || "").trim();
  if (!label) return null;
  return (
    <span
      title={label}
      style={{
        fontSize: "0.72rem",
        padding: "0.15rem 0.5rem",
        borderRadius: "4px",
        fontWeight: 500,
        background: "rgba(167,139,250,0.12)",
        color: "#a78bfa",
        border: "1px solid rgba(167,139,250,0.3)",
        whiteSpace: "nowrap",
        ...style,
      }}
    >
      {label}
    </span>
  );
};
