import type { CSSProperties } from "react";

interface Props {
  triggeredBy?: string | null;
  style?: CSSProperties;
}

export const TriggeredByBadge = ({ triggeredBy, style }: Props) => {
  const label = (triggeredBy || "").trim();
  if (!label) return null;
  return (
    <span className="tag" title={label} style={style}>
      {label}
    </span>
  );
};
