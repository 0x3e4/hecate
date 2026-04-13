import type { CSSProperties, ReactNode } from "react";

/** Shared tab-button style used by the scan and vulnerability detail pages. */
export const tabPillStyle = (active: boolean): CSSProperties => ({
  padding: "0.375rem 0.875rem",
  borderRadius: "6px",
  border: active ? "1px solid rgba(255,193,7,0.5)" : "1px solid rgba(255,255,255,0.1)",
  background: active ? "rgba(255,193,7,0.15)" : "transparent",
  color: active ? "#ffd43b" : "rgba(255,255,255,0.6)",
  cursor: "pointer",
  fontSize: "0.8125rem",
  fontWeight: 500,
  display: "inline-flex",
  alignItems: "center",
  gap: "0.4rem",
});

/** Small numeric badge that sits next to a tab label. */
export const TabBadge = ({ count }: { count: number | undefined | null }) => {
  if (count === null || count === undefined) return null;
  return (
    <span
      style={{
        fontSize: "0.72rem",
        padding: "0.1rem 0.4rem",
        borderRadius: "4px",
        background: "rgba(255,255,255,0.1)",
        color: "#ffffff",
        fontWeight: 600,
        minWidth: "1.1rem",
        textAlign: "center",
      }}
    >
      {count}
    </span>
  );
};

interface TabPillProps {
  active: boolean;
  onClick: () => void;
  count?: number | null;
  accent?: { active: CSSProperties; idle: CSSProperties };
  children: ReactNode;
}

/** Shared tab-button component used by detail pages. */
export const TabPill = ({ active, onClick, count, accent, children }: TabPillProps) => {
  const base = tabPillStyle(active);
  const merged: CSSProperties = accent
    ? { ...base, ...(active ? accent.active : accent.idle) }
    : base;
  return (
    <button type="button" onClick={onClick} style={merged}>
      {children}
      <TabBadge count={count ?? undefined} />
    </button>
  );
};
