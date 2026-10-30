import type { CSSProperties, ReactNode } from "react";

/** Shared tab-button style used by the scan and vulnerability detail pages. */
export const tabPillStyle = (active: boolean): CSSProperties => ({
  minHeight: "var(--control-height)",
  padding: "0 var(--space-sm)",
  border: 0,
  borderBottom: `2px solid ${active ? "var(--color-accent)" : "transparent"}`,
  borderRadius: 0,
  background: "transparent",
  color: active ? "var(--color-ink)" : "var(--color-muted)",
  cursor: "pointer",
  fontSize: "var(--text-sm)",
  fontWeight: active ? 600 : 400,
  display: "inline-flex",
  alignItems: "center",
  gap: "var(--space-xs)",
});

/** Small numeric badge that sits next to a tab label. */
export const TabBadge = ({ count }: { count: number | undefined | null }) => {
  if (count === null || count === undefined) return null;
  return (
    <span
      style={{
        color: "var(--color-muted)",
        fontSize: "var(--text-xs)",
        fontVariantNumeric: "tabular-nums",
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
    <button type="button" onClick={onClick} style={merged} aria-current={active ? "true" : undefined}>
      {children}
      <TabBadge count={count ?? undefined} />
    </button>
  );
};
