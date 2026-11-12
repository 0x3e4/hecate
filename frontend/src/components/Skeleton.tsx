import type { CSSProperties, ReactNode } from "react";
import { useI18n } from "../i18n/context";

/**
 * Placeholders that hold the shape of content still on its way. One family
 * for every screen (see design.md, "Loading"):
 *  - `SkeletonBlock`: one box of a given size.
 *  - `SkeletonText`: a few lines of running text, the last one shorter.
 *  - `SkeletonRows`: rows of a table or list.
 *  - `LoadingRegion`: the wrapper every skeleton group sits in. It announces
 *    the load once to screen readers and only appears after a short delay,
 *    so a fast response never flashes a placeholder.
 */

export type SkeletonBlockProps = {
  height: number | string;
  width?: number | string;
  radius?: number;
  style?: CSSProperties;
};

export const SkeletonBlock = ({ height, width = "100%", radius, style }: SkeletonBlockProps) => (
  <div
    className="skeleton"
    style={{ height, width, ...(radius !== undefined ? { borderRadius: radius } : null), ...style }}
    aria-hidden="true"
  />
);

export const SkeletonText = ({ lines = 3, lastWidth = "60%" }: { lines?: number; lastWidth?: string }) => (
  <div className="skeleton-text" aria-hidden="true">
    {Array.from({ length: lines }, (_, i) => (
      <SkeletonBlock key={i} height="0.9em" width={i === lines - 1 && lines > 1 ? lastWidth : "100%"} />
    ))}
  </div>
);

export const SkeletonRows = ({ rows = 5, height = 28 }: { rows?: number; height?: number | string }) => (
  <div className="skeleton-rows" aria-hidden="true">
    {Array.from({ length: rows }, (_, i) => (
      <SkeletonBlock key={i} height={height} />
    ))}
  </div>
);

export const LoadingRegion = ({
  label,
  children,
  className,
}: {
  /** What is loading, for screen readers. Defaults to "Loading". */
  label?: string;
  children: ReactNode;
  className?: string;
}) => {
  const { t } = useI18n();
  return (
    <div className={`loading-region${className ? ` ${className}` : ""}`} role="status" aria-live="polite">
      <span className="visually-hidden">{label ?? t("Loading", "Wird geladen")}</span>
      {children}
    </div>
  );
};
