import type { CSSProperties } from "react";

export type SkeletonBlockProps = {
  height: number | string;
  width?: number | string;
  radius?: number;
  style?: CSSProperties;
};

export const SkeletonBlock = ({ height, width = "100%", radius = 8, style }: SkeletonBlockProps) => (
  <div
    className="skeleton"
    style={{ height, width, borderRadius: radius, ...style }}
    aria-hidden="true"
  />
);
