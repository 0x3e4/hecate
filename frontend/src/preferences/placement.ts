/**
 * Where the preferences panel opens: next to whatever opened it, inside the
 * viewport. Above the trigger when it sits in the lower half (the sidebar's
 * account row), below it otherwise (the dashboard's "Change"). CSS anchor
 * positioning would do this, but is not in every supported browser yet.
 */
export interface Box {
  top: number;
  left: number;
  bottom: number;
  right: number;
}

const GAP = 6;
const EDGE = 16;

export const placePanel = (
  anchor: Box,
  panel: { width: number; height: number },
  viewport: { width: number; height: number },
): { top: number; left: number } => {
  const fitsAbove = anchor.top - GAP - panel.height >= EDGE;
  const fitsBelow = anchor.bottom + GAP + panel.height <= viewport.height - EDGE;
  const preferAbove = anchor.top > viewport.height / 2;
  const above = anchor.top - GAP - panel.height;
  const below = anchor.bottom + GAP;
  let top: number;
  if (preferAbove) top = fitsAbove ? above : fitsBelow ? below : EDGE;
  else top = fitsBelow ? below : fitsAbove ? above : EDGE;
  const maxLeft = viewport.width - panel.width - EDGE;
  const left = Math.max(EDGE, Math.min(anchor.left, maxLeft));
  return { top: Math.max(EDGE, Math.round(top)), left: Math.round(left) };
};
