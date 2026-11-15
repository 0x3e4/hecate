/**
 * Pure geometry for the zoomable time-series charts on the Statistics page.
 *
 * A window is an inclusive index range into the full series. The plot maps the
 * window's first point to `plot.left` and its last to `plot.left + plot.width`,
 * so every helper takes the current window: a drag inside a zoomed chart
 * selects in full-series indices and zooms further in.
 */

export interface ZoomWindow {
  /** First visible index, inclusive. */
  start: number;
  /** Last visible index, inclusive. */
  end: number;
}

export interface PlotBox {
  left: number;
  width: number;
}

/** The whole series; an empty series yields `{0, 0}`. */
export const fullWindow = (length: number): ZoomWindow => ({ start: 0, end: Math.max(0, length - 1) });

export const windowSize = (win: ZoomWindow): number => win.end - win.start + 1;

export const isFullWindow = (win: ZoomWindow | null, length: number): boolean =>
  win == null || (win.start <= 0 && win.end >= length - 1);

/**
 * Keeps a window inside the series and at least `minPoints` wide (fewer only
 * when the series itself is shorter). Growth happens towards the end first,
 * then towards the start, so a window at the right edge stays there.
 */
export const clampWindow = (win: ZoomWindow, length: number, minPoints = 2): ZoomWindow => {
  if (length <= 0) return { start: 0, end: 0 };
  const last = length - 1;
  let start = Math.max(0, Math.min(last, Math.round(Math.min(win.start, win.end))));
  let end = Math.max(0, Math.min(last, Math.round(Math.max(win.start, win.end))));
  const need = Math.min(Math.max(1, minPoints), length);
  if (end - start + 1 < need) {
    end = Math.min(last, start + need - 1);
    start = Math.max(0, end - need + 1);
  }
  return { start, end };
};

/** Fractional full-series index under a plot x coordinate, not rounded or clamped. */
const fractionalIndex = (x: number, plot: PlotBox, win: ZoomWindow): number => {
  const span = win.end - win.start;
  if (span <= 0 || plot.width <= 0) return win.start;
  return win.start + ((x - plot.left) / plot.width) * span;
};

/** x coordinate of a full-series index in the current window (centre of the plot for a single point). */
export const indexToPixel = (index: number, plot: PlotBox, win: ZoomWindow): number => {
  const span = win.end - win.start;
  if (span <= 0) return plot.left + plot.width / 2;
  return plot.left + ((index - win.start) / span) * plot.width;
};

/** Nearest full-series index to a plot x coordinate, clamped to the window (the crosshair snap). */
export const pixelToIndex = (x: number, plot: PlotBox, win: ZoomWindow): number => {
  const index = Math.round(fractionalIndex(x, plot, win));
  return Math.max(win.start, Math.min(win.end, index));
};

/**
 * The window a drag from `x1` to `x2` selects: the points whose x lies inside
 * the band. Returns `null` when the band holds fewer than `minPoints` points,
 * so a tap or a small wobble keeps the tooltip instead of zooming.
 */
export const selectionToWindow = (
  x1: number,
  x2: number,
  plot: PlotBox,
  win: ZoomWindow,
  minPoints = 2
): ZoomWindow | null => {
  const lo = fractionalIndex(Math.min(x1, x2), plot, win);
  const hi = fractionalIndex(Math.max(x1, x2), plot, win);
  // A tiny epsilon so a band edge that lands exactly on a point (float noise) includes it.
  const start = Math.max(win.start, Math.ceil(lo - 1e-9));
  const end = Math.min(win.end, Math.floor(hi + 1e-9));
  if (end - start + 1 < Math.max(2, minPoints)) return null;
  return { start, end };
};

/** The last `points` entries of a series, e.g. the "7 d" preset. */
export const lastNWindow = (length: number, points: number): ZoomWindow =>
  clampWindow({ start: length - points, end: length - 1 }, length, 1);

/** The visible slice of a series. */
export const sliceWindow = <T>(data: readonly T[], win: ZoomWindow): T[] => data.slice(win.start, win.end + 1);

/**
 * Evenly spaced tick indices across a window, first and last included,
 * at most `maxTicks` of them and never the same index twice.
 */
export const tickIndices = (win: ZoomWindow, maxTicks: number): number[] => {
  const size = windowSize(win);
  const count = Math.max(1, Math.min(Math.floor(maxTicks), size));
  if (count === 1) return [win.start];
  const out: number[] = [];
  for (let i = 0; i < count; i += 1) {
    const index = win.start + Math.round((i * (size - 1)) / (count - 1));
    if (out[out.length - 1] !== index) out.push(index);
  }
  return out;
};
