import { describe, expect, it } from "vitest";
import {
  clampWindow,
  fullWindow,
  indexToPixel,
  isFullWindow,
  lastNWindow,
  pixelToIndex,
  selectionToWindow,
  sliceWindow,
  tickIndices,
  windowSize,
} from "./timeZoom";

// 31 points over a 300px plot starting at x=50: one point every 10px.
const plot = { left: 50, width: 300 };
const all = fullWindow(31);

describe("fullWindow / isFullWindow", () => {
  it("covers the series", () => {
    expect(all).toEqual({ start: 0, end: 30 });
    expect(windowSize(all)).toBe(31);
    expect(isFullWindow(null, 31)).toBe(true);
    expect(isFullWindow(all, 31)).toBe(true);
    expect(isFullWindow({ start: 1, end: 30 }, 31)).toBe(false);
  });

  it("treats an empty series as a single slot", () => {
    expect(fullWindow(0)).toEqual({ start: 0, end: 0 });
  });
});

describe("pixel mapping", () => {
  it("maps indices to pixels and back in the full window", () => {
    expect(indexToPixel(0, plot, all)).toBe(50);
    expect(indexToPixel(30, plot, all)).toBe(350);
    expect(indexToPixel(15, plot, all)).toBe(200);
    expect(pixelToIndex(200, plot, all)).toBe(15);
    expect(pixelToIndex(204, plot, all)).toBe(15);
    expect(pixelToIndex(206, plot, all)).toBe(16);
  });

  it("clamps the crosshair to the window", () => {
    expect(pixelToIndex(-100, plot, all)).toBe(0);
    expect(pixelToIndex(1000, plot, all)).toBe(30);
  });

  it("maps in full-series indices inside a zoomed window", () => {
    const win = { start: 10, end: 20 }; // 10 steps over 300px: 30px each
    expect(indexToPixel(10, plot, win)).toBe(50);
    expect(indexToPixel(20, plot, win)).toBe(350);
    expect(pixelToIndex(110, plot, win)).toBe(12);
  });

  it("centres a single-point window", () => {
    const win = { start: 4, end: 4 };
    expect(indexToPixel(4, plot, win)).toBe(200);
    expect(pixelToIndex(60, plot, win)).toBe(4);
  });
});

describe("selectionToWindow", () => {
  it("selects the points inside the band, in either drag direction", () => {
    expect(selectionToWindow(95, 155, plot, all)).toEqual({ start: 5, end: 10 });
    expect(selectionToWindow(155, 95, plot, all)).toEqual({ start: 5, end: 10 });
  });

  it("includes a point the band edge lands on exactly", () => {
    expect(selectionToWindow(100, 150, plot, all)).toEqual({ start: 5, end: 10 });
  });

  it("ignores a drag that holds fewer than two points (a tap keeps the tooltip)", () => {
    expect(selectionToWindow(101, 109, plot, all)).toBeNull();
    expect(selectionToWindow(98, 102, plot, all)).toBeNull();
    expect(selectionToWindow(98, 112, plot, all)).toEqual({ start: 5, end: 6 });
  });

  it("honours a larger minimum", () => {
    expect(selectionToWindow(98, 112, plot, all, 3)).toBeNull();
    expect(selectionToWindow(98, 122, plot, all, 3)).toEqual({ start: 5, end: 7 });
  });

  it("clamps a band dragged past the plot edges", () => {
    expect(selectionToWindow(-40, 75, plot, all)).toEqual({ start: 0, end: 2 });
    expect(selectionToWindow(320, 900, plot, all)).toEqual({ start: 27, end: 30 });
  });

  it("zooms further in from a zoomed window", () => {
    const win = { start: 10, end: 20 };
    expect(selectionToWindow(80, 170, plot, win)).toEqual({ start: 11, end: 14 });
  });

  it("cannot zoom past a two-point window", () => {
    const win = { start: 3, end: 4 };
    expect(selectionToWindow(50, 350, plot, win)).toEqual({ start: 3, end: 4 });
    expect(selectionToWindow(60, 340, plot, win)).toBeNull();
  });
});

describe("clampWindow", () => {
  it("keeps a window inside the series", () => {
    expect(clampWindow({ start: -5, end: 50 }, 31)).toEqual({ start: 0, end: 30 });
  });

  it("orders swapped bounds", () => {
    expect(clampWindow({ start: 12, end: 8 }, 31)).toEqual({ start: 8, end: 12 });
  });

  it("widens a too-small window, towards the end first", () => {
    expect(clampWindow({ start: 5, end: 5 }, 31, 3)).toEqual({ start: 5, end: 7 });
    expect(clampWindow({ start: 30, end: 30 }, 31, 3)).toEqual({ start: 28, end: 30 });
  });

  it("refits a window after the series shrinks (a refetch)", () => {
    expect(clampWindow({ start: 25, end: 40 }, 20)).toEqual({ start: 18, end: 19 });
  });

  it("never asks for more points than the series has", () => {
    expect(clampWindow({ start: 0, end: 0 }, 1, 5)).toEqual({ start: 0, end: 0 });
    expect(clampWindow({ start: 0, end: 0 }, 0)).toEqual({ start: 0, end: 0 });
  });
});

describe("lastNWindow / sliceWindow", () => {
  it("takes the most recent points", () => {
    expect(lastNWindow(31, 7)).toEqual({ start: 24, end: 30 });
    expect(lastNWindow(5, 7)).toEqual({ start: 0, end: 4 });
  });

  it("slices inclusively", () => {
    expect(sliceWindow([0, 1, 2, 3, 4, 5], { start: 2, end: 4 })).toEqual([2, 3, 4]);
  });
});

describe("tickIndices", () => {
  it("spreads ticks evenly, first and last included", () => {
    expect(tickIndices(all, 4)).toEqual([0, 10, 20, 30]);
    expect(tickIndices({ start: 10, end: 20 }, 3)).toEqual([10, 15, 20]);
  });

  it("never repeats an index or exceeds the window", () => {
    expect(tickIndices({ start: 3, end: 4 }, 8)).toEqual([3, 4]);
    expect(tickIndices({ start: 7, end: 7 }, 8)).toEqual([7]);
  });
});
