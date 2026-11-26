import { describe, expect, it } from "vitest";

import { placePanel } from "./placement";

const viewport = { width: 1440, height: 900 };
const panel = { width: 320, height: 360 };

describe("placePanel", () => {
  it("opens above a trigger in the lower half, aligned to its left edge", () => {
    const row = { top: 820, bottom: 856, left: 8, right: 224 };
    expect(placePanel(row, panel, viewport)).toEqual({ top: 454, left: 16 });
  });

  it("opens below a trigger in the upper half", () => {
    const link = { top: 60, bottom: 80, left: 400, right: 460 };
    expect(placePanel(link, panel, viewport)).toEqual({ top: 86, left: 400 });
  });

  it("stays inside a narrow viewport", () => {
    const phone = { width: 390, height: 844 };
    const link = { top: 100, bottom: 120, left: 300, right: 350 };
    expect(placePanel(link, panel, phone)).toEqual({ top: 126, left: 54 });
  });

  it("pins to the top edge when it fits nowhere", () => {
    const tiny = { width: 800, height: 300 };
    const row = { top: 250, bottom: 280, left: 8, right: 200 };
    expect(placePanel(row, panel, tiny).top).toBe(16);
  });
});
