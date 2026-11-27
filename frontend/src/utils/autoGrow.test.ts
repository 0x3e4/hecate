import { describe, expect, it } from "vitest";

import { type GrowableField, growTextarea, installAutoGrow } from "./autoGrow";

/** A stand-in textarea: 2px of border, content of the given height. */
function field(scrollHeight: number, attrs: string[] = []): GrowableField {
  return {
    tagName: "TEXTAREA",
    style: { height: "" } as CSSStyleDeclaration,
    scrollHeight,
    offsetHeight: 42,
    clientHeight: 40,
    hasAttribute: (name: string) => attrs.includes(name),
  };
}

/** An event whose target is the stand-in, as the browser would deliver it. */
function eventFor(type: string, target: GrowableField): Event {
  const event = new Event(type);
  Object.defineProperty(event, "target", { value: target });
  return event;
}

describe("growTextarea", () => {
  it("takes the content's height plus the borders", () => {
    const ta = field(180);
    growTextarea(ta, 1000);
    expect(ta.style.height).toBe("182px");
  });

  it("stops at 70 % of the window, so a pasted list scrolls", () => {
    const ta = field(5000);
    growTextarea(ta, 1000);
    expect(ta.style.height).toBe("700px");
  });

  it("leaves a field that sizes itself alone", () => {
    const ta = field(180, ["data-own-height"]);
    ta.style.height = "24px";
    growTextarea(ta, 1000);
    expect(ta.style.height).toBe("24px");
  });
});

describe("installAutoGrow", () => {
  it("does nothing where CSS field-sizing works", () => {
    const root = new EventTarget();
    const remove = installAutoGrow(root, true, () => 1000);
    const ta = field(300);
    root.dispatchEvent(eventFor("input", ta));
    expect(ta.style.height).toBe("");
    remove();
  });

  it("grows a field on input and on focus, ignores other elements, and can be removed", () => {
    const root = new EventTarget();
    const remove = installAutoGrow(root, false, () => 1000);
    const ta = field(300);
    root.dispatchEvent(eventFor("input", ta));
    expect(ta.style.height).toBe("302px");

    const input = { ...field(300), tagName: "INPUT" };
    root.dispatchEvent(eventFor("input", input));
    expect(input.style.height).toBe("");

    ta.style.height = "";
    root.dispatchEvent(eventFor("focusin", ta));
    expect(ta.style.height).toBe("302px");

    remove();
    ta.style.height = "";
    root.dispatchEvent(eventFor("input", ta));
    expect(ta.style.height).toBe("");
  });
});
