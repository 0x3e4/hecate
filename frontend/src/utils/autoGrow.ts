/**
 * Multi-line fields grow with what is typed or pasted. styles.css does it with
 * `field-sizing: content`; this is the same for browsers without it (Firefox,
 * older Safari), as one listener on the document instead of a hook per field.
 * A field that sets its own height carries `data-own-height` and is left alone.
 */

/** The share of the window a field may take before it scrolls (matches max-block-size: 70vh). */
export const MAX_VIEWPORT_SHARE = 0.7;

/** The parts of a textarea this needs, so it runs on a stand-in in tests. */
export type GrowableField = Pick<HTMLTextAreaElement, "tagName" | "style" | "scrollHeight" | "offsetHeight" | "clientHeight" | "hasAttribute">;

function isTextarea(target: unknown): target is GrowableField {
  return typeof target === "object" && target !== null && (target as { tagName?: unknown }).tagName === "TEXTAREA";
}

export function growTextarea(ta: GrowableField, viewportHeight: number = window.innerHeight): void {
  if (ta.hasAttribute("data-own-height")) return;
  // "auto" first, so the field can also shrink; rows and min-height keep the floor.
  ta.style.height = "auto";
  const borders = ta.offsetHeight - ta.clientHeight;
  ta.style.height = `${Math.min(ta.scrollHeight + borders, viewportHeight * MAX_VIEWPORT_SHARE)}px`;
}

export function supportsFieldSizing(): boolean {
  return typeof CSS !== "undefined" && typeof CSS.supports === "function" && CSS.supports("field-sizing", "content");
}

/** Installs the fallback where CSS can't do it; returns a function that removes it again. */
export function installAutoGrow(
  root: EventTarget = document,
  supported: boolean = supportsFieldSizing(),
  viewportHeight: () => number = () => window.innerHeight,
): () => void {
  if (supported) return () => {};
  const onEvent = (event: Event) => {
    if (isTextarea(event.target)) growTextarea(event.target, viewportHeight());
  };
  // input covers typing and pasting; focusin catches a field the app filled in (an edit form).
  root.addEventListener("input", onEvent);
  root.addEventListener("focusin", onEvent);
  return () => {
    root.removeEventListener("input", onEvent);
    root.removeEventListener("focusin", onEvent);
  };
}
