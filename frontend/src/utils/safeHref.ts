/**
 * A link target from data, or `undefined` when it is not plain http(s).
 *
 * References, scan findings, repository URLs and feed links come from outside.
 * React blocks `javascript:` but passes `file:`, `search-ms:`, `ms-msdt:` and
 * other handlers that open a local program when clicked. An anchor without an
 * href renders its text and goes nowhere.
 */
export const safeHref = (value: string | null | undefined): string | undefined => {
  if (!value) return undefined;
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:" ? value : undefined;
  } catch {
    return undefined;
  }
};
