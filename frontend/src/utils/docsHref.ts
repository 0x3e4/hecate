/**
 * Link into the documentation site, or null when no docs URL is configured
 * (`DOCS_URL` empty). `path` is relative to the site root, e.g.
 * "guide/vulnerabilities/#severity-by-source".
 */
export const docsHref = (base: string | null | undefined, path: string): string | null => {
  if (!base) return null;
  return `${base.replace(/\/+$/, "")}/${path.replace(/^\/+/, "")}`;
};
