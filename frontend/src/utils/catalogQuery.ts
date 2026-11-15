/**
 * Links from a catalogue vendor or product to the vulnerability list.
 *
 * The list reads `?search=…&mode=dql`; `vendorSlugs` / `productSlugs` are exact-match
 * fields (routed to the keyword path even on a drifted index), so the list returns
 * exactly the vulnerabilities a slug-based count on the Statistics page counted.
 * The same shape as the Dashboard's facet links.
 */
export type CatalogKind = "vendor" | "product";

/** A DQL phrase: backslash, quote and the regex slash escaped. */
export const dqlPhrase = (value: string): string => `"${value.replace(/[\\"/]/g, (char) => `\\${char}`)}"`;

export const catalogQuery = (kind: CatalogKind, slug: string): string =>
  `${kind === "vendor" ? "vendorSlugs" : "productSlugs"}:${dqlPhrase(slug)}`;

export const catalogQueryHref = (kind: CatalogKind, slug: string): string =>
  `/vulnerabilities?search=${encodeURIComponent(catalogQuery(kind, slug))}&mode=dql`;
