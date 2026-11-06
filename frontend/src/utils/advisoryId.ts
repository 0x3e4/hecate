/** Identifier formats Hecate can fetch from its sources (NVD, EUVD, CIRCL, GHSA, OSV). */
const ADVISORY_ID =
  /^(CVE-\d{4}-\d{4,}|GHSA(-[0-9a-z]{4}){3}|MAL-\d{4}-\d+|EUVD-\d{4}-\d+|PYSEC-\d{4}-\d+|GO-\d{4}-\d+|OSV-\d{4}-\d+|RUSTSEC-\d{4}-\d+)$/i;

export const isAdvisoryId = (value: string): boolean => ADVISORY_ID.test(value.trim());

/** The spelling the sources use: upper case, except GHSA's lower-case body. */
export const normalizeAdvisoryId = (value: string): string => {
  const trimmed = value.trim();
  if (/^ghsa-/i.test(trimmed)) return `GHSA-${trimmed.slice(5).toLowerCase()}`;
  return trimmed.toUpperCase();
};
