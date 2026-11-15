import { api } from "./client";
import type { NamedSlug } from "./stats";

export interface CertCve {
  vulnId: string;
  title: string;
  known: boolean;
  severity: string;
  cvssScore: number | null;
  epssScore: number | null;
  exploited: boolean;
  kevListed: boolean;
  dateAdded: string | null;
  dueDate: string | null;
  ransomware: boolean;
  vendorSlugs: string[];
  productSlugs: string[];
  vendors: NamedSlug[];
  products: NamedSlug[];
  inventoryMatchIds: string[];
  /** Latest scan whose SBOM ships a package at a version this CVE affects (backend-checked). */
  sbomScanId?: string | null;
}

/** `cert` and `vendor` feeds count as independent voices; `community` (Mastodon, blogs) is context only. */
export type FeedKind = "cert" | "vendor" | "community";

export const FEED_KINDS: FeedKind[] = ["cert", "vendor", "community"];

export interface FeedSource {
  name: string;
  kind: FeedKind;
}

export interface CertAdvisory {
  feed: string;
  kind: FeedKind;
  title: string | null;
  url: string | null;
  published: string;
}

export interface CertTopic {
  id: string;
  sources: FeedSource[];
  firstSeen: string;
  lastSeen: string;
  worstSeverity: string;
  cves: CertCve[];
  advisories: CertAdvisory[];
  /** Set by narrowToStack: CVEs of the topic left out because they are not in the user's stack. */
  hiddenCves?: number;
}

export interface CertRoundup extends CertAdvisory {
  id: string;
  cveIds: string[];
}

export interface CertOverview {
  since: string;
  days: number;
  topics: CertTopic[];
  roundups: CertRoundup[];
}

export const fetchCertOverview = async (days: number, tz?: string): Promise<CertOverview> => {
  const response = await api.get<CertOverview>("/v1/stats/cert-advisories", { params: { days, ...(tz ? { tz } : {}) } });
  return response.data;
};
