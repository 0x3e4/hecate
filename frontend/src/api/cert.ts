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
}

export interface CertAdvisory {
  feed: string;
  title: string | null;
  url: string | null;
  published: string;
}

export interface CertTopic {
  id: string;
  certs: string[];
  firstSeen: string;
  lastSeen: string;
  worstSeverity: string;
  cves: CertCve[];
  advisories: CertAdvisory[];
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
