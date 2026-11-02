import { describe, expect, it } from "vitest";

import type { CertCve, CertRoundup, CertTopic } from "../api/cert";

import { filterTopics, roundupHits, sortTopics, topicProducts, type TopicFilter } from "./certTopics";

const cve = (vulnId: string, product = "PHP"): CertCve => ({
  vulnId,
  title: "",
  known: true,
  severity: "high",
  cvssScore: null,
  epssScore: null,
  exploited: false,
  kevListed: false,
  dateAdded: null,
  dueDate: null,
  ransomware: false,
  vendorSlugs: [],
  productSlugs: [],
  vendors: [{ slug: "acme", name: "Acme" }],
  products: [{ slug: product.toLowerCase(), name: product }],
  inventoryMatchIds: [],
});

const topic = (id: string, overrides: Partial<CertTopic> = {}): CertTopic => ({
  id,
  certs: ["CERT-FR"],
  firstSeen: "2026-10-28T00:00:00+00:00",
  lastSeen: "2026-10-28T00:00:00+00:00",
  worstSeverity: "high",
  cves: [cve("CVE-2026-1")],
  advisories: [{ feed: "CERT-FR", title: "Vulnérabilité dans PHP", url: null, published: "2026-10-28T00:00:00+00:00" }],
  ...overrides,
});

const all: TopicFilter = { search: "", cert: "", severity: "", stackOnly: false };
const none = () => false;
const ids = (topics: CertTopic[]) => topics.map((item) => item.id);

describe("topicProducts", () => {
  it("lists each product once across the CVEs", () => {
    expect(topicProducts(topic("a", { cves: [cve("CVE-1"), cve("CVE-2"), cve("CVE-3", "Nginx")] }))).toEqual(["PHP", "Nginx"]);
  });

  it("treats two spellings of a product as one", () => {
    expect(topicProducts(topic("a", { cves: [cve("CVE-1", "GitLab"), cve("CVE-2", "gitlab")] }))).toEqual(["GitLab"]);
  });
});

describe("filterTopics", () => {
  const topics = [
    topic("php"),
    topic("nginx", { certs: ["CCCS"], worstSeverity: "critical", cves: [cve("CVE-2026-2", "Nginx")], advisories: [] }),
  ];

  it("keeps everything without a filter", () => {
    expect(ids(filterTopics(topics, all, none))).toEqual(["php", "nginx"]);
  });

  it("filters on a CERT", () => {
    expect(ids(filterTopics(topics, { ...all, cert: "CCCS" }, none))).toEqual(["nginx"]);
  });

  it("filters on the worst severity", () => {
    expect(ids(filterTopics(topics, { ...all, severity: "critical" }, none))).toEqual(["nginx"]);
  });

  it("filters on the stack", () => {
    expect(ids(filterTopics(topics, { ...all, stackOnly: true }, (item) => item.id === "php"))).toEqual(["php"]);
  });

  it.each(["cve-2026-2", "nginx", "ACME"])("searches IDs, products and vendors: %s", (search) => {
    expect(ids(filterTopics(topics, { ...all, search }, none))).toContain("nginx");
  });

  it("searches the advisory titles too", () => {
    expect(ids(filterTopics(topics, { ...all, search: "vulnérabilité" }, none))).toEqual(["php"]);
  });
});

describe("sortTopics", () => {
  it("orders by stack, then CERTs, severity and recency", () => {
    const sorted = sortTopics(
      [
        topic("old"),
        topic("new", { lastSeen: "2026-10-30T00:00:00+00:00" }),
        topic("critical", { worstSeverity: "critical" }),
        topic("two-certs", { certs: ["CERT-FR", "CCCS"] }),
        topic("mine"),
      ],
      (item) => item.id === "mine",
    );

    expect(ids(sorted)).toEqual(["mine", "two-certs", "critical", "new", "old"]);
  });

  it("does not change the list it was given", () => {
    const topics = [topic("a"), topic("b", { certs: ["CERT-FR", "CCCS"] })];

    sortTopics(topics, none);

    expect(ids(topics)).toEqual(["a", "b"]);
  });
});

describe("roundupHits", () => {
  it("counts the CVEs found in the scans", () => {
    const roundup = { cveIds: ["CVE-1", "CVE-2", "CVE-3"] } as CertRoundup;

    expect(roundupHits(roundup, { "CVE-1": "scan", "CVE-3": "scan" })).toBe(2);
  });
});
