import { describe, expect, it } from "vitest";

import type { CertAdvisory, CertCve, CertRoundup, CertTopic, FeedSource } from "../api/cert";

import { applyKinds, filterTopics, kindCounts, roundupHits, sortTopics, topicProducts, voices, type TopicFilter } from "./certTopics";

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

const cert = (name: string): FeedSource => ({ name, kind: "cert" });

const advisory = (feed: string, kind: CertAdvisory["kind"], published = "2026-10-28T00:00:00+00:00"): CertAdvisory => ({
  feed,
  kind,
  title: `${feed} post`,
  url: null,
  published,
});

const topic = (id: string, overrides: Partial<CertTopic> = {}): CertTopic => ({
  id,
  sources: [cert("CERT-FR")],
  firstSeen: "2026-10-28T00:00:00+00:00",
  lastSeen: "2026-10-28T00:00:00+00:00",
  worstSeverity: "high",
  cves: [cve("CVE-2026-1")],
  advisories: [{ feed: "CERT-FR", kind: "cert", title: "Vulnérabilité dans PHP", url: null, published: "2026-10-28T00:00:00+00:00" }],
  ...overrides,
});

const all: TopicFilter = { search: "", source: "", severity: "", stackOnly: false };
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
    topic("nginx", { sources: [cert("CCCS")], worstSeverity: "critical", cves: [cve("CVE-2026-2", "Nginx")], advisories: [] }),
  ];

  it("keeps everything without a filter", () => {
    expect(ids(filterTopics(topics, all, none))).toEqual(["php", "nginx"]);
  });

  it("filters on a source", () => {
    expect(ids(filterTopics(topics, { ...all, source: "CCCS" }, none))).toEqual(["nginx"]);
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
  it("orders by stack, then CERTs and vendors, community, severity and recency", () => {
    const sorted = sortTopics(
      [
        topic("old"),
        topic("new", { lastSeen: "2026-10-30T00:00:00+00:00" }),
        topic("critical", { worstSeverity: "critical" }),
        topic("two-certs", { sources: [cert("CERT-FR"), cert("CCCS")] }),
        topic("discussed", { sources: [cert("CERT-FR"), { name: "@a", kind: "community" }, { name: "@b", kind: "community" }] }),
        topic("mine"),
      ],
      (item) => item.id === "mine",
    );

    expect(ids(sorted)).toEqual(["mine", "two-certs", "discussed", "critical", "new", "old"]);
  });

  it("does not change the list it was given", () => {
    const topics = [topic("a"), topic("b", { sources: [cert("CERT-FR"), cert("CCCS")] })];

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

describe("applyKinds", () => {
  const mixed = topic("mixed", {
    sources: [{ name: "@a", kind: "community" }, cert("CERT-FR")],
    advisories: [advisory("@a", "community", "2026-10-30T00:00:00+00:00"), advisory("CERT-FR", "cert")],
    lastSeen: "2026-10-30T00:00:00+00:00",
  });
  const chatter = topic("chatter", { sources: [{ name: "@b", kind: "community" }], advisories: [advisory("@b", "community")] });

  it("hides community posts but keeps the topic they joined", () => {
    const [shown, ...rest] = applyKinds([mixed, chatter], ["cert", "vendor"]);

    expect(rest).toEqual([]);
    expect(shown.advisories.map((item) => item.feed)).toEqual(["CERT-FR"]);
    expect(shown.sources).toEqual([cert("CERT-FR")]);
    expect(shown.lastSeen).toBe("2026-10-28T00:00:00+00:00");
    expect(shown.cves).toBe(mixed.cves);
  });

  it("returns a topic unchanged when every advisory is shown", () => {
    expect(applyKinds([mixed], ["cert", "vendor", "community"])[0]).toBe(mixed);
  });

  it("counts topics and round-ups per kind", () => {
    const roundup = { ...advisory("Cloudflare", "vendor"), id: "r", cveIds: [] } as CertRoundup;

    expect(kindCounts([mixed, chatter], [roundup])).toEqual({ cert: 1, vendor: 1, community: 2 });
  });
});

describe("voices", () => {
  it("counts CERTs and vendors, not community posts", () => {
    expect(voices(topic("a", { sources: [cert("CERT-FR"), { name: "Cloudflare", kind: "vendor" }, { name: "@a", kind: "community" }] }))).toBe(2);
  });
});
