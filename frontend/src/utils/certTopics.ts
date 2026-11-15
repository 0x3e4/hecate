import type { CertAdvisory, CertCve, CertRoundup, CertTopic, FeedKind, FeedSource } from "../api/cert";
import type { TranslateFn } from "../i18n/context";

import { severityRank } from "./cveGroups";

export interface TopicFilter {
  search: string;
  source: string;
  severity: string;
  stackOnly: boolean;
}

export const feedKindLabel = (kind: FeedKind, t: TranslateFn): string =>
  kind === "vendor" ? t("Vendor", "Hersteller") : kind === "community" ? t("Community", "Community") : "CERT";

/** CERTs and vendors speak for themselves; a community post is context and never counts as agreement. */
export const isVoice = (source: { kind?: FeedKind | string }): boolean => source.kind !== "community";

export const voices = (topic: CertTopic): number => topic.sources.filter(isVoice).length;

const sourcesOf = (advisories: CertAdvisory[]): FeedSource[] => {
  const byName = new Map<string, FeedSource>();
  for (const advisory of advisories) {
    if (!byName.has(advisory.feed)) byName.set(advisory.feed, { name: advisory.feed, kind: advisory.kind });
  }
  return [...byName.values()];
};

/**
 * Keeps only the advisories of the shown kinds. A topic's CVEs come from its CERT and
 * vendor advisories (community posts join without adding any), so hiding the posts
 * leaves them as they are; a topic with nothing left is dropped.
 */
export const applyKinds = (topics: CertTopic[], kinds: FeedKind[]): CertTopic[] =>
  topics.flatMap((topic) => {
    const advisories = topic.advisories.filter((advisory) => kinds.includes(advisory.kind));
    if (advisories.length === 0) return [];
    if (advisories.length === topic.advisories.length) return [topic];
    const published = advisories.map((advisory) => advisory.published).sort();
    return [
      {
        ...topic,
        advisories,
        sources: sourcesOf(advisories),
        firstSeen: published[0],
        lastSeen: published[published.length - 1],
      },
    ];
  });

/** How many topics and round-ups each kind contributes, for the counts on the filter. */
export const kindCounts = (topics: CertTopic[], roundups: CertRoundup[]): Record<FeedKind, number> => {
  const counts: Record<FeedKind, number> = { cert: 0, vendor: 0, community: 0 };
  for (const topic of topics) {
    for (const kind of new Set(topic.advisories.map((advisory) => advisory.kind))) counts[kind] += 1;
  }
  for (const roundup of roundups) counts[roundup.kind] += 1;
  return counts;
};

/** Product names across a topic's CVEs. The feeds' own titles are in five languages, so the row reads from Hecate's data. */
export const topicProducts = (topic: CertTopic): string[] => {
  // Sources spell the same product differently: `GitLab` and `gitlab` are one entry, the first spelling wins.
  const names = new Map<string, string>();
  for (const name of topic.cves.flatMap((cve) => cve.products.map((product) => product.name))) {
    if (!names.has(name.toLowerCase())) names.set(name.toLowerCase(), name);
  }
  return [...names.values()];
};

const haystack = (topic: CertTopic): string =>
  [
    ...topic.cves.flatMap((cve) => [cve.vulnId, cve.title, ...cve.products.map((p) => p.name), ...cve.vendors.map((v) => v.name)]),
    ...topic.advisories.map((advisory) => advisory.title ?? ""),
  ]
    .join(" ")
    .toLowerCase();

export const filterTopics = (topics: CertTopic[], filter: TopicFilter, inStack: (topic: CertTopic) => boolean): CertTopic[] => {
  const needle = filter.search.trim().toLowerCase();
  return topics.filter(
    (topic) =>
      (!filter.source || topic.sources.some((source) => source.name === filter.source)) &&
      (!filter.severity || topic.worstSeverity === filter.severity) &&
      (!filter.stackOnly || inStack(topic)) &&
      (!needle || haystack(topic).includes(needle)),
  );
};

/** What touches the user's stack first, then what most CERTs and vendors agree on, then community interest, severity and recency. */
export const sortTopics = (topics: CertTopic[], inStack: (topic: CertTopic) => boolean): CertTopic[] =>
  [...topics].sort(
    (a, b) =>
      Number(inStack(b)) - Number(inStack(a)) ||
      voices(b) - voices(a) ||
      b.sources.length - a.sources.length ||
      severityRank(a.worstSeverity) - severityRank(b.worstSeverity) ||
      b.lastSeen.localeCompare(a.lastSeen),
  );

/** How many CVEs of a round-up are confirmed findings in the user's scans. */
export const roundupHits = (roundup: CertRoundup, scanCveScan: Record<string, string>): number =>
  roundup.cveIds.filter((cveId) => scanCveScan[cveId]).length;

/**
 * "Only my stack": each topic keeps just the CVEs that touch the user's stack, and its
 * title (topicProducts), worst severity and CVE list follow from those. A topic with
 * none is dropped; `hiddenCves` says how many it left out. The advisories stay whole:
 * they are the sources, not the subject.
 */
export const narrowToStack = (topics: CertTopic[], cveInStack: (cve: CertCve) => boolean): CertTopic[] =>
  topics.flatMap((topic) => {
    const cves = topic.cves.filter(cveInStack);
    if (cves.length === 0) return [];
    if (cves.length === topic.cves.length) return [topic];
    const worstSeverity = cves
      .map((cve) => cve.severity)
      .reduce((worst, severity) => (severityRank(severity) < severityRank(worst) ? severity : worst), cves[0].severity);
    return [{ ...topic, cves, worstSeverity, hiddenCves: topic.cves.length - cves.length }];
  });
