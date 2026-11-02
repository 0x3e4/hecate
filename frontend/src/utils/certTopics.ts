import type { CertRoundup, CertTopic } from "../api/cert";

import { severityRank } from "./cveGroups";

export interface TopicFilter {
  search: string;
  cert: string;
  severity: string;
  stackOnly: boolean;
}

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
      (!filter.cert || topic.certs.includes(filter.cert)) &&
      (!filter.severity || topic.worstSeverity === filter.severity) &&
      (!filter.stackOnly || inStack(topic)) &&
      (!needle || haystack(topic).includes(needle)),
  );
};

/** What touches the user's stack first, then what most CERTs agree on, then severity and recency. */
export const sortTopics = (topics: CertTopic[], inStack: (topic: CertTopic) => boolean): CertTopic[] =>
  [...topics].sort(
    (a, b) =>
      Number(inStack(b)) - Number(inStack(a)) ||
      b.certs.length - a.certs.length ||
      severityRank(a.worstSeverity) - severityRank(b.worstSeverity) ||
      b.lastSeen.localeCompare(a.lastSeen),
  );

/** How many CVEs of a round-up are confirmed findings in the user's scans. */
export const roundupHits = (roundup: CertRoundup, scanCveScan: Record<string, string>): number =>
  roundup.cveIds.filter((cveId) => scanCveScan[cveId]).length;
