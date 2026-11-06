import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { LuChevronRight } from "react-icons/lu";

import "../screens/cert.css";
import {
  FEED_KINDS,
  fetchCertOverview,
  type CertCve,
  type CertOverview,
  type CertRoundup,
  type CertTopic,
  type FeedKind,
  type FeedSource,
} from "../api/cert";
import { fetchScanCoverage, type ScanCoverage } from "../api/scans";
import { ChipLinks, cveMatchesInventory, uniqueChips, useCveChips, type CoverageChip } from "../components/CoverageChips";
import { SkeletonBlock } from "../components/Skeleton";
import { usePersistentState } from "../hooks/usePersistentState";
import { useI18n, type TranslateFn } from "../i18n/context";
import { getCurrentTimezone } from "../timezone/storage";
import { EmptyState, ErrorState, PageHeader, Section, SeverityTag, Stat } from "../ui/primitives";
import {
  applyKinds,
  feedKindLabel,
  filterTopics,
  isVoice,
  kindCounts,
  roundupHits,
  sortTopics,
  topicProducts,
  voices,
} from "../utils/certTopics";
import { SEVERITY_ORDER, severityLabel } from "../utils/cveGroups";
import { formatDateOnly } from "../utils/dateFormat";
import { safeHref } from "../utils/safeHref";

const DAY_OPTIONS = [7, 30, 90];
const PRODUCTS_SHOWN = 3;
const IDS_SHOWN = 2;
// Community posts are context: shown when asked for, so they do not crowd out what the CERTs say.
const DEFAULT_KINDS: FeedKind[] = ["cert", "vendor"];

export const CertPage = () => {
  const { t, locale } = useI18n();
  const [days, setDays] = usePersistentState<number>("hecate.cert.days", 30);
  const [data, setData] = useState<CertOverview | null>(null);
  const [loading, setLoading] = useState(true);
  const [failed, setFailed] = useState(false);
  const [failure, setFailure] = useState<unknown>(null);
  const [retryKey, setRetryKey] = useState(0);
  const [search, setSearch] = useState("");
  const [source, setSource] = useState("");
  const [kinds, setKinds] = usePersistentState<FeedKind[]>("hecate.advisories.kinds", DEFAULT_KINDS);
  const [severity, setSeverity] = useState("");
  const [stackOnly, setStackOnly] = useState(false);
  const [coverage, setCoverage] = useState<ScanCoverage>({ cveScan: {}, productScan: {}, scanTargets: {} });

  useEffect(() => {
    document.title = "Hecate Cyber Defense - Advisories";
    return () => {
      document.title = "Hecate Cyber Defense";
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    fetchScanCoverage()
      .then((res) => {
        if (!cancelled) setCoverage(res);
      })
      .catch(() => {
        /* scan coverage is optional context for this page */
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setFailed(false);
    fetchCertOverview(days, getCurrentTimezone())
      .then((res) => {
        if (!cancelled) setData(res);
      })
      .catch((error) => {
        console.error("Failed to load CERT advisories", error);
        if (!cancelled) {
          setFailure(error);
          setFailed(true);
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [days, retryKey]);

  const allTopics = useMemo(() => data?.topics ?? [], [data]);
  const allRoundups = useMemo(() => data?.roundups ?? [], [data]);
  const counts = useMemo(() => kindCounts(allTopics, allRoundups), [allTopics, allRoundups]);
  // A stored value from an older version or a hand-edited one is not trusted to be a list.
  const shownKinds = useMemo(() => FEED_KINDS.filter((kind) => (Array.isArray(kinds) ? kinds : DEFAULT_KINDS).includes(kind)), [kinds]);
  const topics = useMemo(() => applyKinds(allTopics, shownKinds), [allTopics, shownKinds]);
  const roundups = useMemo(() => allRoundups.filter((roundup) => shownKinds.includes(roundup.kind)), [allRoundups, shownKinds]);
  const toggleKind = (kind: FeedKind) =>
    setKinds(shownKinds.includes(kind) ? shownKinds.filter((item) => item !== kind) : [...shownKinds, kind]);
  const allCves = useMemo(() => topics.flatMap((topic) => topic.cves), [topics]);
  const chipsByCve = useCveChips(
    allCves,
    coverage.cveScan,
    coverage.productScan,
    coverage.scanTargets,
    t("in inventory", "im Inventar"),
    t("SCA scan", "SCA-Scan"),
  );

  // A finding or an inventory hit is confirmed; a package sharing the product's name alone is not.
  const inStack = useCallback(
    (topic: CertTopic) => topic.cves.some((cve) => cveMatchesInventory(cve) || coverage.cveScan[cve.vulnId]),
    [coverage.cveScan],
  );

  const sources = useMemo(() => {
    const byName = new Map<string, FeedSource>();
    for (const item of [...topics.flatMap((topic) => topic.sources), ...roundups.map((roundup) => ({ name: roundup.feed, kind: roundup.kind }))]) {
      byName.set(item.name, item);
    }
    return [...byName.values()].sort((a, b) => a.name.localeCompare(b.name));
  }, [topics, roundups]);
  const visible = useMemo(
    () => sortTopics(filterTopics(topics, { search, source, severity, stackOnly }, inStack), inStack),
    [topics, search, source, severity, stackOnly, inStack],
  );
  const visibleRoundups = useMemo(
    () =>
      roundups
        .filter((roundup) => !source || roundup.feed === source)
        .sort((a, b) => roundupHits(b, coverage.cveScan) - roundupHits(a, coverage.cveScan) || b.published.localeCompare(a.published)),
    [roundups, source, coverage.cveScan],
  );

  const advisoryCount = topics.reduce((sum, topic) => sum + topic.advisories.length, 0) + roundups.length;
  const totalCount = allTopics.reduce((sum, topic) => sum + topic.advisories.length, 0) + allRoundups.length;

  return (
    <div className="page cert">
      <PageHeader
        title={t("Advisories", "Meldungen")}
        description={t(
          "What CERTs, vendors and the community are warning about. Advisories that share a CVE are merged into one topic; community posts join a topic but never merge two.",
          "Wovor CERTs, Hersteller und die Community warnen. Meldungen, die sich eine CVE teilen, sind zu einem Thema zusammengeführt; Community-Beiträge hängen sich an ein Thema an, verbinden aber nie zwei.",
        )}
      />

      {failed ? (
        <ErrorState
          title={t("Advisories could not be loaded.", "Meldungen konnten nicht geladen werden.")}
          error={failure}
          onRetry={() => setRetryKey((k) => k + 1)}
        />
      ) : loading && !data ? (
        <div className="cert-skeleton">
          {Array.from({ length: 8 }).map((_, index) => (
            <SkeletonBlock key={index} height="3rem" />
          ))}
        </div>
      ) : totalCount === 0 ? (
        <EmptyState title={t("No advisories in this period.", "Keine Meldungen in diesem Zeitraum.")}>
          {t(
            "Feeds are read every two hours. System → Data lists the feeds and shows the last run.",
            "Die Feeds werden alle zwei Stunden gelesen. System → Daten listet die Feeds und zeigt den letzten Lauf.",
          )}
        </EmptyState>
      ) : (
        <>
          <dl className="stat-row cert-stats">
            <Stat label={t("Topics", "Themen")} value={topics.length.toLocaleString(locale)} />
            <Stat
              label={t("Named by several CERTs or vendors", "Von mehreren CERTs oder Herstellern genannt")}
              value={topics.filter((topic) => voices(topic) > 1).length.toLocaleString(locale)}
            />
            <Stat label={t("In your stack", "In Ihrem Stack")} value={topics.filter(inStack).length.toLocaleString(locale)} />
            <Stat label={t("Advisories", "Meldungen")} value={advisoryCount.toLocaleString(locale)} />
          </dl>

          <fieldset className="cert-kinds">
            <legend className="visually-hidden">{t("Kinds of source", "Arten von Quellen")}</legend>
            {FEED_KINDS.map((kind) => (
              <label key={kind} className="cert-toggle">
                <input type="checkbox" checked={shownKinds.includes(kind)} onChange={() => toggleKind(kind)} />
                {feedKindLabel(kind, t)}
                <span className="cert-extra">{counts[kind].toLocaleString(locale)}</span>
              </label>
            ))}
          </fieldset>

          <div className="filter-row">
            <input
              type="text"
              aria-label={t("Search product, CVE or title", "Produkt, CVE oder Titel suchen")}
              placeholder={t("Search product, CVE or title", "Produkt, CVE oder Titel suchen")}
              value={search}
              onChange={(event) => setSearch(event.target.value)}
            />
            <select aria-label={t("Source", "Quelle")} value={source} onChange={(event) => setSource(event.target.value)}>
              <option value="">{t("All sources", "Alle Quellen")}</option>
              {shownKinds.map((kind) => {
                const names = sources.filter((item) => item.kind === kind);
                return names.length === 0 ? null : (
                  <optgroup key={kind} label={feedKindLabel(kind, t)}>
                    {names.map((item) => (
                      <option key={item.name} value={item.name}>{item.name}</option>
                    ))}
                  </optgroup>
                );
              })}
            </select>
            <select aria-label={t("Severity", "Schweregrad")} value={severity} onChange={(event) => setSeverity(event.target.value)}>
              <option value="">{t("All severities", "Alle Schweregrade")}</option>
              {SEVERITY_ORDER.map((level) => (
                <option key={level} value={level}>{severityLabel(level, t)}</option>
              ))}
            </select>
            <select aria-label={t("Period", "Zeitraum")} value={days} onChange={(event) => setDays(Number(event.target.value))}>
              {DAY_OPTIONS.map((option) => (
                <option key={option} value={option}>{t(`Last ${option} days`, `Letzte ${option} Tage`)}</option>
              ))}
            </select>
            <label className="cert-toggle">
              <input type="checkbox" checked={stackOnly} onChange={(event) => setStackOnly(event.target.checked)} />
              {t("Only my stack", "Nur mein Stack")}
            </label>
          </div>

          <Section title={t("Topics", "Themen")}>
            {visible.length === 0 ? (
              <EmptyState title={t("No topic matches these filters.", "Kein Thema passt zu diesen Filtern.")} />
            ) : (
              <ul className="cert-topics">
                {visible.map((topic) => (
                  <TopicRow
                    key={topic.id}
                    t={t}
                    topic={topic}
                    chips={uniqueChips(topic.cves.flatMap((cve) => chipsByCve.get(cve.vulnId) ?? []))}
                  />
                ))}
              </ul>
            )}
          </Section>

          {visibleRoundups.length > 0 && (
            <Section title={t("Round-ups", "Sammelmeldungen")}>
              <p className="cert-note">
                {t(
                  "Batches of 20 or more CVEs, such as a kernel update, and community posts listing more than three. They stay apart so unrelated topics do not merge through them.",
                  "Sammlungen ab 20 CVEs, etwa ein Kernel-Update, und Community-Beiträge mit mehr als drei. Sie bleiben getrennt, damit fremde Themen nicht über sie zusammenfallen.",
                )}
              </p>
              <ul className="cert-roundups">
                {visibleRoundups.map((roundup) => (
                  <RoundupRow key={roundup.id} t={t} roundup={roundup} hits={roundupHits(roundup, coverage.cveScan)} />
                ))}
              </ul>
            </Section>
          )}
        </>
      )}
    </div>
  );
};

const AdvisoryLink = ({ title, url }: { title: string; url: string | null }) =>
  url ? (
    <a href={safeHref(url)} target="_blank" rel="noreferrer" className="cert-link">{title}</a>
  ) : (
    <>{title}</>
  );

// CERTs and vendors by name; community posts as a count, since they are context.
const TopicSources = ({ t, sources }: { t: TranslateFn; sources: FeedSource[] }) => {
  const named = sources.filter(isVoice);
  const community = sources.length - named.length;
  return (
    <span className="cert-topic-certs">
      {named.map((source) => source.name).join(", ")}
      {community > 0 && (
        <span className="cert-topic-community" title={sources.filter((source) => !isVoice(source)).map((source) => source.name).join(", ")}>
          {named.length > 0 ? " · " : ""}
          {t(`${community} community`, `${community} Community`)}
        </span>
      )}
    </span>
  );
};

const AdvisoryFeed = ({ t, feed, kind }: { t: TranslateFn; feed: string; kind: FeedKind }) => (
  <span className="cert-advisory-feed" title={feed}>
    {feed}
    {kind !== "cert" && <span className={`chip advisory-kind advisory-kind--${kind}`}>{feedKindLabel(kind, t)}</span>}
  </span>
);

const TopicRow = ({ t, topic, chips }: { t: TranslateFn; topic: CertTopic; chips: CoverageChip[] }) => {
  const products = topicProducts(topic);
  const fallback = topic.advisories[0]?.title ?? topic.cves[0]?.vulnId;
  const exploited = topic.cves.some((cve) => cve.exploited);
  return (
    <li>
      <details className="cert-topic">
        <summary className="cert-topic-row">
          <LuChevronRight className="cert-chevron" aria-hidden="true" />
          <SeverityTag severity={topic.worstSeverity}>{severityLabel(topic.worstSeverity, t)}</SeverityTag>
          <span className="cert-topic-main">
            <span className="cert-topic-title" title={products.join(", ") || fallback}>
              {products.length > 0 ? products.slice(0, PRODUCTS_SHOWN).join(", ") : fallback}
              {products.length > PRODUCTS_SHOWN && <span className="cert-extra">+{products.length - PRODUCTS_SHOWN}</span>}
            </span>
            <span className="cert-topic-ids">
              {topic.cves.slice(0, IDS_SHOWN).map((cve) => (
                <span key={cve.vulnId} className="mono">{cve.vulnId}</span>
              ))}
              {topic.cves.length > IDS_SHOWN && <span className="cert-extra">+{topic.cves.length - IDS_SHOWN}</span>}
            </span>
          </span>
          <span className="cert-topic-side">
            <TopicSources t={t} sources={topic.sources} />
            <span className="cert-topic-when">
              {exploited && <span className="chip cert-flag">{t("Exploited", "Ausgenutzt")}</span>}
              <ChipLinks chips={chips} />
              {formatDateOnly(topic.lastSeen)}
            </span>
          </span>
        </summary>
        <div className="cert-topic-body">
          <div className="table-scroll">
            <table className="cert-cves">
              <thead>
                <tr>
                  <th scope="col">{t("Severity", "Schweregrad")}</th>
                  <th scope="col">ID</th>
                  <th scope="col">{t("Product", "Produkt")}</th>
                  <th scope="col" className="num">CVSS</th>
                  <th scope="col" className="num">EPSS</th>
                </tr>
              </thead>
              <tbody>
                {topic.cves.map((cve) => (
                  <CveRow key={cve.vulnId} t={t} cve={cve} />
                ))}
              </tbody>
            </table>
          </div>
          <ul className="cert-advisories">
            {topic.advisories.map((advisory) => (
              <li key={`${advisory.feed}|${advisory.url ?? advisory.title}`} className="cert-advisory">
                <AdvisoryFeed t={t} feed={advisory.feed} kind={advisory.kind} />
                <span className="cert-advisory-title">
                  <AdvisoryLink title={advisory.title || advisory.feed} url={advisory.url} />
                </span>
                <span className="cert-advisory-date">{formatDateOnly(advisory.published)}</span>
              </li>
            ))}
          </ul>
        </div>
      </details>
    </li>
  );
};

const CveRow = ({ t, cve }: { t: TranslateFn; cve: CertCve }) => (
  <tr>
    <td><SeverityTag severity={cve.severity}>{severityLabel(cve.severity, t)}</SeverityTag></td>
    <td className="cert-cve-id">
      {cve.known ? (
        <Link to={`/vulnerability/${encodeURIComponent(cve.vulnId)}`} className="row-link mono">{cve.vulnId}</Link>
      ) : (
        <span className="mono">{cve.vulnId}</span>
      )}
      {cve.kevListed && <span className="chip cert-flag">KEV</span>}
    </td>
    <td className="cert-cve-product">
      {cve.known ? cve.products.map((product) => product.name).join(", ") || "n/a" : t("Not in Hecate yet", "Noch nicht in Hecate")}
    </td>
    <td className="num">{cve.cvssScore != null ? cve.cvssScore.toFixed(1) : "n/a"}</td>
    <td className="num">{cve.epssScore != null ? `${(cve.epssScore * 100).toFixed(2)}%` : "n/a"}</td>
  </tr>
);

const RoundupRow = ({ t, roundup, hits }: { t: TranslateFn; roundup: CertRoundup; hits: number }) => (
  <li className="cert-advisory">
    <AdvisoryFeed t={t} feed={roundup.feed} kind={roundup.kind} />
    <span className="cert-advisory-title">
      <AdvisoryLink title={roundup.title || roundup.feed} url={roundup.url} />
    </span>
    <span className="cert-roundup-count">
      {hits > 0 && <span className="cert-roundup-hits">{t(`${hits} in your scans`, `${hits} in Ihren Scans`)}</span>}
      {t(`${roundup.cveIds.length} CVEs`, `${roundup.cveIds.length} CVEs`)}
    </span>
    <span className="cert-advisory-date">{formatDateOnly(roundup.published)}</span>
  </li>
);
