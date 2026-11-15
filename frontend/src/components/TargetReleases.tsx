import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

import { fetchTargetReleases } from "../api/scans";
import { useI18n } from "../i18n/context";
import type { ScanReleaseEntry } from "../types";
import { EmptyState, Section } from "../ui/primitives";
import { formatDateTime } from "../utils/dateFormat";
import { SeverityBadges } from "./SeverityBadges";

const shortDigest = (imageRef?: string | null): string | null => {
  const digest = imageRef?.split("@")[1];
  return digest ? digest.replace(/^sha256:/, "").slice(0, 12) : null;
};

/** Scans of a target marked as releases: what shipped, with its evidence one click away. */
export const TargetReleases = ({ targetId }: { targetId: string }) => {
  const { t } = useI18n();
  const [items, setItems] = useState<ScanReleaseEntry[] | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetchTargetReleases(targetId)
      .then((data) => {
        if (!cancelled) setItems(data);
      })
      .catch(() => {
        if (!cancelled) setItems([]);
      });
    return () => {
      cancelled = true;
    };
  }, [targetId]);

  if (items === null) return null;

  return (
    <Section title={t("Releases", "Releases")}>
      {items.length === 0 ? (
        <EmptyState
          title={t(
            "No release marked yet. Open a completed scan and mark it as a release to keep its SBOM and VEX at hand.",
            "Noch kein Release markiert. Öffnen Sie einen abgeschlossenen Scan und markieren Sie ihn als Release, um SBOM und VEX griffbereit zu halten.",
          )}
        />
      ) : (
        <div className="table-scroll scan-target-scroll">
          <table className="scan-target-table scan-target-table--name-sticky">
            <thead>
              <tr>
                <th scope="col">{t("Release", "Release")}</th>
                <th scope="col">{t("Scanned", "Gescannt")}</th>
                <th scope="col">{t("Findings", "Findings")}</th>
                <th scope="col">{t("Commit / digest", "Commit / Digest")}</th>
                <th scope="col">{t("Note", "Notiz")}</th>
              </tr>
            </thead>
            <tbody>
              {items.map((item) => {
                const digest = shortDigest(item.imageRef);
                return (
                  <tr key={item.scanId}>
                    <td>
                      <Link className="row-link mono" to={`/scans/${item.scanId}`}>{item.label}</Link>
                    </td>
                    <td className="scan-target-nowrap">
                      {item.startedAt ? formatDateTime(item.startedAt) : "n/a"}
                    </td>
                    <td>
                      <SeverityBadges summary={item.summary} />
                    </td>
                    <td>
                      {item.commitSha ? (
                        <code className="mono" title={item.commitSha}>{item.commitSha.slice(0, 7)}</code>
                      ) : digest ? (
                        <code className="mono" title={item.imageRef ?? undefined}>{digest}</code>
                      ) : (
                        <span className="scan-target-muted">n/a</span>
                      )}
                    </td>
                    <td className="scan-target-muted">{item.note ?? ""}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </Section>
  );
};
