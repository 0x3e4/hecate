import { Link } from "react-router-dom";

import { useI18n } from "../i18n/context";
import type { PossiblyAffectedEntry } from "../types";

/**
 * Name-only matches for an advisory that names no affected versions yet.
 * Kept apart from the version-confirmed "Affected in …" blocks on purpose:
 * a name match is a reason to look, not a finding.
 */
export const PossiblyAffectedBlock = ({ entries }: { entries?: PossiblyAffectedEntry[] }) => {
  const { t } = useI18n();
  if (!entries || entries.length === 0) return null;
  return (
    <section className="vulnerability-detail-possible" aria-labelledby="possibly-affected-title">
      <div className="vulnerability-detail-callout-head">
        <h2 id="possibly-affected-title">
          {t(
            "Possibly affected: this advisory names no affected versions yet",
            "Möglicherweise betroffen: Dieses Advisory nennt noch keine betroffenen Versionen",
          )}
        </h2>
      </div>
      <p className="vulnerability-detail-possible-lead">
        {t(
          "These entries match a product the advisory names by name only. Without version data Hecate cannot confirm or rule them out; check the vendor's advisory.",
          "Diese Einträge passen nur über den Namen zu einem Produkt, das das Advisory nennt. Ohne Versionsangaben kann Hecate sie weder bestätigen noch ausschließen; prüfen Sie das Advisory des Herstellers.",
        )}
      </p>
      <div className="table-scroll">
        <table className="vulnerability-detail-table vulnerability-detail-possible-table">
          <thead>
            <tr>
              <th>{t("Where", "Wo")}</th>
              <th>{t("Name", "Name")}</th>
              <th>{t("Version", "Version")}</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((entry, index) =>
              entry.kind === "inventory" ? (
                <tr key={`inv-${entry.itemId}-${index}`}>
                  <td>
                    <Link to="/inventory">{t("Inventory", "Inventar")}</Link>
                  </td>
                  <td>
                    {entry.name}
                    {entry.environment ? <span className="muted"> · {entry.environment}</span> : null}
                  </td>
                  <td className="mono">{entry.version || "n/a"}</td>
                </tr>
              ) : (
                <tr key={`sbom-${entry.scanId}-${entry.packageName}-${entry.packageVersion}-${index}`}>
                  <td>
                    {entry.scanId ? <Link to={`/scans/${entry.scanId}`}>{entry.targetName}</Link> : entry.targetName}
                  </td>
                  <td className="mono">{entry.packageName}</td>
                  <td className="mono">{entry.packageVersion || "n/a"}</td>
                </tr>
              ),
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
};
