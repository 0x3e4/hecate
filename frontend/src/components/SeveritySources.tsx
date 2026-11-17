import { useI18n } from "../i18n/context";
import { DocsLink } from "./DocsLink";
import type { SeverityProvenance } from "../types";
import { SeverityTag } from "../ui/primitives";
import { disagreementRange, orderedSources, sourceKindLabel } from "../utils/severitySources";

export const SEVERITY_SOURCES_ID = "severity-sources";

const capitalize = (value: string) => value.charAt(0).toUpperCase() + value.slice(1);

/** One line under the score row when the sources disagree, linking to the table. */
export const SeverityDisagreementNote = ({ provenance }: { provenance?: SeverityProvenance | null }) => {
  const { t } = useI18n();
  const range = disagreementRange(provenance);
  if (!range) return null;
  return (
    <p className="vulnerability-detail-severity-note" role="note">
      {t(
        `Sources disagree on this score: CVSS ${range.major} scores from ${range.min.toFixed(1)} to ${range.max.toFixed(1)}.`,
        `Die Quellen sind sich bei der Bewertung uneinig: CVSS-${range.major}-Werte von ${range.min.toFixed(1)} bis ${range.max.toFixed(1)}.`,
      )}{" "}
      <a href={`#${SEVERITY_SOURCES_ID}`}>{t("Severity by source", "Schweregrad je Quelle")}</a>
    </p>
  );
};

/** Every stored CVSS score next to the one Hecate shows, and why that one. */
export const SeveritySourcesBlock = ({ provenance }: { provenance?: SeverityProvenance | null }) => {
  const { t } = useI18n();
  if (!provenance || provenance.sources.length === 0) return null;
  const rows = orderedSources(provenance.sources);
  const primary = provenance.primary;
  const range = disagreementRange(provenance);
  return (
    <section className="vulnerability-detail-severity" id={SEVERITY_SOURCES_ID} aria-labelledby="severity-sources-title">
      <h2 id="severity-sources-title">{t("Severity by source", "Schweregrad je Quelle")}</h2>
      {range && (
        <p className="vulnerability-detail-severity-disagree">
          {t(
            `Sources disagree: ${range.sources.join(", ")} score this between ${range.min.toFixed(1)} and ${range.max.toFixed(1)} (CVSS ${range.major}). Check the vectors before you rely on the shown score.`,
            `Die Quellen sind uneinig: ${range.sources.join(", ")} bewerten zwischen ${range.min.toFixed(1)} und ${range.max.toFixed(1)} (CVSS ${range.major}). Prüfen Sie die Vektoren, bevor Sie sich auf den angezeigten Wert verlassen.`,
          )}
        </p>
      )}
      <div className="table-scroll">
        <table className="vulnerability-detail-table vulnerability-detail-severity-table">
          <thead>
            <tr>
              <th>{t("Source", "Quelle")}</th>
              <th>CVSS</th>
              <th>{t("Score", "Wert")}</th>
              <th>{t("Severity", "Schweregrad")}</th>
              <th>{t("Vector", "Vektor")}</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row, index) => (
              <tr key={`${row.source}-${row.version}-${row.vector ?? row.baseScore}-${index}`}>
                <td>
                  <span className="vulnerability-detail-severity-source">{row.source}</span>
                  {row.source !== sourceKindLabel(row.kind, t) && (
                    <span className="vulnerability-detail-severity-kind">{sourceKindLabel(row.kind, t)}</span>
                  )}
                  {row.isPrimary && (
                    <span className="tag vulnerability-detail-severity-shown">{t("shown", "angezeigt")}</span>
                  )}
                </td>
                <td className="mono">{row.version ?? "n/a"}</td>
                <td className="vulnerability-detail-severity-score">{row.baseScore != null ? row.baseScore.toFixed(1) : "n/a"}</td>
                <td>
                  {row.severity ? (
                    <SeverityTag severity={row.severity}>{capitalize(row.severity)}</SeverityTag>
                  ) : (
                    <span className="muted">{t("Unknown", "Unbekannt")}</span>
                  )}
                </td>
                <td className="mono vulnerability-detail-severity-vector">{row.vector ?? ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="vulnerability-detail-severity-why">
        {primary.source
          ? t(
              `Hecate shows the CVSS ${primary.version ?? ""} score from ${primary.source}. `,
              `Hecate zeigt den CVSS-${primary.version ?? ""}-Wert von ${primary.source}. `,
            )
          : ""}
        <DocsLink path="guide/vulnerabilities/#severity-by-source">
          {t("Why this score", "Warum dieser Wert")}
        </DocsLink>
      </p>
    </section>
  );
};
