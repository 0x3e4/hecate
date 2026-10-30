import { useEffect, useState } from "react";
import { getFieldAggregation } from "../../api/vulnerabilities";
import { useI18n } from "../../i18n/context";
import { getCurrentLocale } from "../../i18n/language";
import type { DQLFieldValueBucket } from "../../types";
import { EmptyState, ErrorState } from "../../ui/primitives";
import { SkeletonBlock } from "../Skeleton";

interface FieldAggregationProps {
  fieldName: string;
  onValueClick: (fieldName: string, value: string) => void;
}

export const FieldAggregation = ({ fieldName, onValueClick }: FieldAggregationProps) => {
  const { t } = useI18n();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [buckets, setBuckets] = useState<DQLFieldValueBucket[]>([]);

  useEffect(() => {
    const fetchAggregation = async () => {
      setLoading(true);
      setError(null);
      try {
        const result = await getFieldAggregation(fieldName, 10);
        setBuckets(result.buckets);
      } catch (err) {
        console.error(`Failed to load aggregation for field ${fieldName}:`, err);
        setError(t("Error loading values", "Fehler beim Laden der Werte"));
      } finally {
        setLoading(false);
      }
    };

    fetchAggregation();
  }, [fieldName, t]);

  if (loading) {
    return (
      <div className="query-builder-values-loading" role="status">
        <span className="visually-hidden">{t("Loading values...", "Lade Werte...")}</span>
        {["70%", "55%", "62%", "48%", "66%"].map((width) => (
          <div key={width} className="query-builder-values-loading-row" aria-hidden="true">
            <SkeletonBlock height={14} width={width} />
            <SkeletonBlock height={14} width={48} />
          </div>
        ))}
      </div>
    );
  }

  if (error) {
    return <ErrorState title={error} />;
  }

  if (buckets.length === 0) {
    return <EmptyState title={t("No values available", "Keine Werte verfügbar")} />;
  }

  return (
    <div>
      <p className="query-builder-values-note">
        {t(`Top ${buckets.length} values:`, `Top ${buckets.length} Werte:`)}
      </p>
      <table className="query-builder-values-table">
        <tbody>
          {buckets.map((bucket, index) => (
            <tr
              key={index}
              onClick={() => onValueClick(fieldName, bucket.value)}
            >
              <td>
                <button type="button" className="query-builder-value">
                  <code className="mono">{bucket.value}</code>
                </button>
              </td>
              <td className="query-builder-value-count">
                {bucket.count.toLocaleString(getCurrentLocale())}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};
