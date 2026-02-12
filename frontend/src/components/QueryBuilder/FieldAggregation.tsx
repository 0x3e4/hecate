import { useEffect, useState } from "react";
import { getFieldAggregation } from "../../api/vulnerabilities";
import { useI18n } from "../../i18n/context";
import { getCurrentLocale } from "../../i18n/language";
import type { DQLFieldValueBucket } from "../../types";

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
      <div className="field-aggregation loading">
        <p>{t("Loading values...", "Lade Werte...")}</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="field-aggregation error">
        <p>{error}</p>
      </div>
    );
  }

  if (buckets.length === 0) {
    return (
      <div className="field-aggregation empty">
        <p>{t("No values available", "Keine Werte verfügbar")}</p>
      </div>
    );
  }

  return (
    <div className="field-aggregation">
      <div className="aggregation-header">
        <span>{t(`Top ${buckets.length} values:`, `Top ${buckets.length} Werte:`)}</span>
      </div>
      <table className="aggregation-table">
        <tbody>
          {buckets.map((bucket, index) => (
            <tr
              key={index}
              onClick={() => onValueClick(fieldName, bucket.value)}
              className="aggregation-row"
            >
              <td className="aggregation-value">
                <code>{bucket.value}</code>
              </td>
              <td className="aggregation-count">
                ({bucket.count.toLocaleString(getCurrentLocale())})
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};
