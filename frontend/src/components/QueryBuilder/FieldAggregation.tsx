import { useEffect, useState } from "react";
import { getFieldAggregation } from "../../api/vulnerabilities";
import type { DQLFieldValueBucket } from "../../types";

interface FieldAggregationProps {
  fieldName: string;
  onValueClick: (fieldName: string, value: string) => void;
}

export const FieldAggregation = ({ fieldName, onValueClick }: FieldAggregationProps) => {
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
        setError("Fehler beim Laden der Werte");
      } finally {
        setLoading(false);
      }
    };

    fetchAggregation();
  }, [fieldName]);

  if (loading) {
    return (
      <div className="field-aggregation loading">
        <p>Lade Werte...</p>
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
        <p>Keine Werte verfügbar</p>
      </div>
    );
  }

  return (
    <div className="field-aggregation">
      <div className="aggregation-header">
        <span>Top {buckets.length} Werte:</span>
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
                ({bucket.count.toLocaleString("de-DE")})
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};
