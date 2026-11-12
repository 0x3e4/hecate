import { useEffect, useState } from "react";

import { fetchAttackPath } from "../api/attackPath";
import { useI18n } from "../i18n/context";
import type { AIProviderInfo, AttackPathResponse } from "../types";
import { EmptyState, ErrorState } from "../ui/primitives";
import { AttackPathGraphView } from "./AttackPathGraph";
import { LoadingRegion, SkeletonBlock } from "./Skeleton";

interface ScanFindingAttackPathProps {
  vulnerabilityId: string;
  scanId?: string;
  targetId?: string;
  packageName?: string;
  packageVersion?: string;
  aiEnabled: boolean;
  aiProviders?: AIProviderInfo[];
}

/**
 * Inline panel mounted inside the Findings tab's expanded detail row.
 * Fetches the attack path lazily when the finding is opened. Reuses the
 * shared AttackPathGraphView for rendering. No narrative-trigger wiring
 * here because findings on the scan page link out to the full vulnerability
 * detail tab when the user wants to (re)generate the AI narrative.
 */
export function ScanFindingAttackPath({
  vulnerabilityId,
  scanId,
  targetId,
  packageName,
  packageVersion,
  aiEnabled,
  aiProviders = [],
}: ScanFindingAttackPathProps) {
  const { t, locale } = useI18n();
  const [response, setResponse] = useState<AttackPathResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    fetchAttackPath(vulnerabilityId, {
      scanId,
      targetId,
      packageName,
      version: packageVersion,
      language: locale,
    })
      .then((data) => {
        if (!cancelled) setResponse(data);
      })
      .catch((err) => {
        console.error("Failed to fetch attack path for finding", err);
        if (!cancelled) {
          setError(
            t("Failed to load the attack path.", "Angriffspfad konnte nicht geladen werden."),
          );
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [vulnerabilityId, scanId, targetId, packageName, packageVersion, locale, t]);

  if (loading && !response) {
    return (
      <LoadingRegion label={t("Loading attack path", "Angriffspfad wird geladen")}>
        <SkeletonBlock height={160} />
      </LoadingRegion>
    );
  }
  if (error) return <ErrorState title={error} />;
  if (!response) return <EmptyState title={t("No attack path available.", "Kein Angriffspfad verfügbar.")} />;
  return (
    <div className={loading ? "is-refreshing" : undefined} aria-busy={loading || undefined}>
      <AttackPathGraphView
        graph={response.graph}
        narrative={response.narrative ?? null}
        aiEnabled={aiEnabled}
        aiProviders={aiProviders}
      />
    </div>
  );
}

export default ScanFindingAttackPath;
