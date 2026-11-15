import { useMemo } from "react";

import { useI18n } from "../i18n/context";
import type { SbomComponent, SupplyChainSummary } from "../types";
import {
  SUPPLY_CHAIN_SIGNALS,
  signalCounts,
  signalDetail,
  signalLabel,
  signalsOf,
  type SupplyChainSignal,
} from "../utils/supplyChain";

/** Neutral chips under a component name: fresh release, new publisher, unmaintained. */
export const SupplyChainChips = ({ component }: { component: SbomComponent }) => {
  const { t } = useI18n();
  const signals = signalsOf(component);
  if (signals.length === 0) return null;
  return (
    <div className="scan-detail-signals">
      {signals.map(s => (
        <span key={s} className="chip" title={signalDetail(s, component, t)}>
          {signalLabel(s, t)}
        </span>
      ))}
    </div>
  );
};

/** A "Supply chain" row for the SBOM facets; renders nothing while no component carries a signal. */
export const SupplyChainFacet = ({
  components,
  active,
  onChange,
}: {
  components: SbomComponent[];
  active: SupplyChainSignal | null;
  onChange: (signal: SupplyChainSignal | null) => void;
}) => {
  const { t } = useI18n();
  const counts = useMemo(() => signalCounts(components), [components]);
  if (!SUPPLY_CHAIN_SIGNALS.some(s => counts[s] > 0) && !active) return null;
  return (
    <div className="scan-detail-facet">
      <p className="scan-detail-facet-title">{t("Supply chain", "Lieferkette")}</p>
      <div className="scan-detail-facet-values">
        {SUPPLY_CHAIN_SIGNALS.filter(s => counts[s] > 0 || active === s).map(s => {
          const isActive = active === s;
          return (
            <button
              key={s}
              type="button"
              className="scan-detail-facet-value"
              aria-pressed={isActive}
              onClick={() => onChange(isActive ? null : s)}
            >
              <span className="scan-detail-facet-name">{signalLabel(s, t)}</span>
              <span className="scan-detail-facet-count">{counts[s]}</span>
            </button>
          );
        })}
      </div>
    </div>
  );
};

/**
 * The scan header's "Supply chain" value: counts of the flagged components,
 * each a button that opens the SBOM tab filtered to it. Null when there is
 * nothing to say (no lookup, or nothing flagged).
 */
export const SupplyChainSummaryLine = ({
  summary,
  onPick,
}: {
  summary: SupplyChainSummary | null | undefined;
  onPick: (signal: SupplyChainSignal) => void;
}) => {
  const { t } = useI18n();
  if (!summary) return null;
  if (summary.state === "running") return <span className="muted">{t("Checking releases", "Releases werden geprüft")}</span>;
  if (summary.state !== "done") return null;
  const parts: Array<[SupplyChainSignal, number]> = [
    ["fresh", summary.freshRelease],
    ["publisher", summary.publisherChanged],
    ["unmaintained", summary.unmaintained],
  ];
  const shown = parts.filter(([, n]) => n > 0);
  if (shown.length === 0) return <span>{t("No signals", "Keine Auffälligkeiten")}</span>;
  return (
    <span className="scan-detail-inline">
      {shown.map(([signal, n], i) => (
        <span key={signal}>
          {i > 0 ? " · " : ""}
          <button type="button" className="scan-detail-link-button" onClick={() => onPick(signal)}>
            {signalLabel(signal, t)}: {n}
          </button>
        </span>
      ))}
    </span>
  );
};
