import { useId, useState } from "react";
import { Link } from "react-router-dom";

import { updateScanTarget } from "../api/scans";
import { useI18n } from "../i18n/context";
import type { ScanTarget } from "../types";
import { Section } from "../ui/primitives";
import { TARGET_KINDS, exposureLabel, kindLabel, type TargetExposure, type TargetKind } from "../utils/targetClass";
import { DocsLink } from "./DocsLink";

/**
 * What the target is and whether the internet reaches it. "Affected in your
 * scans" lists internet-facing targets first, so an exposed host stands out.
 */
export const TargetClassCard = ({
  target,
  onUpdated,
  notify,
}: {
  target: ScanTarget;
  onUpdated: (target: ScanTarget) => void;
  notify: (message: string, kind: "success" | "error") => void;
}) => {
  const { t } = useI18n();
  const kindId = useId();
  const exposureId = useId();
  const [busy, setBusy] = useState(false);

  const save = async (data: { kind?: TargetKind | null; exposure?: TargetExposure | null }) => {
    setBusy(true);
    try {
      onUpdated(await updateScanTarget(target.id, data));
      notify(t("Saved.", "Gespeichert."), "success");
    } catch {
      notify(t("Could not save.", "Konnte nicht gespeichert werden."), "error");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Section title={t("System", "System")}>
      <p className="scan-target-muted scan-target-vex-intro">
        {t(
          "What this target is and whether the internet reaches it. Internet-facing targets come first wherever a vulnerability lists where it runs.",
          "Was dieses Ziel ist und ob es aus dem Internet erreichbar ist. Erreichbare Ziele stehen überall zuerst, wo eine Schwachstelle auflistet, wo sie läuft.",
        )}{" "}
        <DocsLink path="sca/hosts/">{t("More", "Mehr")}</DocsLink>
      </p>
      {target.systemId && (
        <p className="scan-target-muted">
          {t("This target is a system of the inventory, with its other systems in ", "Dieses Ziel ist ein System des Inventars, mit den anderen Systemen unter ")}
          <Link to="/inventory?tab=systems">{t("Inventory → Systems", "Inventar → Systeme")}</Link>.
        </p>
      )}
      <div className="scan-target-class-fields">
        <div className="scan-target-secret-verification">
          <label htmlFor={kindId}>{t("Kind", "Art")}</label>
          <select
            id={kindId}
            value={target.kind ?? ""}
            disabled={busy}
            aria-busy={busy || undefined}
            onChange={(e) => void save({ kind: (e.target.value || null) as TargetKind | null })}
          >
            <option value="">{t("Unknown", "Unbekannt")}</option>
            {TARGET_KINDS.map((kind) => (
              <option key={kind} value={kind}>
                {kindLabel(kind, t)}
              </option>
            ))}
          </select>
        </div>
        <div className="scan-target-secret-verification">
          <label htmlFor={exposureId}>{t("Exposure", "Erreichbarkeit")}</label>
          <select
            id={exposureId}
            value={target.exposure ?? ""}
            disabled={busy}
            aria-busy={busy || undefined}
            onChange={(e) => void save({ exposure: (e.target.value || null) as TargetExposure | null })}
          >
            <option value="">{t("Unknown", "Unbekannt")}</option>
            <option value="internet">{exposureLabel("internet", t)}</option>
            <option value="internal">{exposureLabel("internal", t)}</option>
          </select>
        </div>
      </div>
    </Section>
  );
};
