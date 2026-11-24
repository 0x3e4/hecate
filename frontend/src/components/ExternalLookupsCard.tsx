import { useId, useState } from "react";

import { updateScanTarget } from "../api/scans";
import { useI18n } from "../i18n/context";
import type { ScanTarget } from "../types";
import { Section } from "../ui/primitives";
import { DocsLink } from "./DocsLink";

type Choice = "default" | "on" | "off";

const toChoice = (value: boolean | null | undefined): Choice =>
  value === true ? "on" : value === false ? "off" : "default";

const toValue = (choice: Choice): boolean | null => (choice === "on" ? true : choice === "off" ? false : null);

/**
 * What scans of this target may send out: "no external lookups" keeps package
 * names, module paths and found secrets in the network; TruffleHog's secret
 * verification can also be set on its own for repositories.
 */
export const ExternalLookupsCard = ({
  target,
  onUpdated,
  notify,
}: {
  target: ScanTarget;
  onUpdated: (target: ScanTarget) => void;
  notify: (message: string, kind: "success" | "error") => void;
}) => {
  const { t } = useI18n();
  const switchId = useId();
  const selectId = useId();
  const [busy, setBusy] = useState<"lookups" | "trufflehog" | null>(null);
  const noLookups = target.noExternalLookups ?? false;
  const isRepo = target.type === "source_repo";
  const trufflehogSelected = target.scanners?.includes("trufflehog") ?? false;
  const current = toChoice(target.trufflehogVerification);

  const save = async (
    kind: "lookups" | "trufflehog",
    data: { noExternalLookups?: boolean; trufflehogVerification?: boolean | null },
  ) => {
    setBusy(kind);
    try {
      onUpdated(await updateScanTarget(target.id, data));
      notify(t("Setting saved. It applies from the next scan.", "Einstellung gespeichert. Sie gilt ab dem nächsten Scan."), "success");
    } catch {
      notify(t("Could not save the setting.", "Die Einstellung konnte nicht gespeichert werden."), "error");
    } finally {
      setBusy(null);
    }
  };

  return (
    <Section title={t("External lookups", "Externe Abfragen")}>
      <p className="scan-target-muted scan-target-vex-intro">
        {t(
          "Some scanners ask outside services about what they find: registries about package names, OSV about the package list, providers about secrets. For private code you can keep all of that in your network.",
          "Einige Scanner fragen externe Dienste zu dem, was sie finden: Registries nach Paketnamen, OSV nach der Paketliste, Anbieter nach Secrets. Bei privatem Code kannst du das alles im eigenen Netz halten.",
        )}{" "}
        <DocsLink path="sca-scanning/#no-external-lookups">{t("What changes", "Was sich ändert")}</DocsLink>
      </p>
      <label className="scan-target-lookups-switch" htmlFor={switchId}>
        <input
          id={switchId}
          type="checkbox"
          checked={noLookups}
          disabled={busy !== null}
          aria-busy={busy === "lookups" || undefined}
          onChange={(e) => void save("lookups", { noExternalLookups: e.target.checked })}
        />
        {t("No external lookups", "Keine externen Abfragen")}
      </label>

      {isRepo && (
        <div className="scan-target-secret-verification">
          <label htmlFor={selectId}>{t("TruffleHog secret verification", "TruffleHog-Secret-Prüfung")}</label>
          <select
            id={selectId}
            value={noLookups ? "off" : current}
            disabled={busy !== null || noLookups}
            aria-busy={busy === "trufflehog" || undefined}
            onChange={(e) => {
              const choice = e.target.value as Choice;
              if (choice !== current) void save("trufflehog", { trufflehogVerification: toValue(choice) });
            }}
          >
            <option value="default">{t("Scanner default", "Standard des Scanners")}</option>
            <option value="on">{t("Verify found secrets", "Gefundene Secrets prüfen")}</option>
            <option value="off">{t("Don't verify", "Nicht prüfen")}</option>
          </select>
          <DocsLink path="sca-scanning/#secret-verification">{t("More", "Mehr")}</DocsLink>
        </div>
      )}
      {isRepo && noLookups && (
        <p className="scan-target-sub">
          {t("Off while there are no external lookups.", "Aus, solange keine externen Abfragen erlaubt sind.")}
        </p>
      )}
      {isRepo && !noLookups && !trufflehogSelected && (
        <p className="scan-target-sub">
          {t(
            "TruffleHog is not among this target's scanners; the setting applies once it is.",
            "TruffleHog ist nicht unter den Scannern dieses Ziels; die Einstellung gilt, sobald er es ist.",
          )}
        </p>
      )}
    </Section>
  );
};
