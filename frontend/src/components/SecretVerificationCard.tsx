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
 * Whether TruffleHog checks the secrets it finds in this repository against
 * their provider. Unset follows the scanner's own setting.
 */
export const SecretVerificationCard = ({
  target,
  onUpdated,
  notify,
}: {
  target: ScanTarget;
  onUpdated: (target: ScanTarget) => void;
  notify: (message: string, kind: "success" | "error") => void;
}) => {
  const { t } = useI18n();
  const selectId = useId();
  const [busy, setBusy] = useState(false);
  const current = toChoice(target.trufflehogVerification);
  const selected = target.scanners?.includes("trufflehog") ?? false;

  const change = async (choice: Choice) => {
    if (choice === current) return;
    setBusy(true);
    try {
      onUpdated(await updateScanTarget(target.id, { trufflehogVerification: toValue(choice) }));
      notify(t("Secret verification saved.", "Secret-Prüfung gespeichert."), "success");
    } catch {
      notify(t("Could not save the secret verification.", "Secret-Prüfung konnte nicht gespeichert werden."), "error");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Section title={t("Secret verification", "Secret-Prüfung")}>
      <p className="scan-target-muted scan-target-vex-intro">
        {t(
          "TruffleHog checks each secret it finds by logging in to its provider. Turn it off where found secrets must not leave your network.",
          "TruffleHog prüft jedes gefundene Secret mit einer Anmeldung beim Anbieter. Schalte das ab, wo gefundene Secrets das Netz nicht verlassen dürfen.",
        )}{" "}
        <DocsLink path="sca-scanning/#secret-verification">{t("More", "Mehr")}</DocsLink>
      </p>
      <div className="scan-target-secret-verification">
        <label htmlFor={selectId}>{t("For this target", "Für dieses Ziel")}</label>
        <select
          id={selectId}
          value={current}
          disabled={busy}
          aria-busy={busy || undefined}
          onChange={(e) => void change(e.target.value as Choice)}
        >
          <option value="default">{t("Scanner default", "Standard des Scanners")}</option>
          <option value="on">{t("Verify found secrets", "Gefundene Secrets prüfen")}</option>
          <option value="off">{t("Don't verify", "Nicht prüfen")}</option>
        </select>
      </div>
      {!selected && (
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
