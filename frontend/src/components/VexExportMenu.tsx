import { useState } from "react";

import { exportVex } from "../api/scans";
import { useI18n } from "../i18n/context";
import type { VexExportFormat } from "../types";
import { Spinner } from "../ui/primitives";
import { describeError } from "../utils/apiError";
import { downloadBlob } from "../utils/download";
import { useToastContext } from "./ToastProvider";

const FALLBACK_NAMES: Record<VexExportFormat, (scanId: string) => string> = {
  cyclonedx: (id) => `vex-${id}.cdx.json`,
  openvex: (id) => `vex-${id}.openvex.json`,
  csaf: (id) => `vex-${id}.csaf.json`,
};

/** VEX download in CycloneDX, OpenVEX or CSAF 2.0, picked from one small select. */
export const VexExportMenu = ({ scanId }: { scanId: string }) => {
  const { t } = useI18n();
  const { showToast } = useToastContext();
  const [busy, setBusy] = useState<VexExportFormat | null>(null);

  const run = async (format: VexExportFormat) => {
    if (busy) return;
    setBusy(format);
    try {
      const { data, filename } = await exportVex(scanId, format);
      downloadBlob(data, filename ?? FALLBACK_NAMES[format](scanId));
    } catch (err) {
      const described = describeError(err);
      showToast(
        described.status === 404 && format === "cyclonedx"
          ? t(
              "No VEX data for CycloneDX yet: set VEX statuses on findings first, or export OpenVEX / CSAF, which list unassessed findings as under investigation.",
              "Noch keine VEX-Daten für CycloneDX: Setzen Sie zuerst VEX-Status bei den Findings oder exportieren Sie OpenVEX / CSAF, die nicht bewertete Findings als in Prüfung führen.",
            )
          : described.status === 404
            ? t("This scan has no vulnerability findings to state.", "Dieser Scan hat keine Schwachstellen-Findings für VEX.")
            : t("The VEX export failed.", "Der VEX-Export ist fehlgeschlagen."),
        "error",
      );
    } finally {
      setBusy(null);
    }
  };

  return (
    <span className="scan-detail-vex-export" aria-busy={busy ? true : undefined}>
      {busy && <Spinner />}
      <select
        value=""
        disabled={busy !== null}
        aria-label={t("Export VEX", "VEX exportieren")}
        title={t("Export VEX", "VEX exportieren")}
        onChange={(e) => {
          const value = e.target.value as VexExportFormat | "";
          if (value) void run(value);
        }}
      >
        <option value="" disabled>
          {t("VEX export…", "VEX-Export…")}
        </option>
        <option value="cyclonedx">CycloneDX VEX</option>
        <option value="openvex">OpenVEX</option>
        <option value="csaf">CSAF 2.0 VEX</option>
      </select>
    </span>
  );
};
