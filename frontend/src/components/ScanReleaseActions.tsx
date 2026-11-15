import { useEffect, useRef, useState } from "react";
import { LuDownload, LuTag } from "react-icons/lu";

import { clearScanRelease, downloadEvidenceBundle, markScanRelease } from "../api/scans";
import { useI18n } from "../i18n/context";
import type { Scan } from "../types";
import { BusyLabel } from "../ui/primitives";
import { describeError } from "../utils/apiError";
import { formatDateTime } from "../utils/dateFormat";
import { downloadBlob } from "../utils/download";
import { useToastContext } from "./ToastProvider";

/**
 * Scan detail header: the release marker (label + mark / edit / remove) and the
 * evidence bundle download (SBOM, VEX in three formats, findings summary, manifest).
 */
export const ScanReleaseActions = ({ scan, onChange }: { scan: Scan; onChange: (scan: Scan) => void }) => {
  const { t } = useI18n();
  const { showToast } = useToastContext();
  const [dialogOpen, setDialogOpen] = useState(false);
  const [bundleBusy, setBundleBusy] = useState(false);
  const canMark = scan.status === "completed";

  const downloadBundle = async () => {
    if (bundleBusy) return;
    setBundleBusy(true);
    try {
      const { data, filename } = await downloadEvidenceBundle(scan.id);
      downloadBlob(data, filename ?? `evidence-${scan.id}.zip`);
    } catch (err) {
      const described = describeError(err);
      showToast(described.detail ?? t("The evidence bundle could not be built.", "Das Nachweis-Paket konnte nicht erstellt werden."), "error");
    } finally {
      setBundleBusy(false);
    }
  };

  return (
    <div className="scan-detail-release">
      {scan.release && (
        <span
          className="tag scan-detail-release-tag"
          title={[
            scan.release.note,
            scan.release.markedAt
              ? t(`Marked ${formatDateTime(scan.release.markedAt)}`, `Markiert ${formatDateTime(scan.release.markedAt)}`)
              : null,
          ].filter(Boolean).join(" · ")}
        >
          <LuTag aria-hidden="true" />
          {t("Release", "Release")} <span className="mono">{scan.release.label}</span>
        </span>
      )}
      {canMark && (
        <button type="button" className="btn" onClick={() => setDialogOpen(true)}>
          {scan.release ? t("Edit release", "Release bearbeiten") : t("Mark as release", "Als Release markieren")}
        </button>
      )}
      <button
        type="button"
        className="btn"
        onClick={() => void downloadBundle()}
        disabled={bundleBusy}
        aria-busy={bundleBusy || undefined}
        title={t(
          "ZIP with SBOM (CycloneDX, SPDX), VEX (CycloneDX, OpenVEX, CSAF), a findings summary and a manifest with SHA-256 hashes",
          "ZIP mit SBOM (CycloneDX, SPDX), VEX (CycloneDX, OpenVEX, CSAF), Findings-Übersicht und Manifest mit SHA-256-Hashes",
        )}
      >
        <BusyLabel busy={bundleBusy}>
          <LuDownload aria-hidden="true" /> {t("Evidence bundle", "Nachweis-Paket")}
        </BusyLabel>
      </button>
      {dialogOpen && (
        <ReleaseDialog
          scan={scan}
          onClose={() => setDialogOpen(false)}
          onSaved={(updated, message) => {
            setDialogOpen(false);
            onChange(updated);
            showToast(message, "success");
          }}
        />
      )}
    </div>
  );
};

const ReleaseDialog = ({
  scan,
  onClose,
  onSaved,
}: {
  scan: Scan;
  onClose: () => void;
  onSaved: (scan: Scan, message: string) => void;
}) => {
  const { t } = useI18n();
  const [label, setLabel] = useState(scan.release?.label ?? "");
  const [note, setNote] = useState(scan.release?.note ?? "");
  const [pending, setPending] = useState<"save" | "remove" | null>(null);
  const [error, setError] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);
  const busy = pending !== null;

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !busy) onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [busy, onClose]);

  const run = async (kind: "save" | "remove") => {
    setPending(kind);
    setError("");
    try {
      if (kind === "save") {
        const updated = await markScanRelease(scan.id, { label: label.trim(), note: note.trim() || null }, scan.targetId);
        onSaved(updated, t(`Marked as release ${label.trim()}.`, `Als Release ${label.trim()} markiert.`));
      } else {
        const updated = await clearScanRelease(scan.id, scan.targetId);
        onSaved(updated, t("Release marker removed.", "Release-Markierung entfernt."));
      }
    } catch (err) {
      const described = describeError(err);
      setError(described.detail ?? t("The release could not be saved.", "Das Release konnte nicht gespeichert werden."));
      setPending(null);
    }
  };

  return (
    <div className="dialog-overlay" role="presentation" onClick={() => !busy && onClose()}>
      <div
        className="dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="scan-release-title"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 id="scan-release-title">{scan.release ? t("Edit release", "Release bearbeiten") : t("Mark as release", "Als Release markieren")}</h2>
        <p>
          {t(
            "A release keeps this scan's SBOM and VEX findable on the target page and in the evidence bundle. A release scan cannot be deleted until the marker is removed.",
            "Ein Release hält SBOM und VEX dieses Scans auf der Zielseite und im Nachweis-Paket auffindbar. Ein Release-Scan lässt sich erst löschen, wenn die Markierung entfernt ist.",
          )}
        </p>
        {error && <p role="alert">{error}</p>}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (label.trim()) void run("save");
          }}
        >
          <label htmlFor="scan-release-label">{t("Version", "Version")}</label>
          <input
            id="scan-release-label"
            ref={inputRef}
            type="text"
            maxLength={64}
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            placeholder="1.4.2"
          />
          <label htmlFor="scan-release-note">{t("Note (optional)", "Notiz (optional)")}</label>
          <textarea
            id="scan-release-note"
            className="scan-detail-release-note"
            maxLength={500}
            rows={3}
            value={note}
            onChange={(e) => setNote(e.target.value)}
          />
          <div className="dialog-actions">
            <button type="button" className="btn btn-secondary" disabled={busy} onClick={onClose}>
              {t("Cancel", "Abbrechen")}
            </button>
            {scan.release && (
              <button
                type="button"
                className="btn dialog-danger"
                disabled={busy}
                aria-busy={pending === "remove" || undefined}
                onClick={() => void run("remove")}
              >
                <BusyLabel busy={pending === "remove"}>{t("Remove marker", "Markierung entfernen")}</BusyLabel>
              </button>
            )}
            <button
              type="submit"
              className="btn btn-primary"
              disabled={busy || !label.trim()}
              aria-busy={pending === "save" || undefined}
            >
              <BusyLabel busy={pending === "save"}>{t("Save", "Speichern")}</BusyLabel>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
