import { useState } from "react";
import { isAxiosError } from "axios";
import { LuPencil, LuRefreshCw } from "react-icons/lu";

import { applyTargetVexSources, setTargetVexSources } from "../api/scans";
import { useI18n } from "../i18n/context";
import type { ScanTarget, VexSourceResult } from "../types";
import { ExternalLink, Section } from "../ui/primitives";
import { formatDateTime } from "../utils/dateFormat";
import { safeHref } from "../utils/safeHref";

const MAX_SOURCES = 5;

const ERROR_TEXT: Record<string, { en: string; de: string }> = {
  not_public: { en: "Host is not public", de: "Host ist nicht öffentlich" },
  http_status: { en: "Server error", de: "Serverfehler" },
  too_large: { en: "Document too large", de: "Dokument zu groß" },
  network: { en: "Not reachable", de: "Nicht erreichbar" },
  invalid_json: { en: "Not JSON", de: "Kein JSON" },
  unknown_format: { en: "Not CycloneDX VEX or OpenVEX", de: "Weder CycloneDX VEX noch OpenVEX" },
};

const errorDetail = (exc: unknown): string | null => {
  if (isAxiosError(exc)) {
    const detail = exc.response?.data?.detail;
    if (typeof detail === "string") return detail;
  }
  return null;
};

/**
 * VEX documents published for this target (e.g. by the image's vendor) that
 * Hecate fetches after every scan and applies to the findings. A status set
 * by hand or by a manual import is never overwritten.
 */
export const VexSourcesCard = ({
  target,
  onUpdated,
  notify,
}: {
  target: ScanTarget;
  onUpdated: (target: ScanTarget) => void;
  notify: (message: string, kind: "success" | "error") => void;
}) => {
  const { t } = useI18n();
  const sources = target.vexSources ?? [];
  const status = target.vexSourceStatus ?? null;
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState("");
  const [busy, setBusy] = useState<"save" | "apply" | null>(null);

  const startEditing = () => {
    setDraft(sources.join("\n"));
    setEditing(true);
  };

  const save = async () => {
    const urls = draft.split(/\s+/).map((u) => u.trim()).filter(Boolean);
    setBusy("save");
    try {
      const updated = await setTargetVexSources(target.id, urls);
      onUpdated(updated);
      setEditing(false);
      notify(
        urls.length
          ? t("VEX sources saved and applied.", "VEX-Quellen gespeichert und angewendet.")
          : t("VEX sources removed.", "VEX-Quellen entfernt."),
        "success",
      );
    } catch (exc) {
      notify(errorDetail(exc) ?? t("Could not save the VEX sources.", "VEX-Quellen konnten nicht gespeichert werden."), "error");
    } finally {
      setBusy(null);
    }
  };

  const apply = async () => {
    setBusy("apply");
    try {
      const updated = await applyTargetVexSources(target.id);
      onUpdated(updated);
      notify(t("VEX sources applied.", "VEX-Quellen angewendet."), "success");
    } catch (exc) {
      notify(errorDetail(exc) ?? t("Could not apply the VEX sources.", "VEX-Quellen konnten nicht angewendet werden."), "error");
    } finally {
      setBusy(null);
    }
  };

  const resultFor = (url: string): VexSourceResult | undefined => status?.sources.find((s) => s.url === url);

  return (
    <Section
      title={t("VEX sources", "VEX-Quellen")}
      actions={
        !editing ? (
          <span className="scan-target-vex-actions">
            {sources.length > 0 && (
              <button type="button" className="btn-secondary" disabled={busy !== null} onClick={apply}>
                <LuRefreshCw aria-hidden="true" />
                {busy === "apply" ? t("Applying…", "Wird angewendet…") : t("Apply now", "Jetzt anwenden")}
              </button>
            )}
            <button type="button" className="btn-secondary" disabled={busy !== null} onClick={startEditing}>
              <LuPencil aria-hidden="true" />
              {sources.length ? t("Edit", "Bearbeiten") : t("Add source", "Quelle hinzufügen")}
            </button>
          </span>
        ) : undefined
      }
    >
      <p className="scan-target-muted scan-target-vex-intro">
        {t(
          "VEX documents published for this target, for example by the vendor of the image. Hecate fetches them after every scan and sets the status of the matching findings; a status you set yourself or imported stays.",
          "VEX-Dokumente, die für dieses Ziel veröffentlicht werden, etwa vom Hersteller des Images. Hecate lädt sie nach jedem Scan und setzt den Status der passenden Findings; ein Status, den du selbst gesetzt oder importiert hast, bleibt.",
        )}
      </p>

      {editing ? (
        <div className="scan-target-vex-form">
          <label htmlFor="scan-target-vex-urls">
            {t(
              `CycloneDX VEX or OpenVEX URLs (https, one per line, up to ${MAX_SOURCES})`,
              `URLs von CycloneDX VEX oder OpenVEX (https, eine pro Zeile, höchstens ${MAX_SOURCES})`,
            )}
          </label>
          <textarea
            id="scan-target-vex-urls"
            rows={3}
            value={draft}
            spellCheck={false}
            onChange={(e) => setDraft(e.target.value)}
            placeholder="https://raw.githubusercontent.com/0x3e4/hecate/main/vex/hecate-backend.openvex.json"
          />
          <div className="scan-target-vex-actions">
            <button type="button" className="btn-primary" disabled={busy !== null} onClick={save}>
              {busy === "save" ? t("Saving…", "Speichert…") : t("Save and apply", "Speichern und anwenden")}
            </button>
            <button type="button" className="btn-secondary" disabled={busy !== null} onClick={() => setEditing(false)}>
              {t("Cancel", "Abbrechen")}
            </button>
          </div>
        </div>
      ) : sources.length === 0 ? null : (
        <>
          <ul className="scan-target-vex-list">
            {sources.map((url) => {
              const result = resultFor(url);
              const error = result && !result.ok ? ERROR_TEXT[result.errorKind ?? ""] : null;
              return (
                <li key={url}>
                  <ExternalLink href={safeHref(url)} className="mono scan-target-vex-url" title={url}>
                    {url}
                  </ExternalLink>
                  {result?.ok && (
                    <span className="scan-target-sub">
                      {result.format === "openvex" ? "OpenVEX" : "CycloneDX"} ·{" "}
                      {result.statements ?? 0} {t("statements", "Aussagen")}
                    </span>
                  )}
                  {result && !result.ok && (
                    <span className="scan-target-sub scan-target-tone-error" title={result.error ?? undefined}>
                      {error ? t(error.en, error.de) : result.errorKind}
                      {result.error ? `: ${result.error}` : ""}
                    </span>
                  )}
                  {!result && <span className="scan-target-sub">{t("not fetched yet", "noch nicht geladen")}</span>}
                </li>
              );
            })}
          </ul>
          {status && (
            <p className="scan-target-sub">
              {t("Last applied", "Zuletzt angewendet")} {formatDateTime(status.checkedAt)}: {status.applied}{" "}
              {t("findings set", "Findings gesetzt")}
              {status.cleared > 0 && `, ${status.cleared} ${t("removed", "entfernt")}`}
              {status.skipped > 0 &&
                `, ${status.skipped} ${t("statements skipped (conflicting, no package)", "Aussagen übersprungen (widersprüchlich, ohne Paket)")}`}
              {status.sources.some((s) => !s.ok) &&
                ` · ${t("a source failed, so no status was removed", "eine Quelle schlug fehl, daher wurde kein Status entfernt")}`}
            </p>
          )}
        </>
      )}
    </Section>
  );
};
