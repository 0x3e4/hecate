import { useState } from "react";
import { LuX } from "react-icons/lu";

import { importInventorySystemList } from "../api/inventory";
import { useI18n } from "../i18n/context";
import type { InventorySystemImportResult, InventorySystemListFormat } from "../types";
import { BusyLabel } from "../ui/primitives";
import { describeError } from "../utils/apiError";
import { DocsLink } from "./DocsLink";

const FORMATS: { value: InventorySystemListFormat | ""; en: string; de: string }[] = [
  { value: "", en: "Detect", de: "Erkennen" },
  { value: "csv", en: "CSV", de: "CSV" },
  { value: "text", en: "One name per line", de: "Ein Name pro Zeile" },
  { value: "ansible-ini", en: "Ansible INI", de: "Ansible INI" },
  { value: "ansible-yaml", en: "Ansible YAML", de: "Ansible YAML" },
  { value: "ansible-json", en: "ansible-inventory --list", de: "ansible-inventory --list" },
  { value: "json", en: "Hecate JSON", de: "Hecate JSON" },
];

const SOURCE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,63}$/;
const NAMES_SHOWN = 12;

const NameList = ({ names, total }: { names: string[]; total: number }) => {
  const { t } = useI18n();
  if (total === 0) return null;
  const shown = names.slice(0, NAMES_SHOWN);
  const more = total - shown.length;
  return (
    <span className="inventory-list-names">
      {shown.join(", ")}
      {more > 0 && ` ${t(`and ${more} more`, `und ${more} weitere`)}`}
    </span>
  );
};

/**
 * Inventory → Systems → Import list: paste or pick a server list, preview what
 * it changes, then apply it. Scripts send the same thing with an
 * inventory:sync token (docs/guide/inventory.md#server-lists).
 */
export const InventorySystemListImport = ({
  onClose,
  onApplied,
}: {
  onClose: () => void;
  onApplied: () => Promise<void> | void;
}) => {
  const { t } = useI18n();
  const [content, setContent] = useState("");
  const [fileName, setFileName] = useState<string | null>(null);
  const [format, setFormat] = useState<InventorySystemListFormat | "">("");
  const [source, setSource] = useState("upload");
  const [mode, setMode] = useState<"merge" | "replace">("merge");
  const [busy, setBusy] = useState<"preview" | "apply" | null>(null);
  const [preview, setPreview] = useState<InventorySystemImportResult | null>(null);
  const [needsForce, setNeedsForce] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Any change to the input makes an earlier preview stale.
  const touched = () => {
    setPreview(null);
    setNeedsForce(null);
    setError(null);
  };

  const run = async (dryRun: boolean, force = false) => {
    if (!content.trim()) {
      setError(t("Paste a list or choose a file.", "Fügen Sie eine Liste ein oder wählen Sie eine Datei."));
      return;
    }
    if (!SOURCE_PATTERN.test(source)) {
      setError(t("The list name takes letters, digits and . _ : / -", "Der Listenname nimmt Buchstaben, Ziffern und . _ : / -"));
      return;
    }
    setBusy(dryRun ? "preview" : "apply");
    setError(null);
    try {
      const result = await importInventorySystemList({ content, format: format || null, source, mode, dryRun, force });
      if (dryRun) {
        setPreview(result);
        setNeedsForce(null);
      } else {
        await onApplied();
        onClose();
      }
    } catch (err) {
      const described = describeError(err);
      if (described.status === 409) {
        setNeedsForce(described.detail);
        setPreview(null);
      } else {
        setError(described.detail || t("The list could not be read.", "Die Liste konnte nicht gelesen werden."));
      }
    } finally {
      setBusy(null);
    }
  };

  const close = () => {
    if (!busy) onClose();
  };

  return (
    <div className="dialog-overlay" role="presentation" onClick={close}>
      <div
        className="dialog dialog--wide"
        role="dialog"
        aria-modal="true"
        aria-labelledby="inventory-list-title"
        onClick={(e) => e.stopPropagation()}
        onKeyDown={(e) => {
          if (e.key === "Escape") close();
        }}
      >
        <div className="dialog-head">
          <div className="inventory-dialog-title">
            <h3 id="inventory-list-title">{t("Import a server list", "Serverliste importieren")}</h3>
            <p className="inventory-dialog-hint">
              {t(
                "CSV, one name per line, an Ansible inventory or its --list output. ",
                "CSV, ein Name pro Zeile, ein Ansible-Inventar oder dessen --list-Ausgabe. ",
              )}
              <DocsLink path="guide/inventory/#server-lists">{t("Formats and push", "Formate und Push")}</DocsLink>
              {". "}
              <DocsLink path="guide/inventory/#fetched-lists">{t("Fetch it on a schedule", "Regelmäßig abrufen")}</DocsLink>
            </p>
          </div>
          <button type="button" className="dialog-close" onClick={close} aria-label={t("Close", "Schließen")}>
            <LuX aria-hidden="true" />
          </button>
        </div>

        <div className="inventory-form">
          <div className="inventory-field inventory-field--full">
            <div className="inventory-list-source">
              <label className="inventory-label" htmlFor="inventory-list-content">{t("List", "Liste")}</label>
              <label className="inventory-list-file">
                {fileName ? fileName : t("Choose a file", "Datei wählen")}
                <input
                  type="file"
                  className="visually-hidden"
                  accept=".csv,.txt,.ini,.yml,.yaml,.json,text/*,application/json"
                  onChange={async (e) => {
                    const file = e.target.files?.[0];
                    e.target.value = "";
                    if (!file) return;
                    setContent(await file.text());
                    setFileName(file.name);
                    touched();
                  }}
                />
              </label>
            </div>
            <textarea
              id="inventory-list-content"
              className="inventory-input inventory-list-content"
              rows={8}
              spellCheck={false}
              value={content}
              onChange={(e) => {
                setContent(e.target.value);
                setFileName(null);
                touched();
              }}
              placeholder={"[web]\nweb-01.example.com hecate_exposure=internet\nweb-02.example.com\n\n[db]\ndb-01.example.com"}
            />
          </div>

          <div className="inventory-field">
            <label className="inventory-label" htmlFor="inventory-list-format">{t("Format", "Format")}</label>
            <select
              id="inventory-list-format"
              value={format}
              onChange={(e) => {
                setFormat(e.target.value as InventorySystemListFormat | "");
                touched();
              }}
            >
              {FORMATS.map((f) => (
                <option key={f.value} value={f.value}>{t(f.en, f.de)}</option>
              ))}
            </select>
          </div>
          <div className="inventory-field">
            <label className="inventory-label" htmlFor="inventory-list-name">{t("List name", "Listenname")}</label>
            <input
              id="inventory-list-name"
              type="text"
              className="inventory-input"
              value={source}
              onChange={(e) => {
                setSource(e.target.value.trim());
                touched();
              }}
              aria-describedby="inventory-list-name-hint"
            />
            <span id="inventory-list-name-hint" className="inventory-hint">
              {t("Replacing only touches systems this list named.", "Ersetzen betrifft nur Systeme, die diese Liste genannt hat.")}
            </span>
          </div>

          <fieldset className="inventory-field inventory-field--full inventory-list-mode">
            <legend className="inventory-label">{t("Systems the list no longer names", "Systeme, die die Liste nicht mehr nennt")}</legend>
            <label>
              <input type="radio" name="inventory-list-mode" checked={mode === "merge"} onChange={() => { setMode("merge"); touched(); }} />
              {t("Keep them (add and update only)", "Behalten (nur hinzufügen und ändern)")}
            </label>
            <label>
              <input type="radio" name="inventory-list-mode" checked={mode === "replace"} onChange={() => { setMode("replace"); touched(); }} />
              {t("Retire them: the list is complete", "Stilllegen: die Liste ist vollständig")}
            </label>
          </fieldset>

          {preview && (
            <div className="inventory-field--full inventory-list-preview" role="status">
              <p className="inventory-list-preview-head">
                {t(
                  `${preview.listed} systems read as ${preview.format}. Applying would:`,
                  `${preview.listed} Systeme gelesen als ${preview.format}. Anwenden würde:`,
                )}
              </p>
              <ul>
                <li>{t(`add ${preview.createdCount}`, `${preview.createdCount} hinzufügen`)} <NameList names={preview.created} total={preview.createdCount} /></li>
                <li>{t(`change ${preview.updatedCount}`, `${preview.updatedCount} ändern`)} <NameList names={preview.updated} total={preview.updatedCount} /></li>
                {preview.restoredCount > 0 && (
                  <li>{t(`bring back ${preview.restoredCount}`, `${preview.restoredCount} zurückholen`)} <NameList names={preview.restored} total={preview.restoredCount} /></li>
                )}
                {preview.mode === "replace" && (
                  <li>{t(`retire ${preview.retiredCount}`, `${preview.retiredCount} stilllegen`)} <NameList names={preview.retired} total={preview.retiredCount} /></li>
                )}
                <li>{t(`leave ${preview.unchangedCount} as they are`, `${preview.unchangedCount} unverändert lassen`)}</li>
              </ul>
              {preview.skipped.length > 0 && (
                <details className="inventory-list-skipped">
                  <summary>
                    {preview.skipped.length === 1
                      ? t("1 line or value left out", "1 Zeile oder Wert ausgelassen")
                      : t(`${preview.skipped.length} lines or values left out`, `${preview.skipped.length} Zeilen oder Werte ausgelassen`)}
                  </summary>
                  <ul>
                    {preview.skipped.map((s, i) => (
                      <li key={i}><span className="mono">{s.where}</span>: {s.reason}</li>
                    ))}
                  </ul>
                </details>
              )}
            </div>
          )}
          {needsForce && (
            <p className="inventory-field--full inventory-systems-error" role="alert">{needsForce}</p>
          )}
          {error && <p className="inventory-field--full inventory-systems-error" role="alert">{error}</p>}

          <div className="dialog-actions inventory-dialog-actions inventory-field--full">
            <button type="button" className="btn" onClick={close} disabled={busy !== null}>
              {t("Cancel", "Abbrechen")}
            </button>
            <button
              type="button"
              className="btn"
              onClick={() => void run(true)}
              disabled={busy !== null}
              aria-busy={busy === "preview" || undefined}
            >
              <BusyLabel busy={busy === "preview"}>{t("Preview", "Vorschau")}</BusyLabel>
            </button>
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => void run(false, Boolean(needsForce))}
              disabled={busy !== null || (!preview && !needsForce)}
              aria-busy={busy === "apply" || undefined}
              title={!preview && !needsForce ? t("Preview first", "Zuerst die Vorschau") : undefined}
            >
              <BusyLabel busy={busy === "apply"}>
                {needsForce ? t("Apply anyway", "Trotzdem anwenden") : t("Apply", "Anwenden")}
              </BusyLabel>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
