import { Fragment, useEffect, useState } from "react";
import type { AxiosError } from "axios";
import { LuPlus } from "react-icons/lu";

import "../screens/advisory-feeds.css";
import "../screens/list-sources.css";

import {
  createInventoryListSource,
  deleteInventoryListSource,
  fetchInventoryListSources,
  pullInventoryListSource,
  updateInventoryListSource,
} from "../api/inventory";
import { useI18n, type TranslateFn } from "../i18n/context";
import type { InventoryListSource, InventoryListSourcePullResult, InventorySystemListFormat } from "../types";
import { BusyLabel, EmptyState, ErrorState, Section } from "../ui/primitives";
import { formatDateTime } from "../utils/dateFormat";
import {
  EMPTY_LIST_SOURCE_FORM,
  INTERVAL_CHOICES,
  formFromSource,
  intervalParts,
  listSourcePayload,
  resultChanges,
  type ChangeKind,
  type ListSourceForm,
} from "../utils/listSources";
import { ConfirmDialog } from "./ConfirmDialog";
import { DocsLink } from "./DocsLink";
import { LoadingRegion, SkeletonRows } from "./Skeleton";
import { useToastContext } from "./ToastProvider";

const FORMATS: { value: InventorySystemListFormat | ""; en: string; de: string }[] = [
  { value: "", en: "Detect", de: "Erkennen" },
  { value: "csv", en: "CSV", de: "CSV" },
  { value: "text", en: "One name per line", de: "Ein Name pro Zeile" },
  { value: "ansible-ini", en: "Ansible INI", de: "Ansible INI" },
  { value: "ansible-yaml", en: "Ansible YAML", de: "Ansible YAML" },
  { value: "ansible-json", en: "ansible-inventory --list", de: "ansible-inventory --list" },
  { value: "json", en: "Hecate JSON", de: "Hecate JSON" },
];

const intervalLabel = (minutes: number, t: TranslateFn): string => {
  const { value, unit } = intervalParts(minutes);
  const one = value === 1;
  switch (unit) {
    case "weeks":
      return one ? t("Weekly", "Wöchentlich") : t(`Every ${value} weeks`, `Alle ${value} Wochen`);
    case "days":
      return one ? t("Daily", "Täglich") : t(`Every ${value} days`, `Alle ${value} Tage`);
    case "hours":
      return one ? t("Hourly", "Stündlich") : t(`Every ${value} hours`, `Alle ${value} Stunden`);
    default:
      return t(`Every ${value} minutes`, `Alle ${value} Minuten`);
  }
};

const changeLabel = (kind: ChangeKind, count: number, t: TranslateFn): string => {
  switch (kind) {
    case "created":
      return t(`${count} added`, `${count} hinzugefügt`);
    case "updated":
      return t(`${count} changed`, `${count} geändert`);
    case "restored":
      return t(`${count} back`, `${count} zurück`);
    default:
      return t(`${count} retired`, `${count} stillgelegt`);
  }
};

const changesText = (
  result: { listed: number; createdCount: number; updatedCount: number; retiredCount: number; restoredCount: number },
  t: TranslateFn,
): string => {
  const changes = resultChanges(result);
  const listed =
    result.listed === 1 ? t("1 system listed", "1 System gelistet") : t(`${result.listed} systems listed`, `${result.listed} Systeme gelistet`);
  if (changes.length === 0) return t(`${listed}, nothing changed`, `${listed}, nichts geändert`);
  return `${listed}, ${changes.map((c) => changeLabel(c.kind, c.count, t)).join(", ")}`;
};

const errorDetail = (error: unknown, fallback: string): string => {
  const detail = (error as AxiosError<{ detail?: unknown }>).response?.data?.detail;
  return typeof detail === "string" ? detail : fallback;
};

/**
 * System → Data: server lists Hecate fetches itself on a schedule and applies
 * like a pushed list (docs/guide/inventory.md#fetched-lists). Admin only: a
 * source holds a credential and makes the backend send requests.
 */
export const InventoryListSourcesPanel = () => {
  const { t } = useI18n();
  const { showToast } = useToastContext();
  const [sources, setSources] = useState<InventoryListSource[]>([]);
  const [allowPrivate, setAllowPrivate] = useState(false);
  const [status, setStatus] = useState<"loading" | "ready" | "error">("loading");
  // `null` = closed, "" = adding, an id = editing that source.
  const [editing, setEditing] = useState<string | null>(null);
  const [form, setForm] = useState<ListSourceForm>(EMPTY_LIST_SOURCE_FORM);
  const [saving, setSaving] = useState(false);
  const [busy, setBusy] = useState<{ id: string; action: "toggle" | "preview" | "pull" } | null>(null);
  // The last preview or fetch per source, shown under its row.
  const [outcomes, setOutcomes] = useState<Record<string, InventoryListSourcePullResult>>({});
  const [deleting, setDeleting] = useState<InventoryListSource | null>(null);

  useEffect(() => {
    fetchInventoryListSources()
      .then((list) => {
        setSources(list.items);
        setAllowPrivate(list.allowPrivateHosts);
        setStatus("ready");
      })
      .catch(() => setStatus("error"));
  }, []);

  const edited = editing ? sources.find((source) => source.id === editing) : undefined;

  const replace = (updated: InventoryListSource) =>
    setSources((current) => current.map((source) => (source.id === updated.id ? updated : source)));

  const openForm = (source?: InventoryListSource) => {
    setEditing(source?.id ?? "");
    setForm(source ? formFromSource(source) : EMPTY_LIST_SOURCE_FORM);
  };

  const closeForm = () => {
    setEditing(null);
    setForm(EMPTY_LIST_SOURCE_FORM);
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      const payload = listSourcePayload(form, edited);
      if (edited) {
        replace(await updateInventoryListSource(edited.id, payload));
        showToast(t(`List "${form.source.trim()}" saved.`, `Liste „${form.source.trim()}“ gespeichert.`), "success");
      } else {
        const created = await createInventoryListSource(payload);
        setSources((current) => [...current, created].sort((a, b) => a.source.localeCompare(b.source)));
        showToast(
          t(`List "${created.source}" added. It is fetched within a few minutes.`, `Liste „${created.source}“ hinzugefügt. Sie wird in wenigen Minuten abgerufen.`),
          "success",
        );
      }
      closeForm();
    } catch (error) {
      showToast(errorDetail(error, t("Failed to save the list.", "Liste konnte nicht gespeichert werden.")), "error");
    } finally {
      setSaving(false);
    }
  };

  const handleToggle = async (source: InventoryListSource) => {
    setBusy({ id: source.id, action: "toggle" });
    try {
      replace(await updateInventoryListSource(source.id, { enabled: !source.enabled }));
    } catch (error) {
      showToast(errorDetail(error, t("Failed to save the list.", "Liste konnte nicht gespeichert werden.")), "error");
    } finally {
      setBusy(null);
    }
  };

  const handlePull = async (source: InventoryListSource, options: { dryRun?: boolean; force?: boolean }) => {
    setBusy({ id: source.id, action: options.dryRun ? "preview" : "pull" });
    try {
      const outcome = await pullInventoryListSource(source.id, options);
      if (!options.dryRun) replace(outcome.source);
      setOutcomes((current) => ({ ...current, [source.id]: outcome }));
      if (!options.dryRun && outcome.ok) {
        showToast(t(`List "${source.source}" fetched.`, `Liste „${source.source}“ abgerufen.`), "success");
      }
    } catch (error) {
      showToast(errorDetail(error, t("The list could not be fetched.", "Die Liste konnte nicht abgerufen werden.")), "error");
    } finally {
      setBusy(null);
    }
  };

  const handleDelete = async (source: InventoryListSource) => {
    try {
      await deleteInventoryListSource(source.id);
      setSources((current) => current.filter((item) => item.id !== source.id));
      if (editing === source.id) closeForm();
      showToast(t(`List "${source.source}" removed.`, `Liste „${source.source}“ entfernt.`), "success");
    } catch (error) {
      showToast(errorDetail(error, t("Failed to remove the list.", "Liste konnte nicht entfernt werden.")), "error");
    } finally {
      setDeleting(null);
    }
  };

  const canSave = form.source.trim().length > 0 && form.url.trim().length > 0 && !saving;
  const isBusy = (id: string, action?: "toggle" | "preview" | "pull") =>
    busy?.id === id && (action === undefined || busy.action === action);

  return (
    <Section
      title={t("Server lists", "Serverlisten")}
      actions={
        <button type="button" className="btn btn-secondary" onClick={() => openForm()} disabled={editing !== null}>
          <LuPlus aria-hidden="true" />
          {t("Add list", "Liste hinzufügen")}
        </button>
      }
    >
      <p className="system-section-help">
        {t(
          "Lists of servers Hecate fetches on a schedule and applies to the inventory's systems, like an import.",
          "Serverlisten, die Hecate regelmäßig abruft und wie einen Import auf die Systeme im Inventar anwendet.",
        )}{" "}
        <DocsLink path="guide/inventory/#fetched-lists">{t("Fetched lists", "Abgerufene Listen")}</DocsLink>
      </p>

      {editing !== null && (
        <form
          className="well system-form advisory-feeds-form list-sources-form"
          onSubmit={(event) => {
            event.preventDefault();
            if (canSave) void handleSave();
          }}
        >
          <label className="advisory-feeds-field">
            <span>{t("List name", "Listenname")}</span>
            <input
              className="system-input"
              value={form.source}
              maxLength={64}
              onChange={(event) => setForm({ ...form, source: event.target.value })}
              placeholder="netbox"
            />
          </label>
          <label className="advisory-feeds-field">
            <span>URL</span>
            <input
              className="system-input mono"
              value={form.url}
              maxLength={2048}
              inputMode="url"
              onChange={(event) => setForm({ ...form, url: event.target.value })}
              placeholder="https://cmdb.example.com/export/hosts.csv"
            />
          </label>
          <label className="advisory-feeds-field">
            <span>{t("Format", "Format")}</span>
            <select
              className="system-input"
              value={form.format}
              onChange={(event) => setForm({ ...form, format: event.target.value as InventorySystemListFormat | "" })}
            >
              {FORMATS.map((f) => (
                <option key={f.value} value={f.value}>{t(f.en, f.de)}</option>
              ))}
            </select>
          </label>
          <label className="advisory-feeds-field">
            <span>{t("Fetch", "Abrufen")}</span>
            <select
              className="system-input"
              value={form.intervalMinutes}
              onChange={(event) => setForm({ ...form, intervalMinutes: Number(event.target.value) })}
            >
              {[...new Set([...INTERVAL_CHOICES, form.intervalMinutes])].sort((a, b) => a - b).map((minutes) => (
                <option key={minutes} value={minutes}>{intervalLabel(minutes, t)}</option>
              ))}
            </select>
          </label>
          <fieldset className="list-sources-mode">
            <legend>{t("Systems the list no longer names", "Systeme, die die Liste nicht mehr nennt")}</legend>
            <label>
              <input type="radio" name="list-source-mode" checked={form.mode === "merge"} onChange={() => setForm({ ...form, mode: "merge" })} />
              {t("Keep them", "Behalten")}
            </label>
            <label>
              <input type="radio" name="list-source-mode" checked={form.mode === "replace"} onChange={() => setForm({ ...form, mode: "replace" })} />
              {t("Retire them: the list is complete", "Stilllegen: die Liste ist vollständig")}
            </label>
          </fieldset>
          <label className="advisory-feeds-field">
            <span>{t("Credential header", "Header für die Anmeldung")}</span>
            <input
              className="system-input mono"
              value={form.authHeaderName}
              maxLength={64}
              disabled={form.removeCredential}
              onChange={(event) => setForm({ ...form, authHeaderName: event.target.value })}
              placeholder="Authorization"
            />
          </label>
          <label className="advisory-feeds-field">
            <span>{t("Credential", "Zugangsdaten")}</span>
            <input
              className="system-input mono"
              type="password"
              autoComplete="off"
              value={form.authHeaderValue}
              maxLength={4096}
              disabled={form.removeCredential}
              onChange={(event) => setForm({ ...form, authHeaderValue: event.target.value })}
              placeholder={edited?.authSet ? t("Stored; type to replace", "Gespeichert; zum Ersetzen eintippen") : "Token …"}
            />
          </label>
          {edited?.authSet && (
            <label className="list-sources-remove">
              <input
                type="checkbox"
                checked={form.removeCredential}
                onChange={(event) => setForm({ ...form, removeCredential: event.target.checked })}
              />
              {t("Remove the stored credential", "Gespeicherte Zugangsdaten entfernen")}
            </label>
          )}
          <p className="advisory-feeds-hint">
            {allowPrivate
              ? t("The credential is only sent over https and is never shown again.", "Zugangsdaten werden nur über https gesendet und nie wieder angezeigt.")
              : t(
                  "Only public addresses are accepted until the server allows internal ones. The credential is only sent over https.",
                  "Nur öffentliche Adressen werden angenommen, bis der Server interne erlaubt. Zugangsdaten werden nur über https gesendet.",
                )}
          </p>
          <div className="advisory-feeds-actions">
            <button type="submit" className="btn btn-primary" disabled={!canSave} aria-busy={saving || undefined}>
              <BusyLabel busy={saving}>{edited ? t("Save", "Speichern") : t("Add list", "Liste hinzufügen")}</BusyLabel>
            </button>
            <button type="button" className="btn btn-secondary" onClick={closeForm}>
              {t("Cancel", "Abbrechen")}
            </button>
          </div>
        </form>
      )}

      {status === "loading" ? (
        <LoadingRegion label={t("Loading server lists", "Serverlisten werden geladen")} className="system-skeleton">
          <SkeletonRows rows={2} height={36} />
        </LoadingRegion>
      ) : status === "error" ? (
        <ErrorState title={t("Server lists could not be loaded.", "Serverlisten konnten nicht geladen werden.")} />
      ) : sources.length === 0 ? (
        <EmptyState title={t("No server lists are fetched yet.", "Noch werden keine Serverlisten abgerufen.")} />
      ) : (
        <div className="table-scroll">
          <table className="system-table system-table--stack-actions advisory-feeds-table list-sources-table">
            <thead>
              <tr>
                <th scope="col">{t("List", "Liste")}</th>
                <th scope="col">{t("Fetch", "Abruf")}</th>
                <th scope="col">{t("Last fetch", "Letzter Abruf")}</th>
                <th scope="col">{t("State", "Status")}</th>
                <th scope="col" className="system-cell-action">{t("Actions", "Aktionen")}</th>
              </tr>
            </thead>
            <tbody>
              {sources.map((source) => {
                const outcome = outcomes[source.id];
                return (
                  <Fragment key={source.id}>
                    <tr className={source.enabled ? undefined : "advisory-feeds-off"}>
                      <td className="system-cell-name">
                        {source.source}
                        <code className="system-code list-sources-url">{source.url}</code>
                      </td>
                      <td data-label={t("Fetch", "Abruf")}>
                        <div className="list-sources-value">
                          {intervalLabel(source.intervalMinutes, t)}
                          <span className="list-sources-sub">
                            {source.mode === "replace" ? t("retires dropped systems", "legt Fehlende still") : t("keeps dropped systems", "behält Fehlende")}
                            {source.authSet && `, ${t("with credential", "mit Zugangsdaten")}`}
                          </span>
                        </div>
                      </td>
                      <td data-label={t("Last fetch", "Letzter Abruf")}>
                        <div className="list-sources-value">
                          {source.lastRunAt ? (
                            <>
                              {formatDateTime(source.lastRunAt)}
                              <span className={`list-sources-sub${source.lastStatus === "error" ? " list-sources-error" : ""}`}>
                                {source.lastStatus === "error"
                                  ? source.lastError
                                  : source.lastResult
                                    ? changesText(source.lastResult, t)
                                    : null}
                              </span>
                            </>
                          ) : (
                            <span className="list-sources-sub">
                              {source.nextRunAt ? t("Not fetched yet", "Noch nicht abgerufen") : t("Switched off", "Ausgeschaltet")}
                            </span>
                          )}
                        </div>
                      </td>
                      <td data-label={t("State", "Status")}>
                        <button
                          type="button"
                          className={`system-toggle${source.enabled ? "" : " system-toggle--off"}`}
                          aria-pressed={source.enabled}
                          disabled={isBusy(source.id)}
                          aria-busy={isBusy(source.id, "toggle") || undefined}
                          onClick={() => void handleToggle(source)}
                          title={t("Click to switch on or off", "Klicken zum Ein- oder Ausschalten")}
                        >
                          <BusyLabel busy={isBusy(source.id, "toggle")}>{source.enabled ? t("On", "An") : t("Off", "Aus")}</BusyLabel>
                        </button>
                      </td>
                      <td className="system-cell-action">
                        <span className="system-row-actions">
                          <button
                            type="button"
                            className="btn btn-secondary"
                            onClick={() => void handlePull(source, { dryRun: true })}
                            disabled={isBusy(source.id)}
                            aria-busy={isBusy(source.id, "preview") || undefined}
                          >
                            <BusyLabel busy={isBusy(source.id, "preview")}>{t("Preview", "Vorschau")}</BusyLabel>
                          </button>
                          <button
                            type="button"
                            className="btn btn-secondary"
                            onClick={() => void handlePull(source, {})}
                            disabled={isBusy(source.id)}
                            aria-busy={isBusy(source.id, "pull") || undefined}
                          >
                            <BusyLabel busy={isBusy(source.id, "pull")}>{t("Fetch now", "Jetzt abrufen")}</BusyLabel>
                          </button>
                          <button type="button" className="btn btn-secondary" onClick={() => openForm(source)} disabled={editing !== null}>
                            {t("Edit", "Bearbeiten")}
                          </button>
                          <button type="button" className="btn btn-secondary system-btn-danger" onClick={() => setDeleting(source)}>
                            {t("Remove", "Entfernen")}
                          </button>
                        </span>
                      </td>
                    </tr>
                    {outcome && (
                      <tr className="list-sources-outcome">
                        <td colSpan={5}>
                          <div role="status" className="list-sources-outcome-body">
                            {outcome.ok && outcome.result ? (
                              <span>
                                {outcome.result.dryRun
                                  ? t("Preview, nothing changed yet: ", "Vorschau, noch nichts geändert: ")
                                  : t("Fetched: ", "Abgerufen: ")}
                                {changesText(outcome.result, t)}
                                {outcome.result.skipped.length > 0 &&
                                  t(`; ${outcome.result.skipped.length} left out`, `; ${outcome.result.skipped.length} ausgelassen`)}
                                .
                              </span>
                            ) : (
                              <span className="list-sources-error">{outcome.error}</span>
                            )}
                            {outcome.errorKind === "too_destructive" && (
                              <button
                                type="button"
                                className="btn btn-secondary"
                                onClick={() => void handlePull(source, { force: true })}
                                disabled={isBusy(source.id)}
                                aria-busy={isBusy(source.id, "pull") || undefined}
                              >
                                <BusyLabel busy={isBusy(source.id, "pull")}>{t("Apply anyway", "Trotzdem anwenden")}</BusyLabel>
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {deleting && (
        <ConfirmDialog
          title={t(`Remove "${deleting.source}"?`, `„${deleting.source}“ entfernen?`)}
          message={t(
            "The list is no longer fetched. Its systems stay in the inventory, none is retired.",
            "Die Liste wird nicht mehr abgerufen. Ihre Systeme bleiben im Inventar, keines wird stillgelegt.",
          )}
          confirmLabel={t("Remove", "Entfernen")}
          onConfirm={() => handleDelete(deleting)}
          onCancel={() => setDeleting(null)}
        />
      )}
    </Section>
  );
};
