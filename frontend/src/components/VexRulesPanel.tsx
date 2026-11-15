import { useEffect, useState } from "react";
import type { AxiosError } from "axios";
import { LuPlay, LuPlus } from "react-icons/lu";

import "../screens/vex-rules.css";

import {
  applyVexRules,
  createVexRule,
  deleteVexRule,
  fetchVexRulePresets,
  fetchVexRules,
  updateVexRule,
} from "../api/vexRules";
import { useI18n, type TranslateFn } from "../i18n/context";
import type { VexRule, VexRuleConditions, VexRuleInput, VexRulePreset } from "../types";
import { BusyLabel, EmptyState, ErrorState, Section } from "../ui/primitives";
import { ConfirmDialog } from "./ConfirmDialog";
import { LoadingRegion, SkeletonRows } from "./Skeleton";
import { useToastContext } from "./ToastProvider";

const TARGET_TYPES: VexRuleConditions["targetTypes"] = ["container_image", "source_repo", "sbom-import"];
const SCOPES: VexRuleConditions["dependencyScopes"] = ["runtime", "optional", "dev", "unknown"];
const SEVERITIES = ["critical", "high", "medium", "low", "negligible"] as const;
const STATUSES: VexRuleInput["action"]["vexStatus"][] = ["not_affected", "under_investigation", "affected", "fixed"];

const errorDetail = (error: unknown, fallback: string): string => {
  const detail = (error as AxiosError<{ detail?: unknown }>).response?.data?.detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail) && detail[0] && typeof detail[0].msg === "string") return detail[0].msg;
  return fallback;
};

const statusLabel = (status: string, t: TranslateFn): string => {
  switch (status) {
    case "not_affected": return t("Not affected", "Nicht betroffen");
    case "affected": return t("Affected", "Betroffen");
    case "fixed": return t("Fixed", "Behoben");
    default: return t("Under investigation", "In Prüfung");
  }
};

const scopeLabel = (scope: string, t: TranslateFn): string => {
  switch (scope) {
    case "runtime": return t("Runtime", "Laufzeit");
    case "dev": return t("Dev", "Dev");
    case "optional": return t("Optional", "Optional");
    default: return t("Unknown", "Unbekannt");
  }
};

const targetTypeLabel = (type: string, t: TranslateFn): string => {
  switch (type) {
    case "container_image": return t("Container image", "Container-Image");
    case "source_repo": return t("Source repository", "Quell-Repository");
    default: return t("SBOM import", "SBOM-Import");
  }
};

/** One line per condition, for the table. */
const describeConditions = (c: VexRuleConditions, t: TranslateFn): string[] => {
  const parts: string[] = [];
  if (c.targetPattern) parts.push(t(`target ${c.targetPattern}`, `Ziel ${c.targetPattern}`));
  if (c.targetGroup) parts.push(t(`group ${c.targetGroup}`, `Gruppe ${c.targetGroup}`));
  if (c.targetTypes.length) parts.push(c.targetTypes.map(type => targetTypeLabel(type, t)).join(" / "));
  if (c.dependencyScopes.length) {
    parts.push(t("scope ", "Scope ") + c.dependencyScopes.map(s => scopeLabel(s, t)).join(" / "));
  }
  if (c.cweIds.length) {
    const shown = c.cweIds.slice(0, 4).join(", ");
    parts.push(c.cweIds.length > 4 ? `${shown} +${c.cweIds.length - 4}` : shown);
  }
  if (c.packagePattern) parts.push(t(`package ${c.packagePattern}`, `Paket ${c.packagePattern}`));
  if (c.ecosystems.length) parts.push(c.ecosystems.join(" / "));
  if (c.maxSeverity) parts.push(t(`severity ≤ ${c.maxSeverity}`, `Schweregrad ≤ ${c.maxSeverity}`));
  if (c.platformMismatch) parts.push(t("Windows/Apple OS only, Linux image", "nur Windows/Apple-OS, Linux-Image"));
  return parts;
};

interface FormState {
  name: string;
  description: string;
  enabled: boolean;
  priority: string;
  targetPattern: string;
  targetGroup: string;
  targetTypes: VexRuleConditions["targetTypes"];
  dependencyScopes: VexRuleConditions["dependencyScopes"];
  cweIds: string;
  packagePattern: string;
  ecosystems: string;
  maxSeverity: string;
  platformMismatch: boolean;
  vexStatus: VexRuleInput["action"]["vexStatus"];
  vexJustification: string;
  vexDetail: string;
  dismiss: boolean;
  preset: string | null;
}

const EMPTY_FORM: FormState = {
  name: "", description: "", enabled: false, priority: "100",
  targetPattern: "", targetGroup: "", targetTypes: [], dependencyScopes: [], cweIds: "",
  packagePattern: "", ecosystems: "", maxSeverity: "", platformMismatch: false,
  vexStatus: "not_affected", vexJustification: "", vexDetail: "", dismiss: false, preset: null,
};

const toForm = (rule: { name: string; description?: string | null; enabled?: boolean; priority: number;
  conditions: VexRuleConditions; action: VexRuleInput["action"]; preset?: string | null }): FormState => ({
  name: rule.name,
  description: rule.description ?? "",
  enabled: rule.enabled ?? false,
  priority: String(rule.priority),
  targetPattern: rule.conditions.targetPattern ?? "",
  targetGroup: rule.conditions.targetGroup ?? "",
  targetTypes: [...rule.conditions.targetTypes],
  dependencyScopes: [...rule.conditions.dependencyScopes],
  cweIds: rule.conditions.cweIds.join(", "),
  packagePattern: rule.conditions.packagePattern ?? "",
  ecosystems: rule.conditions.ecosystems.join(", "),
  maxSeverity: rule.conditions.maxSeverity ?? "",
  platformMismatch: rule.conditions.platformMismatch,
  vexStatus: rule.action.vexStatus,
  vexJustification: rule.action.vexJustification ?? "",
  vexDetail: rule.action.vexDetail ?? "",
  dismiss: rule.action.dismiss,
  preset: rule.preset ?? null,
});

const splitList = (value: string): string[] => value.split(/[,\s]+/).map(v => v.trim()).filter(Boolean);

const toInput = (form: FormState): VexRuleInput => ({
  name: form.name.trim(),
  description: form.description.trim() || null,
  enabled: form.enabled,
  priority: Math.max(0, Math.min(1000, Number.parseInt(form.priority, 10) || 100)),
  conditions: {
    targetPattern: form.targetPattern.trim() || null,
    targetGroup: form.targetGroup.trim() || null,
    targetTypes: form.targetTypes,
    dependencyScopes: form.dependencyScopes,
    cweIds: splitList(form.cweIds),
    packagePattern: form.packagePattern.trim() || null,
    ecosystems: splitList(form.ecosystems).map(e => e.toLowerCase()),
    maxSeverity: (form.maxSeverity || null) as VexRuleConditions["maxSeverity"],
    platformMismatch: form.platformMismatch,
  },
  action: {
    vexStatus: form.vexStatus,
    vexJustification: form.vexJustification || null,
    vexDetail: form.vexDetail.trim() || null,
    dismiss: form.dismiss,
  },
  preset: form.preset,
});

const hasCondition = (form: FormState): boolean => {
  const c = toInput(form).conditions;
  return !!(c.targetPattern || c.targetGroup || c.targetTypes.length || c.dependencyScopes.length || c.cweIds.length
    || c.packagePattern || c.ecosystems.length || c.maxSeverity || c.platformMismatch);
};

const toggle = <T extends string>(list: T[], value: T): T[] =>
  list.includes(value) ? list.filter(v => v !== value) : [...list, value];

/**
 * System -> Policies: automatic VEX triage rules. A rule fills the VEX status
 * of matching findings that have none (or one a rule set); hand-set,
 * imported, MCP, VEX-source and reachability statuses always win.
 */
export const VexRulesPanel = () => {
  const { t } = useI18n();
  const { showToast } = useToastContext();
  const [rules, setRules] = useState<VexRule[]>([]);
  const [presets, setPresets] = useState<VexRulePreset[]>([]);
  const [justifications, setJustifications] = useState<string[]>([]);
  const [status, setStatus] = useState<"loading" | "ready" | "error">("loading");
  const [refreshing, setRefreshing] = useState(false);
  // `null` = closed, "" = new rule, an id = editing that rule.
  const [editing, setEditing] = useState<string | null>(null);
  const [form, setForm] = useState<FormState>(EMPTY_FORM);
  const [saving, setSaving] = useState(false);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [applying, setApplying] = useState(false);
  const [deleting, setDeleting] = useState<VexRule | null>(null);

  const reload = async () => {
    setRefreshing(true);
    try {
      setRules((await fetchVexRules()).items);
    } catch {
      // keep what is shown; the next action reports its own error
    } finally {
      setRefreshing(false);
    }
  };

  useEffect(() => {
    let cancelled = false;
    Promise.all([fetchVexRules(), fetchVexRulePresets()])
      .then(([list, presetList]) => {
        if (cancelled) return;
        setRules(list.items);
        setPresets(presetList.items);
        setJustifications(presetList.justifications);
        setStatus("ready");
      })
      .catch(() => { if (!cancelled) setStatus("error"); });
    return () => { cancelled = true; };
  }, []);

  const openForm = (rule?: VexRule) => {
    setEditing(rule?.id ?? "");
    setForm(rule ? toForm(rule) : EMPTY_FORM);
  };

  const startFromPreset = (preset: VexRulePreset) => {
    setEditing("");
    setForm(toForm({ ...preset, enabled: false, preset: preset.key }));
  };

  const closeForm = () => {
    setEditing(null);
    setForm(EMPTY_FORM);
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      const payload = toInput(form);
      const saved = editing ? await updateVexRule(editing, payload) : await createVexRule(payload);
      showToast(
        saved.enabled
          ? t(`Rule "${saved.name}" saved and applied to the latest scans.`, `Regel „${saved.name}“ gespeichert und auf die neuesten Scans angewendet.`)
          : t(`Rule "${saved.name}" saved (switched off).`, `Regel „${saved.name}“ gespeichert (ausgeschaltet).`),
        "success",
      );
      closeForm();
      await reload();
    } catch (error) {
      showToast(errorDetail(error, t("Failed to save the rule.", "Regel konnte nicht gespeichert werden.")), "error");
    } finally {
      setSaving(false);
    }
  };

  const handleToggle = async (rule: VexRule) => {
    setBusyId(rule.id);
    try {
      await updateVexRule(rule.id, toInput({ ...toForm(rule), enabled: !rule.enabled }));
      await reload();
    } catch (error) {
      showToast(errorDetail(error, t("Failed to save the rule.", "Regel konnte nicht gespeichert werden.")), "error");
    } finally {
      setBusyId(null);
    }
  };

  const handleDelete = async (rule: VexRule) => {
    try {
      await deleteVexRule(rule.id);
      if (editing === rule.id) closeForm();
      showToast(t(`Rule "${rule.name}" deleted; the statuses it set are cleared.`, `Regel „${rule.name}“ gelöscht; ihre Status sind entfernt.`), "success");
      await reload();
    } catch (error) {
      showToast(errorDetail(error, t("Failed to delete the rule.", "Regel konnte nicht gelöscht werden.")), "error");
    } finally {
      setDeleting(null);
    }
  };

  const handleApply = async () => {
    setApplying(true);
    try {
      const result = await applyVexRules();
      showToast(
        t(
          `Applied to ${result.scans} latest scans: ${result.applied} statuses set, ${result.cleared} cleared.`,
          `Auf ${result.scans} neueste Scans angewendet: ${result.applied} Status gesetzt, ${result.cleared} entfernt.`,
        ),
        "success",
      );
      await reload();
    } catch (error) {
      showToast(errorDetail(error, t("Failed to apply the rules.", "Regeln konnten nicht angewendet werden.")), "error");
    } finally {
      setApplying(false);
    }
  };

  const canSave = form.name.trim().length > 0 && hasCondition(form) && !saving;

  return (
    <Section
      title={t("VEX rules", "VEX-Regeln")}
      actions={
        <>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => void handleApply()}
            disabled={applying || rules.every(r => !r.enabled)}
            aria-busy={applying || undefined}
          >
            <BusyLabel busy={applying}>
              {!applying && <LuPlay aria-hidden="true" />}
              {t("Apply to latest scans", "Auf neueste Scans anwenden")}
            </BusyLabel>
          </button>
          <button type="button" className="btn btn-secondary" onClick={() => openForm()} disabled={editing !== null}>
            <LuPlus aria-hidden="true" />
            {t("Add rule", "Regel hinzufügen")}
          </button>
        </>
      }
    >
      <p className="system-section-help">
        {t(
          "A rule sets a VEX status on findings that match all of its conditions, after every scan and SBOM import. It only fills findings without a status or with one a rule set: statuses set by hand, imported, from a VEX source or by reachability analysis always win. When a rule stops matching, is switched off or deleted, the statuses it set are removed again.",
          "Eine Regel setzt einen VEX-Status auf Ergebnisse, die alle ihre Bedingungen erfüllen, nach jedem Scan und SBOM-Import. Sie füllt nur Ergebnisse ohne Status oder mit einem von einer Regel gesetzten: von Hand gesetzte, importierte, aus einer VEX-Quelle oder aus der Erreichbarkeitsanalyse stammende Status gewinnen immer. Passt eine Regel nicht mehr, wird sie ausgeschaltet oder gelöscht, verschwinden ihre Status wieder.",
        )}
      </p>

      {presets.length > 0 && editing === null && (
        <div className="vex-rules-presets">
          <p className="vex-rules-presets-title">{t("Presets", "Vorlagen")}</p>
          <ul className="vex-rules-preset-list">
            {presets.map(preset => (
              <li key={preset.key} className="vex-rules-preset">
                <div>
                  <strong>{preset.name}</strong>
                  <p className="system-cell-sub">{preset.description}</p>
                </div>
                <button type="button" className="btn btn-secondary" onClick={() => startFromPreset(preset)}>
                  {t("Use", "Verwenden")}
                </button>
              </li>
            ))}
          </ul>
        </div>
      )}

      {editing !== null && (
        <form
          className="well system-form vex-rules-form"
          onSubmit={event => {
            event.preventDefault();
            if (canSave) void handleSave();
          }}
        >
          <h3 className="system-form-title vex-rules-span">
            {editing ? t("Edit rule", "Regel bearbeiten") : t("New rule", "Neue Regel")}
          </h3>
          <label className="vex-rules-field">
            <span>{t("Name", "Name")}</span>
            <input className="system-input" value={form.name} maxLength={120} onChange={e => setForm({ ...form, name: e.target.value })} />
          </label>
          <label className="vex-rules-field">
            <span>{t("Priority (lower runs first)", "Priorität (niedriger zuerst)")}</span>
            <input className="system-input" type="number" min={0} max={1000} value={form.priority} onChange={e => setForm({ ...form, priority: e.target.value })} />
          </label>
          <label className="vex-rules-field vex-rules-span">
            <span>{t("Description", "Beschreibung")}</span>
            <input className="system-input" value={form.description} maxLength={1000} onChange={e => setForm({ ...form, description: e.target.value })} />
          </label>

          <p className="vex-rules-group-title vex-rules-span">
            {t("Conditions (all set ones must hold)", "Bedingungen (alle gesetzten müssen zutreffen)")}
          </p>
          <label className="vex-rules-field">
            <span>{t("Target (wildcard on id or name)", "Ziel (Platzhalter auf ID oder Name)")}</span>
            <input className="system-input mono" value={form.targetPattern} placeholder="ghcr.io/acme/*" onChange={e => setForm({ ...form, targetPattern: e.target.value })} />
          </label>
          <label className="vex-rules-field">
            <span>{t("Application group", "Anwendungsgruppe")}</span>
            <input className="system-input" value={form.targetGroup} onChange={e => setForm({ ...form, targetGroup: e.target.value })} />
          </label>
          <fieldset className="vex-rules-checks">
            <legend>{t("Target type", "Zieltyp")}</legend>
            {TARGET_TYPES.map(type => (
              <label key={type}>
                <input type="checkbox" checked={form.targetTypes.includes(type)} onChange={() => setForm({ ...form, targetTypes: toggle(form.targetTypes, type) })} />
                {targetTypeLabel(type, t)}
              </label>
            ))}
          </fieldset>
          <fieldset className="vex-rules-checks">
            <legend>{t("Dependency scope", "Abhängigkeits-Scope")}</legend>
            {SCOPES.map(scope => (
              <label key={scope}>
                <input type="checkbox" checked={form.dependencyScopes.includes(scope)} onChange={() => setForm({ ...form, dependencyScopes: toggle(form.dependencyScopes, scope) })} />
                {scopeLabel(scope, t)}
              </label>
            ))}
          </fieldset>
          <label className="vex-rules-field">
            <span>{t("CWE ids (any of)", "CWE-IDs (eine davon)")}</span>
            <input className="system-input mono" value={form.cweIds} placeholder="CWE-400, CWE-1333" onChange={e => setForm({ ...form, cweIds: e.target.value })} />
          </label>
          <label className="vex-rules-field">
            <span>{t("Package (wildcard)", "Paket (Platzhalter)")}</span>
            <input className="system-input mono" value={form.packagePattern} placeholder="@types/*" onChange={e => setForm({ ...form, packagePattern: e.target.value })} />
          </label>
          <label className="vex-rules-field">
            <span>{t("Ecosystems (purl types)", "Ökosysteme (purl-Typen)")}</span>
            <input className="system-input mono" value={form.ecosystems} placeholder="npm, pypi" onChange={e => setForm({ ...form, ecosystems: e.target.value })} />
          </label>
          <label className="vex-rules-field">
            <span>{t("Severity at or below", "Schweregrad höchstens")}</span>
            <select className="system-input" value={form.maxSeverity} onChange={e => setForm({ ...form, maxSeverity: e.target.value })}>
              <option value="">{t("Any", "Beliebig")}</option>
              {SEVERITIES.map(sev => <option key={sev} value={sev}>{sev.charAt(0).toUpperCase() + sev.slice(1)}</option>)}
            </select>
          </label>
          <label className="vex-rules-check vex-rules-span">
            <input type="checkbox" checked={form.platformMismatch} onChange={e => setForm({ ...form, platformMismatch: e.target.checked })} />
            <span>
              {t("Only Windows or Apple operating systems are affected, and the target is a Linux image", "Nur Windows- oder Apple-Betriebssysteme betroffen, und das Ziel ist ein Linux-Image")}
              <span className="system-cell-sub">
                {t(
                  "Read from the vulnerability's CPE configurations; it matches only when every vulnerable configuration needs such an OS and the image's SBOM holds Linux distribution packages. When in doubt it does not match.",
                  "Aus den CPE-Konfigurationen der Schwachstelle gelesen; greift nur, wenn jede verwundbare Konfiguration ein solches OS braucht und das SBOM des Images Pakete einer Linux-Distribution enthält. Im Zweifel greift sie nicht.",
                )}
              </span>
            </span>
          </label>

          <p className="vex-rules-group-title vex-rules-span">{t("Action", "Aktion")}</p>
          <label className="vex-rules-field">
            <span>{t("VEX status", "VEX-Status")}</span>
            <select className="system-input" value={form.vexStatus} onChange={e => setForm({ ...form, vexStatus: e.target.value as FormState["vexStatus"] })}>
              {STATUSES.map(s => <option key={s} value={s}>{statusLabel(s, t)}</option>)}
            </select>
          </label>
          <label className="vex-rules-field">
            <span>{t("Justification", "Begründung")}</span>
            <select className="system-input mono" value={form.vexJustification} onChange={e => setForm({ ...form, vexJustification: e.target.value })}>
              <option value="">{t("None", "Keine")}</option>
              {justifications.map(j => <option key={j} value={j}>{j}</option>)}
            </select>
          </label>
          <label className="vex-rules-field vex-rules-span">
            <span>{t("Detail", "Detail")}</span>
            <textarea className="system-input" rows={2} maxLength={2000} value={form.vexDetail} onChange={e => setForm({ ...form, vexDetail: e.target.value })} />
          </label>
          <label className="vex-rules-check">
            <input type="checkbox" checked={form.dismiss} onChange={e => setForm({ ...form, dismiss: e.target.checked })} />
            <span>{t("Also dismiss the finding", "Ergebnis auch verwerfen")}</span>
          </label>
          <label className="vex-rules-check">
            <input type="checkbox" checked={form.enabled} onChange={e => setForm({ ...form, enabled: e.target.checked })} />
            <span>{t("Switched on", "Eingeschaltet")}</span>
          </label>
          {!hasCondition(form) && (
            <p className="vex-rules-hint vex-rules-span">{t("Set at least one condition.", "Mindestens eine Bedingung setzen.")}</p>
          )}
          <div className="system-form-actions vex-rules-span">
            <button type="submit" className="btn btn-primary" disabled={!canSave} aria-busy={saving || undefined}>
              <BusyLabel busy={saving}>{editing ? t("Save", "Speichern") : t("Create", "Erstellen")}</BusyLabel>
            </button>
            <button type="button" className="btn btn-secondary" onClick={closeForm}>
              {t("Cancel", "Abbrechen")}
            </button>
          </div>
        </form>
      )}

      {status === "loading" ? (
        <LoadingRegion label={t("Loading VEX rules", "VEX-Regeln werden geladen")} className="system-skeleton">
          <SkeletonRows rows={2} height={36} />
        </LoadingRegion>
      ) : status === "error" ? (
        <ErrorState title={t("VEX rules could not be loaded.", "VEX-Regeln konnten nicht geladen werden.")} />
      ) : rules.length === 0 ? (
        <EmptyState title={t("No VEX rules yet. Start from a preset above.", "Noch keine VEX-Regeln. Mit einer Vorlage oben beginnen.")} />
      ) : (
        <div className={`table-scroll${refreshing ? " is-refreshing" : ""}`} aria-busy={refreshing || undefined}>
          <table className="system-table system-table--stack-actions">
            <thead>
              <tr>
                <th scope="col">{t("Rule", "Regel")}</th>
                <th scope="col">{t("Sets", "Setzt")}</th>
                <th scope="col">{t("Findings", "Ergebnisse")}</th>
                <th scope="col">{t("State", "Zustand")}</th>
                <th scope="col" className="system-cell-action">{t("Actions", "Aktionen")}</th>
              </tr>
            </thead>
            <tbody>
              {rules.map(rule => (
                <tr key={rule.id} className={rule.enabled ? undefined : "vex-rules-off"}>
                  <td className="system-cell-name">
                    <div className="system-name-line">
                      <strong>{rule.name}</strong>
                      <span className="tag mono" title={t("Priority", "Priorität")}>{rule.priority}</span>
                    </div>
                    <p className="system-cell-sub">{describeConditions(rule.conditions, t).join(" · ")}</p>
                  </td>
                  <td data-label={t("Sets", "Setzt")}>
                    <span className="chip">{statusLabel(rule.action.vexStatus, t)}</span>
                    {rule.action.vexJustification && <span className="vex-rules-justification mono">{rule.action.vexJustification}</span>}
                    {rule.action.dismiss && <span className="vex-rules-justification">{t("+ dismiss", "+ verwerfen")}</span>}
                  </td>
                  <td data-label={t("Findings", "Ergebnisse")} className="vex-rules-count" title={t("Findings in the latest scans that carry this rule's status", "Ergebnisse in den neuesten Scans mit dem Status dieser Regel")}>
                    {rule.findingCount}
                  </td>
                  <td data-label={t("State", "Zustand")}>
                    <button
                      type="button"
                      className={`system-toggle${rule.enabled ? "" : " system-toggle--off"}`}
                      aria-pressed={rule.enabled}
                      disabled={busyId === rule.id}
                      aria-busy={busyId === rule.id || undefined}
                      onClick={() => void handleToggle(rule)}
                      title={t("Click to switch on or off", "Klicken zum Ein- oder Ausschalten")}
                    >
                      <BusyLabel busy={busyId === rule.id}>{rule.enabled ? t("On", "An") : t("Off", "Aus")}</BusyLabel>
                    </button>
                  </td>
                  <td className="system-cell-action">
                    <span className="system-row-actions">
                      <button type="button" className="btn btn-secondary" onClick={() => openForm(rule)} disabled={editing !== null}>
                        {t("Edit", "Bearbeiten")}
                      </button>
                      <button type="button" className="btn btn-secondary system-btn-danger" onClick={() => setDeleting(rule)}>
                        {t("Delete", "Löschen")}
                      </button>
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {deleting && (
        <ConfirmDialog
          title={t(`Delete "${deleting.name}"?`, `„${deleting.name}“ löschen?`)}
          message={t(
            "The VEX statuses this rule set are removed from every scan. Another rule may fill them again.",
            "Die VEX-Status dieser Regel werden aus allen Scans entfernt. Eine andere Regel kann sie wieder füllen.",
          )}
          confirmLabel={t("Delete", "Löschen")}
          onConfirm={() => handleDelete(deleting)}
          onCancel={() => setDeleting(null)}
        />
      )}
    </Section>
  );
};
