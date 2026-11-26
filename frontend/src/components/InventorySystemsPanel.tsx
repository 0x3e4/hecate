import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { LuPencil, LuPlus, LuTrash2, LuX } from "react-icons/lu";

import {
  createInventorySystem,
  deleteInventorySystem,
  updateInventorySystem,
  type InventorySystemInput,
} from "../api/inventory";
import { useI18n } from "../i18n/context";
import type { InventorySystem, InventorySystemReportStatus } from "../types";
import { BusyLabel, EmptyState, IconButton, Section, SeverityTag, Stat } from "../ui/primitives";
import { describeError } from "../utils/apiError";
import { severityLabel } from "../utils/cveGroups";
import { formatDateTime } from "../utils/dateFormat";
import {
  matchesSystemFilters,
  parseGroups,
  reportAgeLabel,
  reportStatusLabel,
  sortSystems,
  systemStats,
  type SystemFilters,
} from "../utils/inventorySystems";
import { TARGET_KINDS, exposureLabel, kindLabel } from "../utils/targetClass";
import { ConfirmDialog } from "./ConfirmDialog";
import { DocsLink } from "./DocsLink";
import { TargetClassChips } from "./TargetClassChips";
import { useToastContext } from "./ToastProvider";

const STATUSES: InventorySystemReportStatus[] = ["stale", "never", "reporting"];

interface FormState {
  name: string;
  kind: string;
  exposure: string;
  environment: string;
  owner: string;
  groups: string;
  notes: string;
}

const EMPTY_FORM: FormState = { name: "", kind: "host", exposure: "", environment: "", owner: "", groups: "", notes: "" };

const formFor = (system: InventorySystem): FormState => ({
  name: system.name,
  kind: system.kind ?? "",
  exposure: system.exposure ?? "",
  environment: system.environment ?? "",
  owner: system.owner ?? "",
  groups: system.groups.join(", "),
  notes: system.notes ?? "",
});

const worstSeverity = (system: InventorySystem): string | null => {
  const summary = system.latestSummary;
  if (!summary) return null;
  for (const level of ["critical", "high", "medium", "low"] as const) {
    if (summary[level] > 0) return level;
  }
  return null;
};

/**
 * Inventory → Systems: the servers, nodes and other systems you run, whether
 * each one still sends its SBOM, and what its last one found
 * (docs/guide/inventory.md#systems).
 */
export const InventorySystemsPanel = ({
  systems,
  staleAfterDays,
  loaded,
  environmentSuggestions,
  onChanged,
}: {
  systems: InventorySystem[];
  staleAfterDays: number;
  loaded: boolean;
  environmentSuggestions: string[];
  onChanged: () => Promise<void> | void;
}) => {
  const { t } = useI18n();
  const { showToast } = useToastContext();
  const [filters, setFilters] = useState<SystemFilters>({ query: "", status: "", kind: "" });
  const [editing, setEditing] = useState<InventorySystem | "new" | null>(null);
  const [form, setForm] = useState<FormState>(EMPTY_FORM);
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [deleteCandidate, setDeleteCandidate] = useState<InventorySystem | null>(null);

  const stats = useMemo(() => systemStats(systems), [systems]);
  const visible = useMemo(
    () => sortSystems(systems.filter((s) => matchesSystemFilters(s, filters))),
    [systems, filters],
  );

  const open = (system: InventorySystem | "new") => {
    setEditing(system);
    setForm(system === "new" ? EMPTY_FORM : formFor(system));
    setFormError(null);
  };
  const close = () => {
    if (!saving) setEditing(null);
  };

  const save = async () => {
    if (!form.name.trim()) {
      setFormError(t("A name is needed.", "Ein Name ist nötig."));
      return;
    }
    const payload: InventorySystemInput = {
      name: form.name.trim(),
      kind: (form.kind || null) as InventorySystem["kind"],
      exposure: (form.exposure || null) as InventorySystem["exposure"],
      environment: form.environment.trim() || null,
      owner: form.owner.trim() || null,
      notes: form.notes.trim() || null,
      groups: parseGroups(form.groups),
    };
    setSaving(true);
    setFormError(null);
    try {
      if (editing === "new") {
        await createInventorySystem(payload);
        showToast(t(`${payload.name} added.`, `${payload.name} hinzugefügt.`), "success");
      } else if (editing) {
        await updateInventorySystem(editing.id, payload);
        showToast(t(`${payload.name} saved.`, `${payload.name} gespeichert.`), "success");
      }
      setEditing(null);
      await onChanged();
    } catch (err) {
      const described = describeError(err);
      setFormError(
        described.status === 409
          ? t("A system with this name already exists.", "Ein System mit diesem Namen gibt es bereits.")
          : described.detail || t("Saving failed.", "Speichern fehlgeschlagen."),
      );
    } finally {
      setSaving(false);
    }
  };

  const remove = async (system: InventorySystem) => {
    try {
      await deleteInventorySystem(system.id);
      showToast(t(`${system.name} removed.`, `${system.name} entfernt.`), "success");
      setDeleteCandidate(null);
      await onChanged();
    } catch {
      showToast(t("Removing failed.", "Entfernen fehlgeschlagen."), "error");
    }
  };

  return (
    <>
      {systems.length > 0 && (
        <dl className="stat-row inventory-stats">
          <Stat label={t(stats.total === 1 ? "System" : "Systems", stats.total === 1 ? "System" : "Systeme")} value={stats.total} />
          <Stat label={t("Reporting", "Melden")} value={stats.reporting} />
          <Stat
            label={t(`No report for ${staleAfterDays}+ days`, `Seit ${staleAfterDays}+ Tagen keine Meldung`)}
            value={stats.stale}
          />
          <Stat label={t("Never reported", "Nie gemeldet")} value={stats.never} />
          <Stat label={t("Internet-facing", "Aus dem Internet erreichbar")} value={stats.internet} />
        </dl>
      )}

      <Section
        title={t("Systems", "Systeme")}
        className="inventory-systems"
        actions={
          <button type="button" className="btn btn-primary" onClick={() => open("new")}>
            <LuPlus aria-hidden="true" />
            {t("Add system", "System hinzufügen")}
          </button>
        }
      >
        <p className="inventory-note">
          {t(
            "Servers, VMs and nodes you run. Each one sends its SBOM or scanner report; the list shows which ones stopped. ",
            "Server, VMs und Nodes, die Sie betreiben. Jedes sendet sein SBOM oder seinen Scanner-Bericht; die Liste zeigt, welche damit aufgehört haben. ",
          )}
          <DocsLink path="sca/hosts/">{t("Sending SBOMs", "SBOMs senden")}</DocsLink>
        </p>

        {systems.length > 0 && (
          <div className="filter-row">
            <input
              type="search"
              className="inventory-search"
              aria-label={t("Search systems", "Systeme durchsuchen")}
              placeholder={t("Name, group, owner, product…", "Name, Gruppe, Verantwortlich, Produkt…")}
              value={filters.query}
              onChange={(e) => setFilters({ ...filters, query: e.target.value })}
            />
            <label className="inventory-control">
              <span>{t("Report", "Meldung")}</span>
              <select
                value={filters.status}
                onChange={(e) => setFilters({ ...filters, status: e.target.value as SystemFilters["status"] })}
              >
                <option value="">{t("All", "Alle")}</option>
                {STATUSES.map((status) => (
                  <option key={status} value={status}>{reportStatusLabel(status, t)}</option>
                ))}
              </select>
            </label>
            <label className="inventory-control">
              <span>{t("Kind", "Art")}</span>
              <select value={filters.kind} onChange={(e) => setFilters({ ...filters, kind: e.target.value })}>
                <option value="">{t("All", "Alle")}</option>
                {TARGET_KINDS.map((kind) => (
                  <option key={kind} value={kind}>{kindLabel(kind, t)}</option>
                ))}
              </select>
            </label>
          </div>
        )}

        {!loaded ? null : systems.length === 0 ? (
          <EmptyState title={t("No systems yet.", "Noch keine Systeme.")}>
            {t(
              "Add one by hand, or let a host push its SBOM with a kind (host, Kubernetes node): it appears here on its own.",
              "Legen Sie eines von Hand an, oder lassen Sie einen Host sein SBOM mit einer Art (Host, Kubernetes-Node) senden: Es erscheint dann von selbst hier.",
            )}
          </EmptyState>
        ) : visible.length === 0 ? (
          <EmptyState title={t("No systems match your search or filters.", "Keine Systeme passen zu Suche oder Filtern.")} />
        ) : (
          <div className="table-scroll">
            <table className="inventory-table inventory-systems-table">
              <thead>
                <tr>
                  <th scope="col">{t("System", "System")}</th>
                  <th scope="col">{t("Last report", "Letzte Meldung")}</th>
                  <th scope="col">{t("Worst severity", "Höchster Schweregrad")}</th>
                  <th scope="col">{t("Findings", "Funde")}</th>
                  <th scope="col">{t("Products", "Produkte")}</th>
                  <th scope="col">{t("Environment", "Umgebung")}</th>
                  <th scope="col"><span className="visually-hidden">{t("Actions", "Aktionen")}</span></th>
                </tr>
              </thead>
              <tbody>
                {visible.map((system) => {
                  const worst = worstSeverity(system);
                  return (
                    <tr key={system.id}>
                      <td className="inventory-cell-name">
                        <div className="inventory-systems-name">
                          {system.targetId ? (
                            <Link to={`/scans/targets/${encodeURIComponent(system.targetId)}`}>{system.name}</Link>
                          ) : (
                            <span>{system.name}</span>
                          )}
                          <TargetClassChips kind={system.kind} exposure={system.exposure} />
                        </div>
                        {(system.groups.length > 0 || system.owner) && (
                          <div className="inventory-systems-sub">
                            {system.groups.length > 0 && <span>{system.groups.join(", ")}</span>}
                            {system.owner && <span>{system.owner}</span>}
                          </div>
                        )}
                        {system.notes && <div className="inventory-systems-notes">{system.notes}</div>}
                      </td>
                      <td className="inventory-systems-report" title={system.lastReportAt ? formatDateTime(system.lastReportAt) : undefined}>
                        <span className={`inventory-systems-status is-${system.reportStatus}`}>
                          {system.reportStatus === "reporting"
                            ? reportAgeLabel(system.lastReportAt, t)
                            : reportStatusLabel(system.reportStatus, t)}
                        </span>
                        {system.reportStatus === "stale" && (
                          <span className="inventory-systems-age">{reportAgeLabel(system.lastReportAt, t)}</span>
                        )}
                      </td>
                      <td className="inventory-cell-severity">
                        {worst && <SeverityTag severity={worst}>{severityLabel(worst, t)}</SeverityTag>}
                      </td>
                      <td className="inventory-systems-findings">
                        {system.latestScanId ? (
                          <Link to={`/scans/${encodeURIComponent(system.latestScanId)}`}>
                            {system.latestSummary?.total ?? 0}
                            <span className="inventory-unit"> {t("findings", "Funde")}</span>
                          </Link>
                        ) : (
                          <span className="inventory-systems-none">–</span>
                        )}
                      </td>
                      <td className="inventory-systems-products">
                        {system.products.length > 0
                          ? system.products.map((p) => `${p.name} ${p.version}`).join(", ")
                          : <span className="inventory-systems-none">–</span>}
                      </td>
                      <td className="inventory-cell-meta">{system.environment || <span className="inventory-systems-none">–</span>}</td>
                      <td className="inventory-cell-actions">
                        <div className="inventory-actions">
                          <IconButton label={t(`Edit ${system.name}`, `${system.name} bearbeiten`)} onClick={() => open(system)}>
                            <LuPencil aria-hidden="true" />
                          </IconButton>
                          <IconButton
                            label={t(`Remove ${system.name}`, `${system.name} entfernen`)}
                            className="inventory-delete"
                            onClick={() => setDeleteCandidate(system)}
                          >
                            <LuTrash2 aria-hidden="true" />
                          </IconButton>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Section>

      {deleteCandidate && (
        <ConfirmDialog
          title={t(`Remove ${deleteCandidate.name}?`, `${deleteCandidate.name} entfernen?`)}
          message={t(
            "The system leaves the inventory. Its findings and scan history stay, as an SCA target.",
            "Das System verschwindet aus dem Inventar. Seine Funde und der Scan-Verlauf bleiben, als SCA-Ziel.",
          )}
          confirmLabel={t("Remove", "Entfernen")}
          onConfirm={() => remove(deleteCandidate)}
          onCancel={() => setDeleteCandidate(null)}
        />
      )}

      {editing && (
        <div className="dialog-overlay" role="presentation" onClick={close}>
          <div
            className="dialog dialog--wide"
            role="dialog"
            aria-modal="true"
            aria-labelledby="inventory-system-dialog-title"
            onClick={(e) => e.stopPropagation()}
            onKeyDown={(e) => {
              if (e.key === "Escape") close();
            }}
          >
            <div className="dialog-head">
              <h3 id="inventory-system-dialog-title">
                {editing === "new" ? t("Add system", "System hinzufügen") : t("Edit system", "System bearbeiten")}
              </h3>
              <button type="button" className="dialog-close" onClick={close} aria-label={t("Close", "Schließen")}>
                <LuX aria-hidden="true" />
              </button>
            </div>
            <form
              className="inventory-form"
              onSubmit={(e) => {
                e.preventDefault();
                void save();
              }}
            >
              <div className="inventory-field inventory-field--full">
                <label className="inventory-label" htmlFor="system-name">{t("Name", "Name")}</label>
                <input
                  id="system-name"
                  type="text"
                  className="inventory-input"
                  autoFocus
                  value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                  placeholder="web-01.example.com"
                  aria-describedby="system-name-hint"
                />
                <p id="system-name-hint" className="inventory-systems-hint">
                  {t(
                    "Use the name the host sends as targetName: its SBOM then lands here.",
                    "Den Namen, den der Host als targetName sendet: Sein SBOM landet dann hier.",
                  )}
                </p>
              </div>
              <div className="inventory-field">
                <label className="inventory-label" htmlFor="system-kind">{t("Kind", "Art")}</label>
                <select id="system-kind" value={form.kind} onChange={(e) => setForm({ ...form, kind: e.target.value })}>
                  <option value="">{t("Unknown", "Unbekannt")}</option>
                  {TARGET_KINDS.map((kind) => (
                    <option key={kind} value={kind}>{kindLabel(kind, t)}</option>
                  ))}
                </select>
              </div>
              <div className="inventory-field">
                <label className="inventory-label" htmlFor="system-exposure">{t("Reachable from", "Erreichbar von")}</label>
                <select id="system-exposure" value={form.exposure} onChange={(e) => setForm({ ...form, exposure: e.target.value })}>
                  <option value="">{t("Unknown", "Unbekannt")}</option>
                  <option value="internet">{exposureLabel("internet", t)}</option>
                  <option value="internal">{exposureLabel("internal", t)}</option>
                </select>
              </div>
              <div className="inventory-field">
                <label className="inventory-label" htmlFor="system-environment">{t("Environment", "Umgebung")}</label>
                <input
                  id="system-environment"
                  type="text"
                  className="inventory-input"
                  list="system-environment-suggestions"
                  value={form.environment}
                  onChange={(e) => setForm({ ...form, environment: e.target.value })}
                  placeholder="prod"
                />
                <datalist id="system-environment-suggestions">
                  {environmentSuggestions.map((env) => <option key={env} value={env} />)}
                </datalist>
              </div>
              <div className="inventory-field">
                <label className="inventory-label" htmlFor="system-owner">{t("Owner", "Verantwortlich")}</label>
                <input
                  id="system-owner"
                  type="text"
                  className="inventory-input"
                  value={form.owner}
                  onChange={(e) => setForm({ ...form, owner: e.target.value })}
                />
              </div>
              <div className="inventory-field inventory-field--full">
                <label className="inventory-label" htmlFor="system-groups">{t("Groups", "Gruppen")}</label>
                <input
                  id="system-groups"
                  type="text"
                  className="inventory-input"
                  value={form.groups}
                  onChange={(e) => setForm({ ...form, groups: e.target.value })}
                  placeholder={t("dmz, cluster-a, payments", "dmz, cluster-a, zahlungen")}
                />
              </div>
              <div className="inventory-field inventory-field--full">
                <label className="inventory-label" htmlFor="system-notes">{t("Notes", "Notizen")}</label>
                <textarea
                  id="system-notes"
                  className="inventory-input"
                  rows={2}
                  value={form.notes}
                  onChange={(e) => setForm({ ...form, notes: e.target.value })}
                />
              </div>
              {formError && <p className="inventory-systems-error inventory-field--full" role="alert">{formError}</p>}
              <div className="dialog-actions inventory-dialog-actions inventory-field--full">
                <button type="button" className="btn" onClick={close} disabled={saving}>
                  {t("Cancel", "Abbrechen")}
                </button>
                <button type="submit" className="btn btn-primary" disabled={saving} aria-busy={saving || undefined}>
                  <BusyLabel busy={saving}>{t("Save", "Speichern")}</BusyLabel>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </>
  );
};
