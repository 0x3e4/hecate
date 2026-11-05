import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import { Link, useNavigate } from "react-router-dom";
import AsyncSelect from "react-select/async";
import { LuArrowRight, LuChevronRight, LuCopy, LuPencil, LuPlus, LuTrash2, LuX } from "react-icons/lu";

import "../screens/inventory.css";
import {
  createInventoryItem,
  deleteInventoryItem,
  fetchInventoryAffectedVulnerabilities,
  fetchInventoryHistory,
  fetchInventoryItemHistory,
  fetchInventoryItems,
  updateInventoryItem,
  type InventoryItemCreateInput,
} from "../api/inventory";
import { fetchEolProducts, fetchInventoryEol } from "../api/endoflife";
import { fetchProducts, fetchVendors } from "../api/assets";
import { renderCatalogOption } from "../components/CatalogOption";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { SkeletonBlock } from "../components/Skeleton";
import { useToastContext } from "../components/ToastProvider";
import { useServerConfig } from "../server-config/context";
import { useI18n, type TranslateFn } from "../i18n/context";
import type {
  AffectedVulnerabilityItem,
  CatalogProduct,
  CatalogVendor,
  EolStatus,
  EolStatusKind,
  InventoryDeployment,
  InventoryEnvironment,
  InventoryHistoryChange,
  InventoryHistoryEntry,
  InventoryItem,
} from "../types";
import { EmptyState, ErrorState, IconButton, PageHeader, Section, SeverityTag, Stat } from "../ui/primitives";
import { primaryVendorSlug } from "../utils/catalog";
import { formatDateTime } from "../utils/dateFormat";
import { safeHref } from "../utils/safeHref";
const DEPLOYMENTS: InventoryDeployment[] = ["onprem", "cloud", "hybrid"];
const DEFAULT_ENVIRONMENT_SUGGESTIONS: string[] = ["prod", "staging", "dev", "test", "dr"];

const SELECT_LIMIT = 200;

const deploymentLabel = (value: InventoryDeployment, t: TranslateFn) => {
  switch (value) {
    case "onprem":
      return t("On-Prem", "On-Prem");
    case "cloud":
      return t("Cloud", "Cloud");
    case "hybrid":
      return t("Hybrid", "Hybrid");
    default:
      return value;
  }
};

const environmentLabel = (value: InventoryEnvironment, t: TranslateFn) => {
  switch (value.toLowerCase()) {
    case "prod":
    case "production":
      return t("Production", "Produktion");
    case "staging":
    case "stage":
      return t("Staging", "Staging");
    case "dev":
    case "development":
      return t("Development", "Entwicklung");
    case "test":
    case "testing":
    case "qa":
      return t("Test", "Test");
    case "dr":
      return t("Disaster Recovery", "Disaster Recovery");
    default:
      return value;
  }
};

const severityOf = (severity: string | null | undefined): "critical" | "high" | "medium" | "low" | "unknown" => {
  const lower = (severity || "").toLowerCase();
  if (lower === "critical" || lower === "high" || lower === "medium" || lower === "low") {
    return lower;
  }
  return "unknown";
};

const severityLabel = (severity: ReturnType<typeof severityOf>, t: TranslateFn): string => {
  switch (severity) {
    case "critical":
      return t("Critical", "Kritisch");
    case "high":
      return t("High", "Hoch");
    case "medium":
      return t("Medium", "Mittel");
    case "low":
      return t("Low", "Niedrig");
    default:
      return t("Unknown", "Unbekannt");
  }
};

// Sort rank for the aggregated CVE table (mirrors the backend severity order).
const SEVERITY_RANK: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  unknown: 4,
};

// --- endoflife.date status presentation ---

interface EolOption {
  value: string;
  label: string;
}

const eolStatusLabel = (status: EolStatusKind, t: TranslateFn): string => {
  switch (status) {
    case "active":
      return t("Active support", "Aktiver Support");
    case "security":
      return t("Security support", "Security-Support");
    case "eol":
      return t("End of life", "End of Life");
    default:
      return t("Support unknown", "Support unbekannt");
  }
};

// Support end date for the version's release cycle, phrased per status.
const eolUntilLabel = (status: EolStatus, t: TranslateFn): string | null => {
  if (status.status === "active") {
    if (status.eoasDate) return t(`active until ${status.eoasDate}`, `aktiv bis ${status.eoasDate}`);
    if (status.eolDate)
      return t(`supported until ${status.eolDate}`, `unterstützt bis ${status.eolDate}`);
    return null;
  }
  if (status.status === "security") {
    return status.eolDate
      ? t(`security until ${status.eolDate}`, `Security bis ${status.eolDate}`)
      : null;
  }
  if (status.status === "eol") return status.eolDate ?? null;
  return null;
};

// Compact status for the row, in words: support status (+ date), LTS, and
// "update available" only. The verbose detail (latest release, newer line,
// link, dates) lives in the expandable `EolDetailBlock` below, to keep the
// row readable.
const EolStatusBadge = ({ status, t }: { status: EolStatus; t: TranslateFn }) => {
  const untilLabel = eolUntilLabel(status, t);
  return (
    <div className="inventory-eol">
      <span
        className={`inventory-eol-status inventory-eol-status--${status.status}`}
        title={status.productLabel ?? undefined}
      >
        {eolStatusLabel(status.status, t)}
      </span>
      {untilLabel && <span className="inventory-eol-until">{untilLabel}</span>}
      {status.isLts && (
        <span className="chip" title={status.ltsFrom ? `LTS since ${status.ltsFrom}` : undefined}>
          LTS
        </span>
      )}
      {status.isOutdated && <span className="chip">{t("update available", "Update verfügbar")}</span>}
    </div>
  );
};

// Full endoflife.date detail, shown inside the row's expansion above the CVEs.
const EolDetailBlock = ({ status, t }: { status: EolStatus; t: TranslateFn }) => {
  const productHref =
    status.productLink || (status.product ? `https://endoflife.date/${status.product}` : null);
  const rows: { label: string; value: ReactNode }[] = [];
  if (status.matchedCycle)
    rows.push({
      label: t("Release cycle", "Release-Zyklus"),
      value: <span className="mono">{status.matchedCycle}</span>,
    });
  if (status.releaseDate)
    rows.push({ label: t("Released", "Veröffentlicht"), value: status.releaseDate });
  if (status.eoasDate)
    rows.push({ label: t("Active support until", "Aktiver Support bis"), value: status.eoasDate });
  if (status.eolDate)
    rows.push({ label: t("End of life", "End of Life"), value: status.eolDate });
  if (status.isLts)
    rows.push({
      label: "LTS",
      value: status.ltsFrom ? t(`since ${status.ltsFrom}`, `seit ${status.ltsFrom}`) : t("yes", "ja"),
    });
  if (status.latestVersion)
    rows.push({
      label: t("Latest release", "Neueste Version"),
      value: (
        <span className="inventory-eol-latest">
          {status.latestLink ? (
            <a href={safeHref(status.latestLink)} target="_blank" rel="noreferrer" className="mono">
              {status.latestVersion}
            </a>
          ) : (
            <span className="mono">{status.latestVersion}</span>
          )}
          {status.isOutdated && <span className="chip">{t("update available", "Update verfügbar")}</span>}
        </span>
      ),
    });
  if (!status.isLatestCycle && status.latestCycle)
    rows.push({
      label: t("Newer release line", "Neuere Release-Linie"),
      value: <span className="mono">{status.latestCycle}</span>,
    });

  return (
    <div className="inventory-eol-detail">
      <div className="inventory-expansion-head">
        <h3>{t("End-of-life", "End of Life")}</h3>
        {status.productLabel && <span className="inventory-expansion-sub">{status.productLabel}</span>}
        {productHref && (
          <span className="link-list">
            <a href={safeHref(productHref)} target="_blank" rel="noreferrer" title="endoflife.date">
              endoflife.date
            </a>
          </span>
        )}
      </div>
      <dl className="inventory-eol-rows">
        {rows.map((r, i) => (
          <div key={i} className="inventory-eol-row">
            <dt>{r.label}</dt>
            <dd>{r.value}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
};

const emptyForm = (): InventoryItemCreateInput => ({
  name: "",
  vendorSlug: "",
  productSlug: "",
  vendorName: "",
  productName: "",
  version: "",
  deployment: "onprem",
  environment: "prod",
  instanceCount: 1,
  owner: "",
  notes: "",
  changeNote: "",
});

// --- AsyncSelect option types + styles (mirrors components/AssetFilters.tsx) ---

interface VendorOption {
  value: string;
  label: string;
  aliases: string[];
  vulnerabilityCount?: number | null;
}

interface ProductOption {
  value: string;
  label: string;
  vendorSlugs: string[];
  aliases: string[];
  vulnerabilityCount?: number | null;
  hint?: string | null;
}

const mapVendorToOption = (item: CatalogVendor): VendorOption => ({
  value: item.slug,
  label: item.name,
  aliases: item.aliases,
  vulnerabilityCount: item.vulnerabilityCount,
});

const mapProductToOption = (item: CatalogProduct): ProductOption => ({
  value: item.slug,
  label: item.name,
  vendorSlugs: item.vendorSlugs,
  aliases: item.aliases,
  vulnerabilityCount: item.vulnerabilityCount,
  hint: primaryVendorSlug(item.slug, item.vendorSlugs),
});

const selectStyles = {
  control: (provided: any, state: any) => ({
    ...provided,
    background: "var(--color-paper)",
    borderColor: "var(--color-field-edge)",
    borderRadius: "var(--radius-control)",
    color: "var(--color-ink)",
    boxShadow: "none",
    minHeight: "var(--control-height)",
    outline: state.isFocused ? "2px solid var(--color-focus)" : "none",
    outlineOffset: "-1px",
    "&:hover": {
      borderColor: "var(--color-field-edge)",
    },
  }),
  menu: (provided: any) => ({
    ...provided,
    background: "var(--color-paper)",
    zIndex: 100,
  }),
  menuPortal: (provided: any) => ({
    ...provided,
    // Must exceed the .dialog-overlay (z-index 12000) so the dropdown menus
    // render above the modal backdrop instead of being clipped behind it.
    zIndex: 12100,
  }),
  option: (provided: any, state: any) => ({
    ...provided,
    backgroundColor: state.isFocused ? "var(--overlay-3)" : "transparent",
    color: "var(--color-ink)",
  }),
  singleValue: (provided: any) => ({
    ...provided,
    color: "var(--color-ink)",
  }),
  indicatorSeparator: () => ({
    display: "none",
  }),
  valueContainer: (provided: any) => ({
    ...provided,
    paddingBlock: 0,
  }),
  dropdownIndicator: (provided: any) => ({
    ...provided,
    paddingBlock: 0,
  }),
  clearIndicator: (provided: any) => ({
    ...provided,
    paddingBlock: 0,
  }),
  input: (provided: any) => ({
    ...provided,
    color: "var(--color-ink)",
    margin: 0,
    paddingBlock: 0,
    "& input": {
      outline: "none !important",
      boxShadow: "none !important",
      border: "none !important",
      // The dialog's text-input rules would otherwise pad the search box inside the control.
      margin: "0 !important",
      padding: "0 !important",
      minHeight: "0 !important",
    },
  }),
  placeholder: (provided: any) => ({
    ...provided,
    color: "var(--color-muted)",
    whiteSpace: "nowrap",
    overflow: "hidden",
    textOverflow: "ellipsis",
  }),
};

// Vendor / product option in the catalog pickers: name plus up to two aliases.
// Latest release of the matched cycle, offered as a one-click version. Never
// applied on its own: the inventory states what runs, and a version nobody
// deployed would silently clear real CVE matches.
const VersionUpdateForm = ({
  item,
  suggested,
  onSaved,
  t,
}: {
  item: InventoryItem;
  suggested: string | null;
  onSaved: (updated: InventoryItem) => void;
  t: TranslateFn;
}) => {
  const { showToast } = useToastContext();
  const [value, setValue] = useState(item.version);
  const [note, setNote] = useState("");
  const [saving, setSaving] = useState(false);

  const save = async (version: string) => {
    setSaving(true);
    try {
      const updated = await updateInventoryItem(item.id, { version, changeNote: note.trim() || null });
      setValue(updated.version);
      setNote("");
      onSaved(updated);
    } catch (exc: unknown) {
      showToast(exc instanceof Error ? exc.message : String(exc), "error");
    } finally {
      setSaving(false);
    }
  };

  const trimmed = value.trim();
  return (
    <form
      className="inventory-version-form"
      onSubmit={(event) => {
        event.preventDefault();
        if (trimmed && trimmed !== item.version) void save(trimmed);
      }}
    >
      <label htmlFor={`inventory-version-${item.id}`}>{t("Running version", "Laufende Version")}</label>
      <div className="inventory-version-controls">
        <input
          id={`inventory-version-${item.id}`}
          className="mono"
          value={value}
          onChange={(event) => setValue(event.target.value)}
          autoComplete="off"
          spellCheck={false}
        />
        <button
          type="submit"
          className="btn btn-secondary"
          disabled={saving || !trimmed || trimmed === item.version}
        >
          {t("Update", "Aktualisieren")}
        </button>
      </div>
      <input
        className="inventory-version-note"
        value={note}
        onChange={(event) => setNote(event.target.value)}
        maxLength={500}
        placeholder={t("Note for the history: ticket, server… (optional)", "Notiz für die Historie: Ticket, Server … (optional)")}
        aria-label={t("Note for the history", "Notiz für die Historie")}
        autoComplete="off"
      />
      {suggested && suggested !== item.version ? (
        <button
          type="button"
          className="inventory-version-suggestion"
          disabled={saving}
          onClick={() => void save(suggested)}
          title={t(
            "Latest release of this cycle according to endoflife.date. Use it once this version is deployed.",
            "Neueste Version dieses Zyklus laut endoflife.date. Erst verwenden, wenn sie ausgerollt ist.",
          )}
        >
          {t("Set to", "Setzen auf")} <span className="mono">{suggested}</span>
        </button>
      ) : null}
    </form>
  );
};

const historySourceLabel = (source: InventoryHistoryEntry["source"], t: TranslateFn) => {
  switch (source) {
    case "report":
      return t("API report", "API-Meldung");
    case "mcp":
      return "MCP";
    case "restore":
      return t("Restore", "Wiederherstellung");
    default:
      return t("Web", "Web");
  }
};

const historyFieldLabel = (field: string, t: TranslateFn) => {
  switch (field) {
    case "name":
      return t("Name", "Name");
    case "vendorSlug":
      return t("Vendor", "Hersteller");
    case "productSlug":
      return t("Product", "Produkt");
    case "deployment":
      return t("Deployment", "Bereitstellung");
    case "environment":
      return t("Environment", "Umgebung");
    case "instanceCount":
      return t("Instances", "Instanzen");
    case "owner":
      return t("Owner", "Verantwortlich");
    case "notes":
      return t("Notes", "Notizen");
    case "eolProduct":
      return t("End-of-life link", "End-of-Life-Verknüpfung");
    default:
      return field;
  }
};

const HistoryValue = ({ value }: { value: InventoryHistoryChange["old"] }) =>
  value === null || value === undefined || value === "" ? (
    <span className="muted">n/a</span>
  ) : (
    <span className="mono">{value}</span>
  );

const HistoryChangeLine = ({ change, t }: { change: InventoryHistoryChange; t: TranslateFn }) => (
  <span className="inventory-history-change">
    {change.field !== "version" && <span>{historyFieldLabel(change.field, t)}</span>}
    {/* Free text would swamp a one-line log; the item itself shows it. */}
    {change.field === "notes" ? (
      <span className="muted">{t("changed", "geändert")}</span>
    ) : (
      <>
        <HistoryValue value={change.old} />
        <LuArrowRight aria-hidden="true" />
        <span className="visually-hidden">{t("to", "auf")}</span>
        <HistoryValue value={change.new} />
      </>
    )}
  </span>
);

const HistoryEntrySummary = ({ entry, t }: { entry: InventoryHistoryEntry; t: TranslateFn }) => {
  const version = entry.changes.find((change) => change.field === "version");
  if (entry.action === "created") {
    return (
      <span className="inventory-history-change">
        {t("Added at", "Angelegt mit")} <HistoryValue value={version?.new} />
      </span>
    );
  }
  if (entry.action === "deleted") {
    return (
      <span className="inventory-history-change">
        {t("Deleted at", "Gelöscht bei")} <HistoryValue value={version?.old} />
      </span>
    );
  }
  return (
    <>
      {entry.changes.map((change) => (
        <HistoryChangeLine key={change.field} change={change} t={t} />
      ))}
    </>
  );
};

const InventoryHistoryList = ({
  entries,
  showItem = false,
  t,
}: {
  entries: InventoryHistoryEntry[];
  showItem?: boolean;
  t: TranslateFn;
}) => (
  <ol className="inventory-history">
    {entries.map((entry) => (
      <li key={entry.id}>
        <time dateTime={entry.createdAt}>{formatDateTime(entry.createdAt)}</time>
        <div className="inventory-history-body">
          {showItem && <span className="inventory-history-item">{entry.itemName}</span>}
          <HistoryEntrySummary entry={entry} t={t} />
          {entry.note && <span className="inventory-history-note">{entry.note}</span>}
        </div>
        <span className="inventory-history-source">
          {historySourceLabel(entry.source, t)}
          {entry.actor ? `: ${entry.actor}` : ""}
        </span>
      </li>
    ))}
  </ol>
);

export const InventoryPage = () => {
  const { t } = useI18n();
  const { showToast } = useToastContext();
  const { eolEnabled } = useServerConfig();
  const navigate = useNavigate();

  const [items, setItems] = useState<InventoryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [creating, setCreating] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [deleteCandidate, setDeleteCandidate] = useState<InventoryItem | null>(null);
  const [form, setForm] = useState<InventoryItemCreateInput>(emptyForm());
  const [saving, setSaving] = useState(false);

  const [selectedVendor, setSelectedVendor] = useState<VendorOption | null>(null);
  const [selectedProduct, setSelectedProduct] = useState<ProductOption | null>(null);

  const [search, setSearch] = useState("");
  const [expandedItemId, setExpandedItemId] = useState<string | null>(null);
  const [affectedById, setAffectedById] = useState<
    Record<string, AffectedVulnerabilityItem[] | "loading" | { error: string }>
  >({});

  // endoflife.date support status per item (eager-loaded, parallel to affectedById).
  const [eolById, setEolById] = useState<Record<string, EolStatus | "loading">>({});
  const [historyById, setHistoryById] = useState<
    Record<string, InventoryHistoryEntry[] | "loading" | { error: string }>
  >({});
  const [recentChanges, setRecentChanges] = useState<
    InventoryHistoryEntry[] | "loading" | { error: string }
  >("loading");
  // Manual EOL-product link in the modal: only sent to the backend when the
  // user touches the picker, so an untouched create/edit lets the backend
  // auto-match (or re-match when the product changes).
  const [selectedEol, setSelectedEol] = useState<EolOption | null>(null);
  const [eolTouched, setEolTouched] = useState(false);

  const loadItems = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetchInventoryItems();
      setItems(response.items);
    } catch (exc: unknown) {
      setError(exc instanceof Error ? exc.message : String(exc));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadItems();
  }, [loadItems]);

  const loadRecentChanges = useCallback(async () => {
    try {
      const response = await fetchInventoryHistory();
      setRecentChanges(response.items);
    } catch (exc: unknown) {
      setRecentChanges({ error: exc instanceof Error ? exc.message : String(exc) });
    }
  }, []);

  useEffect(() => {
    void loadRecentChanges();
  }, [loadRecentChanges]);

  const loadItemHistory = useCallback(async (itemId: string) => {
    setHistoryById((prev) => ({ ...prev, [itemId]: "loading" }));
    try {
      const response = await fetchInventoryItemHistory(itemId);
      setHistoryById((prev) => ({ ...prev, [itemId]: response.items }));
    } catch (exc: unknown) {
      setHistoryById((prev) => ({
        ...prev,
        [itemId]: { error: exc instanceof Error ? exc.message : String(exc) },
      }));
    }
  }, []);

  // Eagerly resolve affected vulnerabilities for every item so the card
  // border color reflects real severity without requiring a click on
  // "Show CVEs". Runs each lookup in parallel and populates the same
  // `affectedById` cache the expand handler uses — so clicking later is
  // instant.
  useEffect(() => {
    if (items.length === 0) return;
    let cancelled = false;
    // "loading" counts as pending: a cleaned-up run left it behind without a result.
    const pending = items.filter((item) => affectedById[item.id] === undefined || affectedById[item.id] === "loading");
    if (pending.length === 0) return;

    (async () => {
      await Promise.all(
        pending.map(async (item) => {
          setAffectedById((prev) =>
            prev[item.id] === undefined ? { ...prev, [item.id]: "loading" } : prev,
          );
          try {
            const response = await fetchInventoryAffectedVulnerabilities(item.id, 200);
            if (cancelled) return;
            setAffectedById((prev) => ({ ...prev, [item.id]: response.vulnerabilities }));
          } catch (exc: unknown) {
            if (cancelled) return;
            setAffectedById((prev) => ({
              ...prev,
              [item.id]: { error: exc instanceof Error ? exc.message : String(exc) },
            }));
          }
        }),
      );
    })();

    return () => {
      cancelled = true;
    };
    // Intentionally only depend on `items` — affectedById updates would
    // otherwise retrigger the effect mid-flight.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [items]);

  // Eager endoflife.date status for each item so cards show support/EOL info
  // without a click. Cached server-side (catalog + per-product), so this is
  // cheap after warmup. Skipped entirely when the feature flag is off.
  useEffect(() => {
    if (!eolEnabled || items.length === 0) return;
    let cancelled = false;
    const pending = items.filter((item) => eolById[item.id] === undefined || eolById[item.id] === "loading");
    if (pending.length === 0) return;

    (async () => {
      await Promise.all(
        pending.map(async (item) => {
          setEolById((prev) => (prev[item.id] === undefined ? { ...prev, [item.id]: "loading" } : prev));
          try {
            const status = await fetchInventoryEol(item.id);
            if (cancelled) return;
            setEolById((prev) => ({ ...prev, [item.id]: status }));
          } catch {
            if (cancelled) return;
            // Leave as "loading" → the card simply renders no EOL badge.
          }
        }),
      );
    })();

    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [items, eolEnabled]);

  const loadEolOptions = useCallback(async (inputValue: string): Promise<EolOption[]> => {
    try {
      const response = await fetchEolProducts(inputValue || undefined);
      return response.products.map((p) => ({ value: p.name, label: `${p.label} (${p.name})` }));
    } catch (exc) {
      console.error("Failed to load endoflife.date products", exc);
      return [];
    }
  }, []);

  // --- AsyncSelect loaders ---

  const loadVendorOptions = useCallback(async (inputValue: string): Promise<VendorOption[]> => {
    try {
      const response = await fetchVendors(inputValue || null, SELECT_LIMIT);
      return response.items.map(mapVendorToOption);
    } catch (exc) {
      console.error("Failed to load vendor catalog", exc);
      return [];
    }
  }, []);

  const loadProductOptions = useCallback(
    async (inputValue: string): Promise<ProductOption[]> => {
      const vendorSlugs = selectedVendor ? [selectedVendor.value] : [];
      try {
        const response = await fetchProducts(vendorSlugs, inputValue || null, SELECT_LIMIT);
        return response.items.map(mapProductToOption);
      } catch (exc) {
        console.error("Failed to load product catalog", exc);
        return [];
      }
    },
    [selectedVendor],
  );

  // Finding the product is the hard part, so it can come first. The vendor then
  // follows from it and stays editable in its own field.
  const selectVendorForProduct = async (product: ProductOption) => {
    const slug = primaryVendorSlug(product.value, product.vendorSlugs);
    if (!slug) return;
    let vendor: CatalogVendor | undefined;
    try {
      const response = await fetchVendors(slug, 5);
      vendor = response.items.find((item) => item.slug === slug);
    } catch (exc) {
      console.error("Failed to load vendor", exc);
    }
    const name = vendor?.name ?? slug;
    setSelectedVendor({ value: slug, label: name, aliases: vendor?.aliases ?? [] });
    setForm((prev) => ({ ...prev, vendorSlug: slug, vendorName: name }));
  };

  const resetForm = () => {
    setForm(emptyForm());
    setSelectedVendor(null);
    setSelectedProduct(null);
    setSelectedEol(null);
    setEolTouched(false);
    setCreating(false);
    setEditingId(null);
  };

  // A version or product change invalidates the cached CVEs and EOL status: the
  // eager `[items]` effects then re-fetch, so the row updates without a reload.
  const forgetItemDetails = (itemId: string) => {
    setAffectedById((prev) => {
      const next = { ...prev };
      delete next[itemId];
      return next;
    });
    setEolById((prev) => {
      const next = { ...prev };
      delete next[itemId];
      return next;
    });
  };

  const startEditing = (item: InventoryItem) => {
    setForm({
      name: item.name,
      vendorSlug: item.vendorSlug,
      productSlug: item.productSlug,
      vendorName: item.vendorName ?? "",
      productName: item.productName ?? "",
      version: item.version,
      deployment: item.deployment,
      environment: item.environment,
      instanceCount: item.instanceCount,
      owner: item.owner ?? "",
      notes: item.notes ?? "",
      changeNote: "",
    });
    setSelectedVendor({
      value: item.vendorSlug,
      label: item.vendorName || item.vendorSlug,
      aliases: [],
    });
    setSelectedProduct({
      value: item.productSlug,
      label: item.productName || item.productSlug,
      vendorSlugs: [item.vendorSlug],
      aliases: [],
    });
    setSelectedEol(item.eolProduct ? { value: item.eolProduct, label: item.eolProduct } : null);
    setEolTouched(false);
    setEditingId(item.id);
    setCreating(true);
  };

  // A second server or environment of the same product: the create dialog with
  // this item's values, so only what differs needs typing.
  const startDuplicating = (item: InventoryItem) => {
    startEditing(item);
    setForm((prev) => ({ ...prev, name: `${item.name} ${t("(copy)", "(Kopie)")}` }));
    // Carry the endoflife.date link over instead of auto-matching again.
    setEolTouched(Boolean(item.eolProduct));
    setEditingId(null);
  };

  const handleSave = async () => {
    if (!form.name.trim() || !form.vendorSlug.trim() || !form.productSlug.trim() || !form.version.trim()) {
      showToast(
        t(
          "Name, vendor, product and version are required.",
          "Name, Hersteller, Produkt und Version sind erforderlich.",
        ),
        "error",
      );
      return;
    }
    setSaving(true);
    try {
      const payload: InventoryItemCreateInput = {
        ...form,
        name: form.name.trim(),
        vendorSlug: form.vendorSlug.trim().toLowerCase(),
        productSlug: form.productSlug.trim().toLowerCase(),
        version: form.version.trim(),
        vendorName: form.vendorName?.trim() || null,
        productName: form.productName?.trim() || null,
        owner: form.owner?.trim() || null,
        notes: form.notes?.trim() || null,
        changeNote: form.changeNote?.trim() || null,
        instanceCount: Math.max(1, Number(form.instanceCount) || 1),
      };
      // Only send the EOL link when the user touched the picker — otherwise the
      // backend auto-matches (create) or re-matches on product change (edit).
      if (eolTouched) {
        payload.eolProduct = selectedEol?.value ?? null;
      }
      const wasEditingId = editingId;
      if (editingId) {
        await updateInventoryItem(editingId, payload);
      } else {
        await createInventoryItem(payload);
      }
      // Live refresh: drop the edited item's cached CVEs + EOL so the eager
      // effects re-fetch and the row, EOL badge and Flagged-CVEs table update
      // without a manual reload. (A new item gets a fresh id → fetched anyway.)
      if (wasEditingId) {
        forgetItemDetails(wasEditingId);
      }
      resetForm();
      await loadItems();
      void loadRecentChanges();
      showToast(
        editingId
          ? t("Inventory item updated.", "Inventar-Eintrag aktualisiert.")
          : t("Inventory item created.", "Inventar-Eintrag erstellt."),
        "success"
      );
    } catch (exc: unknown) {
      const message = exc instanceof Error ? exc.message : String(exc);
      showToast(message, "error");
    } finally {
      setSaving(false);
    }
  };

  const handleVersionSaved = (updated: InventoryItem) => {
    forgetItemDetails(updated.id);
    setItems((prev) => prev.map((item) => (item.id === updated.id ? updated : item)));
    void loadItemHistory(updated.id);
    void loadRecentChanges();
    showToast(t("Version updated.", "Version aktualisiert."), "success");
  };

  const handleDelete = async (itemId: string) => {
    try {
      await deleteInventoryItem(itemId);
      if (editingId === itemId) resetForm();
      setDeleteCandidate(null);
      await loadItems();
      void loadRecentChanges();
      showToast(t("Inventory item deleted.", "Inventar-Eintrag gelöscht."), "success");
    } catch (exc: unknown) {
      showToast(exc instanceof Error ? exc.message : String(exc), "error");
    }
  };

  const loadAffected = useCallback(async (itemId: string) => {
    setAffectedById((prev) => ({ ...prev, [itemId]: "loading" }));
    try {
      const response = await fetchInventoryAffectedVulnerabilities(itemId, 200);
      setAffectedById((prev) => ({ ...prev, [itemId]: response.vulnerabilities }));
    } catch (exc: unknown) {
      setAffectedById((prev) => ({
        ...prev,
        [itemId]: { error: exc instanceof Error ? exc.message : String(exc) },
      }));
    }
  }, []);

  const toggleExpanded = (itemId: string) => {
    if (expandedItemId === itemId) {
      setExpandedItemId(null);
      return;
    }
    setExpandedItemId(itemId);
    if (affectedById[itemId] === undefined) {
      void loadAffected(itemId);
    }
    if (historyById[itemId] === undefined) {
      void loadItemHistory(itemId);
    }
  };

  const totalInstances = useMemo(
    () => items.reduce((acc, item) => acc + (item.instanceCount || 0), 0),
    [items],
  );

  const totalItems = items.length;

  // Client-side filter over all searchable text fields. Kept local because
  // the list is expected to be small (≲1k entries) and we don't want a
  // backend round-trip on every keystroke.
  const filteredItems = useMemo(() => {
    const query = search.trim().toLowerCase();
    if (!query) return items;
    return items.filter((item) => {
      const haystack = [
        item.name,
        item.vendorName,
        item.productName,
        item.vendorSlug,
        item.productSlug,
        item.version,
        item.deployment,
        item.environment,
        item.owner,
        item.notes,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return haystack.includes(query);
    });
  }, [items, search]);

  // Aggregated roll-up: every distinct CVE flagged across all configured items,
  // built client-side from the already-eager `affectedById` cache (no extra
  // API). A CVE on multiple items appears once with all affected items listed;
  // the highest-severity metadata wins. Sorted by severity then CVSS desc.
  const aggregatedCves = useMemo(() => {
    type Row = {
      vulnId: string;
      title?: string | null;
      severity?: string | null;
      cvssScore?: number | null;
      epssScore?: number | null;
      exploited?: boolean | null;
      published?: string | null;
      items: { id: string; product: string; version: string }[];
    };
    const byId = new Map<string, Row>();
    for (const item of items) {
      const entry = affectedById[item.id];
      if (!Array.isArray(entry)) continue;
      for (const v of entry) {
        let row = byId.get(v.vulnId);
        if (!row) {
          row = {
            vulnId: v.vulnId,
            title: v.title,
            severity: v.severity,
            cvssScore: v.cvssScore,
            epssScore: v.epssScore,
            exploited: v.exploited,
            published: v.published,
            items: [],
          };
          byId.set(v.vulnId, row);
        } else if (SEVERITY_RANK[severityOf(v.severity)] < SEVERITY_RANK[severityOf(row.severity)]) {
          row.severity = v.severity;
          row.cvssScore = v.cvssScore;
          row.epssScore = v.epssScore;
          row.exploited = v.exploited;
          row.published = v.published;
          if (v.title) row.title = v.title;
        }
        if (!row.items.some((it) => it.id === item.id)) {
          row.items.push({
            id: item.id,
            product: item.productName || item.productSlug,
            version: item.version,
          });
        }
      }
    }
    const rows = Array.from(byId.values());
    rows.sort((a, b) => {
      const sr = SEVERITY_RANK[severityOf(a.severity)] - SEVERITY_RANK[severityOf(b.severity)];
      return sr !== 0 ? sr : (b.cvssScore ?? 0) - (a.cvssScore ?? 0);
    });
    return rows;
  }, [items, affectedById]);

  const aggregatedLoading = useMemo(
    () =>
      items.some((item) => {
        const e = affectedById[item.id];
        return e === undefined || e === "loading";
      }),
    [items, affectedById],
  );

  // DQL query for the VulnerabilityList page. We use the backend matcher
  // (same logic that drives the "Show CVEs" list) to resolve the exact set
  // of affecting vuln IDs, then hand them to the list page as a `vuln_id:`
  // disjunction. That's the only way the list page can mirror the matcher
  // output exactly. When the matcher finds nothing, the fallback below asks
  // the index directly through `affectedVersion:`.
  const buildVendorProductFallbackDql = (item: InventoryItem): string => {
    const parts: string[] = [];
    if (item.vendorSlug) parts.push(`vendorSlugs:${item.vendorSlug}`);
    if (item.productSlug) parts.push(`productSlugs:${item.productSlug}`);
    // Include the declared version so the list is scoped to it. An exact
    // version goes through `affectedVersion:`, which checks the indexed
    // version ranges: `productVersions` only holds the bounds an advisory
    // names, so "4.7 through 7.1.3" never contains 7.1.3 itself. Wildcards
    // (e.g. `8.0.*`) have no range form and stay a Lucene wildcard.
    const version = item.version?.trim();
    if (version) {
      parts.push(
        version.includes("*") ? `productVersions:${version}` : `affectedVersion:"${version}"`,
      );
    }
    return parts.join(" AND ");
  };

  const navigateWithDql = (dql: string) => {
    const params = new URLSearchParams({ mode: "dql", search: dql });
    navigate(`/vulnerabilities?${params.toString()}`);
  };

  const [dqlLoadingId, setDqlLoadingId] = useState<string | null>(null);

  const handleOpenInList = async (item: InventoryItem) => {
    // If the user already expanded "Show CVEs", reuse the cached result.
    const cached = affectedById[item.id];
    if (Array.isArray(cached)) {
      if (cached.length === 0) {
        navigateWithDql(buildVendorProductFallbackDql(item));
      } else {
        const ids = cached.map((v) => `"${v.vulnId}"`).join(" OR ");
        navigateWithDql(`vuln_id:(${ids})`);
      }
      return;
    }

    setDqlLoadingId(item.id);
    try {
      const response = await fetchInventoryAffectedVulnerabilities(item.id, 1000);
      setAffectedById((prev) => ({ ...prev, [item.id]: response.vulnerabilities }));
      if (response.vulnerabilities.length === 0) {
        navigateWithDql(buildVendorProductFallbackDql(item));
      } else {
        const ids = response.vulnerabilities.map((v) => `"${v.vulnId}"`).join(" OR ");
        navigateWithDql(`vuln_id:(${ids})`);
      }
    } catch {
      // On any failure, fall back to the best-effort vendor/product query.
      navigateWithDql(buildVendorProductFallbackDql(item));
    } finally {
      setDqlLoadingId(null);
    }
  };

  // Union of built-in environment suggestions and any custom values already
  // used in the inventory, so the datalist auto-suggests what the user
  // previously typed without restricting new values.
  const environmentSuggestions = useMemo(() => {
    const seen = new Set<string>();
    const result: string[] = [];
    const add = (value: string) => {
      const trimmed = value.trim();
      if (!trimmed) return;
      const key = trimmed.toLowerCase();
      if (seen.has(key)) return;
      seen.add(key);
      result.push(trimmed);
    };
    DEFAULT_ENVIRONMENT_SUGGESTIONS.forEach(add);
    items.forEach((item) => add(item.environment));
    return result;
  }, [items]);

  const columnCount = eolEnabled ? 9 : 8;

  return (
    <div className="page inventory-page">
      <PageHeader
        title={t("Inventory", "Inventar")}
        description={t(
          "Declare the products and versions you run. Hecate flags matching CVEs on every vulnerability page, enriches AI analyses with your environment impact, and fires notifications when a new CVE matches any item.",
          "Deklarieren Sie die Produkte und Versionen, die Sie betreiben. Hecate markiert passende CVEs auf jeder Schwachstellen-Seite, reichert KI-Analysen mit Ihrer Umgebungswirkung an und sendet Benachrichtigungen, sobald ein neuer CVE zu einem Eintrag passt.",
        )}
        actions={
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => {
              resetForm();
              setCreating(true);
            }}
            title={t("Add inventory item", "Inventar-Eintrag hinzufügen")}
            aria-label={t("Add inventory item", "Inventar-Eintrag hinzufügen")}
          >
            <LuPlus aria-hidden="true" />
            {t("Add", "Hinzufügen")}
          </button>
        }
      />

      {totalItems > 0 && (
        <dl className="stat-row inventory-stats">
          <Stat
            label={t("Flagged CVEs", "Gemeldete CVEs")}
            value={
              aggregatedLoading && aggregatedCves.length === 0 ? (
                <SkeletonBlock height="2rem" width="3rem" radius={4} />
              ) : (
                aggregatedCves.length
              )
            }
          />
          <Stat
            label={t(totalItems === 1 ? "Item" : "Items", totalItems === 1 ? "Eintrag" : "Einträge")}
            value={totalItems}
          />
          <Stat
            label={t(
              totalInstances === 1 ? "Instance" : "Instances",
              totalInstances === 1 ? "Instanz" : "Instanzen",
            )}
            value={totalInstances}
          />
        </dl>
      )}

      {error && <ErrorState title={error} />}

      {/* Items list */}
      <Section title={t("Configuration management", "Konfigurationsverwaltung")} className="inventory-items">
        {items.length > 0 && (
          <div className="filter-row">
            <input
              type="search"
              className="inventory-search"
              aria-label={t("Search inventory", "Inventar durchsuchen")}
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder={t(
                "Search name, vendor, product, version, owner…",
                "Name, Hersteller, Produkt, Version, Owner durchsuchen…",
              )}
            />
            {search && (
              <span className="inventory-search-count">
                {filteredItems.length} / {items.length}
              </span>
            )}
          </div>
        )}
        {loading ? (
          <div className="inventory-skeleton" role="status">
            <span className="visually-hidden">{t("Loading...", "Laden...")}</span>
            {Array.from({ length: 3 }, (_, i) => (
              <SkeletonBlock key={i} height="3.25rem" radius={4} />
            ))}
          </div>
        ) : items.length === 0 ? (
          <EmptyState title={t("No inventory items yet.", "Noch keine Einträge.")}>
            {t(
              'Use the "Add" button above to add your first product + version.',
              'Nutzen Sie die Schaltfläche „Hinzufügen" oben, um Ihr erstes Produkt + Version anzulegen.',
            )}
          </EmptyState>
        ) : filteredItems.length === 0 ? (
          <EmptyState title={t("No items match your search.", "Keine Einträge passen zur Suche.")} />
        ) : (
          <div className="table-scroll">
            <table className="inventory-table">
              <thead>
                <tr>
                  <th scope="col">{t("Item", "Eintrag")}</th>
                  <th scope="col">{t("Version", "Version")}</th>
                  <th scope="col">{t("Worst severity", "Höchster Schweregrad")}</th>
                  <th scope="col">{t("CVEs", "CVEs")}</th>
                  {eolEnabled && <th scope="col">{t("End of life", "End of Life")}</th>}
                  <th scope="col">{t("Environment", "Umgebung")}</th>
                  <th scope="col">{t("Deployment", "Betriebsart")}</th>
                  <th scope="col">{t("Instances", "Instanzen")}</th>
                  <th scope="col">
                    <span className="visually-hidden">{t("Actions", "Aktionen")}</span>
                  </th>
                </tr>
              </thead>
              {filteredItems.map((item) => {
                const expanded = expandedItemId === item.id;
                const affected = affectedById[item.id];
                const isLoading = affected === "loading";
                const isError =
                  !!affected && typeof affected === "object" && !Array.isArray(affected) && "error" in affected;
                const vulns = Array.isArray(affected) ? affected : [];
                const worst = vulns.length > 0 ? severityOf(vulns[0]?.severity as string | null) : "unknown";
                const eolEntry = eolEnabled ? eolById[item.id] : undefined;
                const itemHistory = historyById[item.id];
                const eolStatus =
                  eolEntry && eolEntry !== "loading" && eolEntry.linked ? eolEntry : null;

                return (
                  <tbody key={item.id} className="inventory-item">
                    {/* The whole row toggles; the button is the keyboard and
                        screen-reader path and bubbles its click to the row. */}
                    <tr className="inventory-item-row" onClick={() => toggleExpanded(item.id)}>
                      <td className="inventory-cell-name">
                        <button type="button" className="inventory-toggle" aria-expanded={expanded}>
                          <LuChevronRight
                            aria-hidden="true"
                            className={`inventory-chevron${expanded ? " is-open" : ""}`}
                          />
                          <span>{item.name}</span>
                        </button>
                        <div className="inventory-sub">
                          <span>
                            {[item.vendorName || item.vendorSlug, item.productName || item.productSlug]
                              .filter(Boolean)
                              .join(" / ")}
                          </span>
                          {item.owner && <span>{item.owner}</span>}
                        </div>
                        {item.notes && <div className="inventory-notes">{item.notes}</div>}
                      </td>
                      <td className="inventory-cell-version mono">{item.version}</td>
                      <td className="inventory-cell-severity">
                        {vulns.length > 0 && (
                          <SeverityTag severity={worst}>{severityLabel(worst, t)}</SeverityTag>
                        )}
                      </td>
                      <td className="inventory-cell-cves">
                        {isLoading ? (
                          <SkeletonBlock height="1rem" width="2rem" radius={4} />
                        ) : (
                          <span className={isError ? "inventory-cve-count is-error" : "inventory-cve-count"}>
                            {isError ? "!" : vulns.length}
                            <span className="inventory-unit"> {t("CVEs", "CVEs")}</span>
                          </span>
                        )}
                      </td>
                      {eolEnabled && (
                        <td className="inventory-cell-eol">
                          {eolStatus && (
                            <div onClick={(e) => e.stopPropagation()} role="presentation">
                              <EolStatusBadge status={eolStatus} t={t} />
                            </div>
                          )}
                        </td>
                      )}
                      <td className="inventory-cell-meta">{environmentLabel(item.environment, t)}</td>
                      <td className="inventory-cell-meta">{deploymentLabel(item.deployment, t)}</td>
                      <td className="inventory-cell-meta inventory-cell-instances">
                        {item.instanceCount}
                        <span className="inventory-unit">
                          {" "}
                          {t(
                            item.instanceCount === 1 ? "instance" : "instances",
                            item.instanceCount === 1 ? "Instanz" : "Instanzen",
                          )}
                        </span>
                      </td>
                      <td className="inventory-cell-actions">
                        <div
                          className="inventory-actions"
                          role="presentation"
                          onClick={(e) => e.stopPropagation()}
                          onKeyDown={(e) => e.stopPropagation()}
                        >
                          <button
                            type="button"
                            className="btn btn-secondary inventory-dql"
                            onClick={() => void handleOpenInList(item)}
                            disabled={dqlLoadingId === item.id}
                            title={t(
                              "Open a pre-built DQL query for this item in the Vulnerabilities list",
                              "Vorbereitete DQL-Abfrage für diesen Eintrag in der Schwachstellen-Liste öffnen",
                            )}
                          >
                            {dqlLoadingId === item.id ? t("…", "…") : t("DQL", "DQL")}
                          </button>
                          <IconButton label={t("Edit", "Bearbeiten")} onClick={() => startEditing(item)}>
                            <LuPencil aria-hidden="true" />
                          </IconButton>
                          <IconButton label={t("Duplicate", "Duplizieren")} onClick={() => startDuplicating(item)}>
                            <LuCopy aria-hidden="true" />
                          </IconButton>
                          <IconButton
                            label={t("Delete", "Löschen")}
                            className="inventory-delete"
                            onClick={() => setDeleteCandidate(item)}
                          >
                            <LuTrash2 aria-hidden="true" />
                          </IconButton>
                        </div>
                      </td>
                    </tr>

                    {expanded && (
                      <tr className="inventory-expansion-row">
                        <td colSpan={columnCount}>
                          <div className="well inventory-expansion">
                            <div className="inventory-expansion-side">
                              <VersionUpdateForm
                                key={item.version}
                                item={item}
                                suggested={eolStatus?.isOutdated ? (eolStatus.latestVersion ?? null) : null}
                                onSaved={handleVersionSaved}
                                t={t}
                              />
                              {eolStatus && <EolDetailBlock status={eolStatus} t={t} />}
                              <div className="inventory-item-history">
                                <div className="inventory-expansion-head">
                                  <h3>{t("History", "Verlauf")}</h3>
                                </div>
                                {itemHistory === undefined || itemHistory === "loading" ? (
                                  <SkeletonBlock height="1.5rem" radius={4} />
                                ) : "error" in itemHistory ? (
                                  <ErrorState title={itemHistory.error} />
                                ) : itemHistory.length === 0 ? (
                                  <p className="inventory-note">
                                    {t(
                                      "No changes recorded yet. Changes are tracked from now on.",
                                      "Noch keine Änderungen erfasst. Änderungen werden ab jetzt aufgezeichnet.",
                                    )}
                                  </p>
                                ) : (
                                  <InventoryHistoryList entries={itemHistory} t={t} />
                                )}
                              </div>
                            </div>
                            <div className="inventory-expansion-cves">
                              {isLoading ? (
                                <div className="inventory-skeleton" role="status">
                                  <span className="visually-hidden">
                                    {t("Loading affected vulnerabilities...", "Betroffene Schwachstellen werden geladen...")}
                                  </span>
                                  {Array.from({ length: 3 }, (_, i) => (
                                    <SkeletonBlock key={i} height="1.5rem" radius={4} />
                                  ))}
                                </div>
                              ) : isError ? (
                                <ErrorState title={(affected as { error: string }).error} />
                              ) : vulns.length === 0 ? (
                                <EmptyState
                                  title={t(
                                    "No known vulnerabilities currently affect this version.",
                                    "Aktuell sind keine Schwachstellen für diese Version bekannt.",
                                  )}
                                />
                              ) : (
                                <>
                                  <div className="inventory-expansion-head">
                                    <h3>
                                      {vulns.length}{" "}
                                      {t(
                                        vulns.length === 1 ? "affecting vulnerability" : "affecting vulnerabilities",
                                        vulns.length === 1 ? "betroffene Schwachstelle" : "betroffene Schwachstellen",
                                      )}
                                    </h3>
                                  </div>
                                  <ul className="inventory-cve-list">
                                    {vulns.slice(0, 50).map((v) => {
                                      const sev = severityOf(v.severity);
                                      return (
                                        <li key={v.vulnId}>
                                          <Link
                                            to={`/vulnerability/${encodeURIComponent(v.vulnId)}`}
                                            className="row-link inventory-cve-row"
                                          >
                                            <span className="mono inventory-cve-id">{v.vulnId}</span>
                                            <span className="inventory-cve-severity">
                                              <SeverityTag severity={sev}>{severityLabel(sev, t)}</SeverityTag>
                                            </span>
                                            {v.exploited && <span className="chip inventory-kev">KEV</span>}
                                            {v.title && v.title !== v.vulnId && (
                                              <span className="inventory-cve-title">{v.title}</span>
                                            )}
                                          </Link>
                                        </li>
                                      );
                                    })}
                                  </ul>
                                  {vulns.length > 50 && (
                                    <p className="inventory-cve-more">
                                      {t("... and", "... und")} {vulns.length - 50} {t("more", "weitere")}
                                    </p>
                                  )}
                                </>
                              )}
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </tbody>
                );
              })}
            </table>
          </div>
        )}
      </Section>

      {/* Aggregated CVE roll-up across every configured item */}
      <Section title={t("Flagged CVEs", "Gemeldete CVEs")}>
        <p className="inventory-note">
          {t(
            "Every distinct CVE matching any configured item, sorted by severity.",
            "Jeder eindeutige CVE, der zu einem konfigurierten Eintrag passt, nach Schweregrad sortiert.",
          )}
        </p>
        {aggregatedCves.length === 0 ? (
          aggregatedLoading ? (
            <div className="inventory-skeleton" role="status">
              <span className="visually-hidden">
                {t("Loading affected vulnerabilities...", "Betroffene Schwachstellen werden geladen...")}
              </span>
              {Array.from({ length: 5 }, (_, i) => (
                <SkeletonBlock key={i} height="2.25rem" radius={4} />
              ))}
            </div>
          ) : (
            <EmptyState
              title={
                items.length === 0
                  ? t("Add inventory items to see flagged CVEs.", "Fügen Sie Einträge hinzu, um gemeldete CVEs zu sehen.")
                  : t("No known vulnerabilities affect your inventory.", "Keine bekannten Schwachstellen betreffen Ihr Inventar.")
              }
            />
          )
        ) : (
          <>
            {aggregatedLoading && (
              <p className="inventory-note">
                {t("Still resolving some items…", "Einige Einträge werden noch geladen…")}
              </p>
            )}
            <div className="table-scroll">
              <table className="inventory-flagged-table">
                <thead>
                  <tr>
                    <th scope="col">{t("CVE", "CVE")}</th>
                    <th scope="col">{t("Severity", "Schweregrad")}</th>
                    <th scope="col">{t("CVSS", "CVSS")}</th>
                    <th scope="col">{t("EPSS", "EPSS")}</th>
                    <th scope="col">{t("Published", "Veröffentlicht")}</th>
                    <th scope="col">{t("Affected items", "Betroffene Einträge")}</th>
                  </tr>
                </thead>
                <tbody>
                  {aggregatedCves.map((row) => {
                    const sev = severityOf(row.severity);
                    return (
                      <tr key={row.vulnId}>
                        <td>
                          <span className="inventory-flagged-id">
                            <Link
                              to={`/vulnerability/${encodeURIComponent(row.vulnId)}`}
                              className="row-link mono"
                            >
                              {row.vulnId}
                            </Link>
                            {row.exploited && <span className="chip inventory-kev">KEV</span>}
                          </span>
                        </td>
                        <td>
                          <SeverityTag severity={sev}>{severityLabel(sev, t)}</SeverityTag>
                        </td>
                        <td>{row.cvssScore != null ? row.cvssScore.toFixed(1) : "n/a"}</td>
                        <td>
                          {row.epssScore != null ? `${(row.epssScore * 100).toFixed(1)}%` : "n/a"}
                        </td>
                        <td className="inventory-flagged-date">
                          {row.published ? formatDateTime(row.published) : "n/a"}
                        </td>
                        <td>
                          <div className="inventory-flagged-items">
                            {row.items.map((it) => (
                              <span key={it.id} className="chip inventory-flagged-item">
                                <span>{it.product}</span>
                                <span className="inventory-version">{it.version}</span>
                              </span>
                            ))}
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </>
        )}
      </Section>

      <Section title={t("Recent changes", "Letzte Änderungen")} className="inventory-recent-changes">
        {recentChanges === "loading" ? (
          <SkeletonBlock height="4rem" radius={4} />
        ) : "error" in recentChanges ? (
          <ErrorState title={recentChanges.error} />
        ) : recentChanges.length === 0 ? (
          <EmptyState
            title={t("No changes recorded yet.", "Noch keine Änderungen erfasst.")}
          >
            {t(
              "Every version change, from here or through the API, shows up in this list.",
              "Jede Versionsänderung, ob hier oder über die API, erscheint in dieser Liste.",
            )}
          </EmptyState>
        ) : (
          <InventoryHistoryList entries={recentChanges} showItem t={t} />
        )}
      </Section>

      {/* Add / edit modal, opened from the page header and the row edit action */}
      {deleteCandidate && (
        <ConfirmDialog
          title={t("Delete inventory item", "Inventar-Eintrag löschen")}
          message={
            <>
              {t("Delete", "Soll")} <strong>{deleteCandidate.name}</strong>{" "}
              {t(
                "from the inventory? Its CVE matches and notifications stop; the change log keeps the entry.",
                "aus dem Inventar gelöscht werden? CVE-Treffer und Benachrichtigungen dafür entfallen, das Änderungsprotokoll behält den Eintrag.",
              )}
            </>
          }
          confirmLabel={t("Delete", "Löschen")}
          onConfirm={() => handleDelete(deleteCandidate.id)}
          onCancel={() => setDeleteCandidate(null)}
        />
      )}

      {(creating || editingId !== null) && (
        <div className="dialog-overlay" role="presentation" onClick={resetForm}>
          <div
            className="dialog dialog--wide"
            role="dialog"
            aria-modal="true"
            aria-labelledby="inventory-dialog-title"
            onClick={(e) => e.stopPropagation()}
            onKeyDown={(e) => {
              if (e.key === "Escape") resetForm();
            }}
          >
            <div className="dialog-head">
              <div className="inventory-dialog-title">
                <h3 id="inventory-dialog-title">
                  {editingId
                    ? t("Edit Item", "Eintrag bearbeiten")
                    : t("Add Item", "Eintrag hinzufügen")}
                </h3>
                <p className="inventory-dialog-hint">
                  {t(
                    "Vendor and product auto-complete from the asset catalog. Versions accept exact values (8.0.25) or wildcards (8.0.*).",
                    "Hersteller und Produkt werden aus dem Asset-Katalog vervollständigt. Versionen akzeptieren exakte Werte (8.0.25) oder Wildcards (8.0.*).",
                  )}
                </p>
              </div>
              <button
                type="button"
                className="dialog-close"
                onClick={resetForm}
                aria-label={t("Close", "Schließen")}
                title={t("Close", "Schließen")}
              >
                <LuX aria-hidden="true" />
              </button>
            </div>
            <div className="inventory-form">
              <div className="inventory-field inventory-field--full">
                <label className="inventory-label" htmlFor="inventory-name">{t("Name", "Name")}</label>
                <input
                  id="inventory-name"
                  type="text"
                  className="inventory-input"
                  value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                  placeholder={t(".NET 8.0.25, prod cluster", ".NET 8.0.25, Prod-Cluster")}
                />
              </div>

              <div className="inventory-field">
                <label className="inventory-label" htmlFor="inventory-vendor">{t("Vendor", "Hersteller")}</label>
                <AsyncSelect<VendorOption, false>
                  inputId="inventory-vendor"
                  cacheOptions
                  defaultOptions
                  loadOptions={loadVendorOptions}
                  value={selectedVendor}
                  onChange={(option) => {
                    setSelectedVendor(option);
                    // Product becomes invalid when vendor changes
                    setSelectedProduct(null);
                    setForm({
                      ...form,
                      vendorSlug: option?.value ?? "",
                      vendorName: option?.label ?? "",
                      productSlug: "",
                      productName: "",
                    });
                  }}
                  placeholder={t("Select vendor...", "Hersteller auswählen...")}
                  styles={selectStyles}
                  menuPortalTarget={document.body}
                  menuPosition="fixed"
                  isClearable
                  noOptionsMessage={({ inputValue }) =>
                    inputValue
                      ? t(`No vendors found for "${inputValue}"`, `Keine Hersteller gefunden für "${inputValue}"`)
                      : t("Type to search", "Tippen Sie, um zu suchen")
                  }
                  formatOptionLabel={renderCatalogOption}
                />
              </div>

              <div className="inventory-field">
                <label className="inventory-label" htmlFor="inventory-product">{t("Product", "Produkt")}</label>
                <AsyncSelect<ProductOption, false>
                  key={selectedVendor?.value ?? "no-vendor"}
                  inputId="inventory-product"
                  cacheOptions
                  defaultOptions={Boolean(selectedVendor)}
                  loadOptions={loadProductOptions}
                  value={selectedProduct}
                  onChange={(option) => {
                    setSelectedProduct(option);
                    setForm({
                      ...form,
                      productSlug: option?.value ?? "",
                      productName: option?.label ?? "",
                    });
                    if (option && !selectedVendor) void selectVendorForProduct(option);
                  }}
                  placeholder={t("Search product...", "Produkt suchen...")}
                  styles={selectStyles}
                  menuPortalTarget={document.body}
                  menuPosition="fixed"
                  isClearable
                  noOptionsMessage={({ inputValue }) =>
                    inputValue
                      ? t(`No products found for "${inputValue}"`, `Keine Produkte gefunden für "${inputValue}"`)
                      : t("Type to search", "Tippen Sie, um zu suchen")
                  }
                  formatOptionLabel={renderCatalogOption}
                />
              </div>

              <div className="inventory-field">
                <label className="inventory-label" htmlFor="inventory-version">{t("Version", "Version")}</label>
                <input
                  id="inventory-version"
                  type="text"
                  className="inventory-input"
                  value={form.version}
                  onChange={(e) => setForm({ ...form, version: e.target.value })}
                  placeholder="8.0.25"
                />
              </div>

              <div className="inventory-field">
                <span className="inventory-label" id="inventory-deployment-label">
                  {t("Deployment", "Betriebsart")}
                </span>
                <div className="inventory-choices" role="group" aria-labelledby="inventory-deployment-label">
                  {DEPLOYMENTS.map((d) => (
                    <button
                      key={d}
                      type="button"
                      className={`inventory-choice ${form.deployment === d ? "active" : ""}`}
                      aria-pressed={form.deployment === d}
                      onClick={() => setForm({ ...form, deployment: d })}
                    >
                      {deploymentLabel(d, t)}
                    </button>
                  ))}
                </div>
              </div>

              <div className="inventory-field">
                <label className="inventory-label" htmlFor="inventory-environment">{t("Environment", "Umgebung")}</label>
                <input
                  id="inventory-environment"
                  type="text"
                  className="inventory-input"
                  list="inventory-environment-suggestions"
                  value={form.environment}
                  onChange={(e) => setForm({ ...form, environment: e.target.value })}
                  placeholder={t("prod, staging, dev, test, …", "prod, staging, dev, test, …")}
                />
                <datalist id="inventory-environment-suggestions">
                  {environmentSuggestions.map((env) => (
                    <option key={env} value={env} />
                  ))}
                </datalist>
              </div>

              <div className="inventory-field">
                <label className="inventory-label" htmlFor="inventory-instances">
                  {t("Instance Count", "Anzahl Instanzen")}
                </label>
                <input
                  id="inventory-instances"
                  type="number"
                  min={1}
                  className="inventory-input"
                  value={form.instanceCount}
                  onChange={(e) =>
                    setForm({ ...form, instanceCount: Math.max(1, Number(e.target.value) || 1) })
                  }
                />
              </div>

              <div className="inventory-field">
                <label className="inventory-label" htmlFor="inventory-owner">
                  {t("Owner / Team (optional)", "Verantwortlich / Team (optional)")}
                </label>
                <input
                  id="inventory-owner"
                  type="text"
                  className="inventory-input"
                  value={form.owner ?? ""}
                  onChange={(e) => setForm({ ...form, owner: e.target.value })}
                  placeholder="platform-team"
                />
              </div>

              {eolEnabled && (
                <div className="inventory-field">
                  <label className="inventory-label" htmlFor="inventory-eol">
                    {t("End-of-life tracking", "End-of-Life-Tracking")}
                  </label>
                  <AsyncSelect<EolOption, false>
                    inputId="inventory-eol"
                    cacheOptions
                    defaultOptions
                    loadOptions={loadEolOptions}
                    value={selectedEol}
                    onChange={(option) => {
                      setSelectedEol(option);
                      setEolTouched(true);
                    }}
                    placeholder={t("Auto-detected", "Automatisch")}
                    styles={selectStyles}
                    menuPortalTarget={document.body}
                    menuPosition="fixed"
                    isClearable
                    noOptionsMessage={({ inputValue }) =>
                      inputValue
                        ? t(`No products found for "${inputValue}"`, `Keine Produkte gefunden für "${inputValue}"`)
                        : t("Type to search endoflife.date", "Tippen, um endoflife.date zu durchsuchen")
                    }
                  />
                  <small className="inventory-hint">
                    {t(
                      "endoflife.date product, auto-detected from the product name; change or clear to override.",
                      "endoflife.date-Produkt, automatisch aus dem Produktnamen erkannt; ändern oder leeren zum Überschreiben.",
                    )}
                  </small>
                </div>
              )}

              <div className="inventory-field inventory-field--full">
                <label className="inventory-label" htmlFor="inventory-notes">
                  {t("Notes (optional)", "Notizen (optional)")}
                </label>
                <textarea
                  id="inventory-notes"
                  className="inventory-input"
                  value={form.notes ?? ""}
                  onChange={(e) => setForm({ ...form, notes: e.target.value })}
                  rows={3}
                />
              </div>
              <div className="inventory-field inventory-field--full">
                <label className="inventory-label" htmlFor="inventory-change-note">
                  {t("Note for the history (optional)", "Notiz für die Historie (optional)")}
                </label>
                <input
                  id="inventory-change-note"
                  className="inventory-input"
                  value={form.changeNote ?? ""}
                  onChange={(e) => setForm({ ...form, changeNote: e.target.value })}
                  maxLength={500}
                  placeholder={t("Ticket, server or change request", "Ticket, Server oder Change Request")}
                  autoComplete="off"
                />
              </div>
            </div>
            <div className="dialog-actions inventory-dialog-actions">
              <button type="button" className="btn btn-secondary" onClick={resetForm}>
                {t("Cancel", "Abbrechen")}
              </button>
              <button
                type="button"
                className="btn btn-primary"
                onClick={() => void handleSave()}
                disabled={saving}
              >
                {saving
                  ? t("Saving...", "Speichern…")
                  : editingId
                    ? t("Save", "Speichern")
                    : t("Create", "Erstellen")}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
