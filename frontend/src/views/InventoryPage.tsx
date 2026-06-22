import { useCallback, useEffect, useMemo, useState, type CSSProperties, type ReactNode } from "react";
import { Link, useNavigate } from "react-router-dom";
import AsyncSelect from "react-select/async";
import { LuPlus, LuX } from "react-icons/lu";

import {
  createInventoryItem,
  deleteInventoryItem,
  fetchInventoryAffectedVulnerabilities,
  fetchInventoryItems,
  updateInventoryItem,
  type InventoryItemCreateInput,
} from "../api/inventory";
import { fetchEolProducts, fetchInventoryEol } from "../api/endoflife";
import { fetchProducts, fetchVendors } from "../api/assets";
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
  InventoryItem,
} from "../types";
import { formatDateTime } from "../utils/dateFormat";

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

const EOL_STATUS_TONE: Record<EolStatusKind, { bg: string; fg: string }> = {
  active: { bg: "rgba(105,219,124,0.15)", fg: "#69db7c" },
  security: { bg: "rgba(252,196,25,0.15)", fg: "#fcc419" },
  eol: { bg: "rgba(255,107,107,0.15)", fg: "#ff6b6b" },
  unknown: { bg: "rgba(255,255,255,0.06)", fg: "rgba(255,255,255,0.6)" },
};

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

// Compact badge for the row: status pill (+ date), LTS, and "update available"
// only. The verbose detail (latest release, newer line, link, dates) lives in
// the expandable `EolDetailBlock` below, to keep the row readable.
const EolStatusBadge = ({ status, t }: { status: EolStatus; t: TranslateFn }) => {
  const tone = EOL_STATUS_TONE[status.status] ?? EOL_STATUS_TONE.unknown;
  const untilLabel = eolUntilLabel(status, t);
  return (
    <div
      style={{ display: "flex", gap: "0.4rem", flexWrap: "wrap", alignItems: "center", fontSize: "0.75rem" }}
    >
      <span
        className="chip"
        style={{ background: tone.bg, color: tone.fg }}
        title={status.productLabel ?? undefined}
      >
        {eolStatusLabel(status.status, t)}
        {untilLabel ? ` · ${untilLabel}` : ""}
      </span>
      {status.isLts && (
        <span
          className="chip"
          style={{ background: "rgba(105,219,124,0.12)", color: "#69db7c" }}
          title={status.ltsFrom ? `LTS since ${status.ltsFrom}` : undefined}
        >
          LTS
        </span>
      )}
      {status.isOutdated && (
        <span className="chip" style={{ background: "rgba(92,132,255,0.15)", color: "#93bbfd" }}>
          {t("update available", "Update verfügbar")}
        </span>
      )}
    </div>
  );
};

// Full endoflife.date detail, shown inside the row's expansion above the CVEs.
const EolDetailBlock = ({ status, t }: { status: EolStatus; t: TranslateFn }) => {
  const productHref =
    status.productLink || (status.product ? `https://endoflife.date/${status.product}` : null);
  const rows: { label: string; value: ReactNode }[] = [];
  if (status.matchedCycle)
    rows.push({ label: t("Release cycle", "Release-Zyklus"), value: status.matchedCycle });
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
        <>
          {status.latestLink ? (
            <a href={status.latestLink} target="_blank" rel="noreferrer" style={{ color: "inherit" }}>
              {status.latestVersion}
            </a>
          ) : (
            status.latestVersion
          )}
          {status.isOutdated ? ` — ${t("update available", "Update verfügbar")}` : ""}
        </>
      ),
    });
  if (!status.isLatestCycle && status.latestCycle)
    rows.push({ label: t("Newer release line", "Neuere Release-Linie"), value: status.latestCycle });

  return (
    <div style={{ marginBottom: "0.75rem", fontSize: "0.78rem" }}>
      <div
        className="muted"
        style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.35rem", fontWeight: 600 }}
      >
        {t("End-of-life", "End of Life")}
        {status.productLabel ? ` · ${status.productLabel}` : ""}
        {productHref && (
          <a
            href={productHref}
            target="_blank"
            rel="noreferrer"
            className="muted"
            style={{ textDecoration: "none", whiteSpace: "nowrap", fontWeight: 400 }}
            title="endoflife.date"
          >
            ↗ endoflife.date
          </a>
        )}
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: "0.15rem" }}>
        {rows.map((r, i) => (
          <div key={i} style={{ display: "flex", gap: "0.5rem" }}>
            <span className="muted" style={{ minWidth: "9.5rem", flexShrink: 0 }}>
              {r.label}
            </span>
            <span style={{ wordBreak: "break-word" }}>{r.value}</span>
          </div>
        ))}
      </div>
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
});

// --- AsyncSelect option types + styles (mirrors components/AssetFilters.tsx) ---

interface VendorOption {
  value: string;
  label: string;
  aliases: string[];
}

interface ProductOption {
  value: string;
  label: string;
  vendorSlugs: string[];
  aliases: string[];
}

const mapVendorToOption = (item: CatalogVendor): VendorOption => ({
  value: item.slug,
  label: item.name,
  aliases: item.aliases,
});

const mapProductToOption = (item: CatalogProduct): ProductOption => ({
  value: item.slug,
  label: item.name,
  vendorSlugs: item.vendorSlugs,
  aliases: item.aliases,
});

const selectStyles = {
  control: (provided: any, state: any) => ({
    ...provided,
    background: "rgba(15, 18, 30, 0.85)",
    borderColor: state.isFocused ? "rgba(255, 212, 59, 0.7)" : "rgba(255, 255, 255, 0.12)",
    borderRadius: "8px",
    color: "#f5f7fa",
    boxShadow: "none",
    minHeight: "38px",
    "&:hover": {
      borderColor: state.isFocused ? "rgba(255, 212, 59, 0.7)" : "rgba(255, 255, 255, 0.25)",
    },
  }),
  menu: (provided: any) => ({
    ...provided,
    background: "rgba(10, 12, 20, 0.95)",
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
    backgroundColor: state.isFocused ? "rgba(92,132,255,0.2)" : "transparent",
    color: "#f5f7fa",
  }),
  singleValue: (provided: any) => ({
    ...provided,
    color: "#f5f7fa",
  }),
  indicatorSeparator: () => ({
    display: "none",
  }),
  input: (provided: any) => ({
    ...provided,
    color: "#f5f7fa",
    "& input": {
      outline: "none !important",
      boxShadow: "none !important",
      border: "none !important",
    },
  }),
  placeholder: (provided: any) => ({
    ...provided,
    color: "rgba(255, 255, 255, 0.6)",
    whiteSpace: "nowrap",
    overflow: "hidden",
    textOverflow: "ellipsis",
  }),
};

// --- Form-grid layout for the Add/Edit card ---
// Uses a simple CSS-grid with minmax so columns collapse to one on narrow
// viewports. No per-field maxWidth — inputs always fill their cell.

const formGridStyle: CSSProperties = {
  display: "grid",
  gap: "1rem",
  gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
  marginTop: "1rem",
};

const fieldFullStyle: CSSProperties = {
  gridColumn: "1 / -1",
  display: "flex",
  flexDirection: "column",
  gap: "0.35rem",
  minWidth: 0,
};

const fieldStyle: CSSProperties = {
  display: "flex",
  flexDirection: "column",
  gap: "0.35rem",
  minWidth: 0,
};

// Shared pill-button style used by all four card-action buttons
// (Show CVEs / DQL / Edit / Delete). A single base + per-button tint
// variants keeps them visually consistent (same rounding, size, font,
// padding) while letting each convey intent with color.
const actionButtonBaseStyle: CSSProperties = {
  display: "inline-flex",
  alignItems: "center",
  justifyContent: "center",
  padding: "0.3rem 0.65rem",
  borderRadius: "6px",
  fontSize: "0.8125rem",
  fontWeight: 500,
  lineHeight: 1.2,
  cursor: "pointer",
  transition: "background 0.15s, border-color 0.15s",
};

const neutralActionStyle: CSSProperties = {
  ...actionButtonBaseStyle,
  background: "rgba(255,255,255,0.06)",
  border: "1px solid rgba(255,255,255,0.15)",
  color: "rgba(255,255,255,0.85)",
};

const primaryActionStyle: CSSProperties = {
  ...actionButtonBaseStyle,
  background: "rgba(92,132,255,0.12)",
  border: "1px solid rgba(92,132,255,0.35)",
  color: "#93bbfd",
};

const dangerActionStyle: CSSProperties = {
  ...actionButtonBaseStyle,
  background: "rgba(255,107,107,0.1)",
  border: "1px solid rgba(255,107,107,0.3)",
  color: "#ff6b6b",
};

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

  // Eagerly resolve affected vulnerabilities for every item so the card
  // border color reflects real severity without requiring a click on
  // "Show CVEs". Runs each lookup in parallel and populates the same
  // `affectedById` cache the expand handler uses — so clicking later is
  // instant.
  useEffect(() => {
    if (items.length === 0) return;
    let cancelled = false;
    const pending = items.filter((item) => affectedById[item.id] === undefined);
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
    const pending = items.filter((item) => eolById[item.id] === undefined);
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

  const resetForm = () => {
    setForm(emptyForm());
    setSelectedVendor(null);
    setSelectedProduct(null);
    setSelectedEol(null);
    setEolTouched(false);
    setCreating(false);
    setEditingId(null);
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
        setAffectedById((prev) => {
          const next = { ...prev };
          delete next[wasEditingId];
          return next;
        });
        setEolById((prev) => {
          const next = { ...prev };
          delete next[wasEditingId];
          return next;
        });
      }
      resetForm();
      await loadItems();
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

  const handleDelete = async (itemId: string) => {
    const confirmed = window.confirm(
      t(
        "Delete this inventory item? This cannot be undone.",
        "Diesen Inventar-Eintrag löschen? Kann nicht rückgängig gemacht werden.",
      ),
    );
    if (!confirmed) return;
    try {
      await deleteInventoryItem(itemId);
      if (editingId === itemId) resetForm();
      await loadItems();
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
  // output — a naive `productVersions:"8.0.25"` query only hits records
  // that literally contain that version string and misses range matches
  // like `>= 8.0.0, < 8.0.26`, which the Python-side range parser
  // recognises but OpenSearch DQL cannot.
  const buildVendorProductFallbackDql = (item: InventoryItem): string => {
    const parts: string[] = [];
    if (item.vendorSlug) parts.push(`vendorSlugs:${item.vendorSlug}`);
    if (item.productSlug) parts.push(`productSlugs:${item.productSlug}`);
    // Include the declared version so the list is scoped to it. Exact versions
    // are quoted; wildcards (e.g. `8.0.*`) pass through as a Lucene wildcard.
    const version = item.version?.trim();
    if (version) {
      parts.push(
        version.includes("*") ? `productVersions:${version}` : `productVersions:"${version}"`,
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

  return (
    <div className="page">
      {/* Intro / summary */}
      <section className="card">
        <h2>{t("Inventory", "Inventar")}</h2>
        <p className="muted">
          {t(
            "Declare the products and versions you run. Hecate flags matching CVEs on every vulnerability page, enriches AI analyses with your environment impact, and fires notifications when a new CVE matches any item.",
            "Deklarieren Sie die Produkte und Versionen, die Sie betreiben. Hecate markiert passende CVEs auf jeder Schwachstellen-Seite, reichert KI-Analysen mit Ihrer Umgebungswirkung an und sendet Benachrichtigungen, sobald ein neuer CVE zu einem Eintrag passt.",
          )}
        </p>
        {totalItems > 0 && (
          <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap", marginTop: "0.75rem" }}>
            <span className="chip">
              {totalItems}{" "}
              {t(totalItems === 1 ? "item" : "items", totalItems === 1 ? "Eintrag" : "Einträge")}
            </span>
            <span className="chip">
              {totalInstances}{" "}
              {t(
                totalInstances === 1 ? "instance" : "instances",
                totalInstances === 1 ? "Instanz" : "Instanzen",
              )}
            </span>
          </div>
        )}
        {error && (
          <div className="alert error" style={{ marginTop: "1rem" }}>
            {error}
          </div>
        )}
      </section>

      {/* Add / edit modal — triggered from the Configuration management header */}
      {(creating || editingId !== null) && (
        <div className="dialog-overlay" role="presentation" onClick={resetForm}>
          <div
            className="dialog dialog--wide"
            role="dialog"
            aria-modal="true"
            onClick={(e) => e.stopPropagation()}
            onKeyDown={(e) => {
              if (e.key === "Escape") resetForm();
            }}
          >
            <div className="dialog-head">
              <div style={{ minWidth: 0 }}>
                <h3 style={{ margin: "0 0 0.25rem" }}>
                  {editingId
                    ? t("Edit Item", "Eintrag bearbeiten")
                    : t("Add Item", "Eintrag hinzufügen")}
                </h3>
                <p className="muted" style={{ margin: 0, fontSize: "0.85rem" }}>
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
                <LuX aria-hidden />
              </button>
            </div>
            <div style={formGridStyle}>
            <div style={fieldFullStyle}>
              <label className="advanced-filter-label">{t("Name", "Name")}</label>
              <input
                type="text"
                className="advanced-filter-input"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                placeholder={t(".NET 8.0.25 — prod cluster", ".NET 8.0.25 – Prod-Cluster")}
              />
            </div>

            <div style={fieldStyle}>
              <label className="advanced-filter-label">{t("Vendor", "Hersteller")}</label>
              <AsyncSelect<VendorOption, false>
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
                formatOptionLabel={(option) => (
                  <span style={{ display: "flex", flexDirection: "column" }}>
                    <span>{option.label}</span>
                    {option.aliases.length > 0 ? (
                      <small style={{ opacity: 0.65, fontSize: "0.75rem" }}>
                        {option.aliases.slice(0, 2).join(", ")}
                        {option.aliases.length > 2 ? " …" : ""}
                      </small>
                    ) : null}
                  </span>
                )}
              />
            </div>

            <div style={fieldStyle}>
              <label className="advanced-filter-label">{t("Product", "Produkt")}</label>
              <AsyncSelect<ProductOption, false>
                key={selectedVendor?.value ?? "no-vendor"}
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
                }}
                placeholder={
                  selectedVendor
                    ? t("Select product...", "Produkt auswählen...")
                    : t("Select a vendor first", "Zuerst Hersteller wählen")
                }
                styles={selectStyles}
                menuPortalTarget={document.body}
                menuPosition="fixed"
                isClearable
                isDisabled={!selectedVendor}
                noOptionsMessage={({ inputValue }) =>
                  inputValue
                    ? t(`No products found for "${inputValue}"`, `Keine Produkte gefunden für "${inputValue}"`)
                    : t("Type to search", "Tippen Sie, um zu suchen")
                }
                formatOptionLabel={(option) => (
                  <span style={{ display: "flex", flexDirection: "column" }}>
                    <span>{option.label}</span>
                    {option.aliases.length > 0 ? (
                      <small style={{ opacity: 0.65, fontSize: "0.75rem" }}>
                        {option.aliases.slice(0, 2).join(", ")}
                        {option.aliases.length > 2 ? " …" : ""}
                      </small>
                    ) : null}
                  </span>
                )}
              />
            </div>

            <div style={fieldStyle}>
              <label className="advanced-filter-label">{t("Version", "Version")}</label>
              <input
                type="text"
                className="advanced-filter-input"
                value={form.version}
                onChange={(e) => setForm({ ...form, version: e.target.value })}
                placeholder="8.0.25"
              />
            </div>

            <div style={fieldStyle}>
              <label className="advanced-filter-label">{t("Deployment", "Betriebsart")}</label>
              <div className="advanced-filter-chips">
                {DEPLOYMENTS.map((d) => (
                  <button
                    key={d}
                    type="button"
                    className={`advanced-filter-chip ${form.deployment === d ? "active" : ""}`}
                    onClick={() => setForm({ ...form, deployment: d })}
                  >
                    {deploymentLabel(d, t)}
                  </button>
                ))}
              </div>
            </div>

            <div style={fieldStyle}>
              <label className="advanced-filter-label">{t("Environment", "Umgebung")}</label>
              <input
                type="text"
                className="advanced-filter-input"
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

            <div style={fieldStyle}>
              <label className="advanced-filter-label">{t("Instance Count", "Anzahl Instanzen")}</label>
              <input
                type="number"
                min={1}
                className="advanced-filter-input"
                value={form.instanceCount}
                onChange={(e) =>
                  setForm({ ...form, instanceCount: Math.max(1, Number(e.target.value) || 1) })
                }
              />
            </div>

            <div style={fieldStyle}>
              <label className="advanced-filter-label">
                {t("Owner / Team (optional)", "Verantwortlich / Team (optional)")}
              </label>
              <input
                type="text"
                className="advanced-filter-input"
                value={form.owner ?? ""}
                onChange={(e) => setForm({ ...form, owner: e.target.value })}
                placeholder="platform-team"
              />
            </div>

            {eolEnabled && (
              <div style={fieldStyle}>
                <label className="advanced-filter-label">
                  {t("End-of-life tracking", "End-of-Life-Tracking")}
                </label>
                <AsyncSelect<EolOption, false>
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
                <small className="muted" style={{ fontSize: "0.7rem" }}>
                  {t(
                    "endoflife.date product — auto-detected from the product name; change or clear to override.",
                    "endoflife.date-Produkt — automatisch aus dem Produktnamen erkannt; ändern oder leeren zum Überschreiben.",
                  )}
                </small>
              </div>
            )}

            <div style={fieldFullStyle}>
              <label className="advanced-filter-label">{t("Notes (optional)", "Notizen (optional)")}</label>
              <textarea
                className="advanced-filter-input"
                value={form.notes ?? ""}
                onChange={(e) => setForm({ ...form, notes: e.target.value })}
                rows={3}
                style={{ resize: "vertical", fontFamily: "inherit" }}
              />
            </div>

              </div>
              <div className="dialog-actions" style={{ marginTop: "1rem" }}>
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

      {/* Items list */}
      <section className="card">
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            gap: "1rem",
          }}
        >
          <h2 style={{ margin: 0 }}>{t("Configuration management", "Konfigurationsverwaltung")}</h2>
          <button
            type="button"
            className="btn btn-primary inventory-add-btn"
            onClick={() => {
              resetForm();
              setCreating(true);
            }}
            title={t("Add inventory item", "Inventar-Eintrag hinzufügen")}
            aria-label={t("Add inventory item", "Inventar-Eintrag hinzufügen")}
          >
            <LuPlus aria-hidden />
            <span className="hide-mobile">{t("Add", "Hinzufügen")}</span>
          </button>
        </div>
        {items.length > 0 && (
          <div style={{ display: "flex", gap: "0.75rem", alignItems: "center", flexWrap: "wrap", marginTop: "0.5rem", marginBottom: "0.75rem" }}>
            <input
              type="search"
              className="advanced-filter-input"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder={t(
                "Search name, vendor, product, version, owner…",
                "Name, Hersteller, Produkt, Version, Owner durchsuchen…",
              )}
              style={{ flex: 1, minWidth: "240px", maxWidth: "480px" }}
            />
            {search && (
              <span className="muted" style={{ fontSize: "0.8125rem" }}>
                {filteredItems.length} / {items.length}
              </span>
            )}
          </div>
        )}
        {loading ? (
          <p className="muted">{t("Loading...", "Laden...")}</p>
        ) : items.length === 0 ? (
          <p className="muted">
            {t(
              'No inventory items yet. Use the "Add" button above to add your first product + version.',
              'Noch keine Einträge. Nutzen Sie die Schaltfläche „Hinzufügen" oben, um Ihr erstes Produkt + Version anzulegen.',
            )}
          </p>
        ) : filteredItems.length === 0 ? (
          <p className="muted">
            {t("No items match your search.", "Keine Einträge passen zur Suche.")}
          </p>
        ) : (
          <div className="inventory-list">
            {filteredItems.map((item) => {
              const expanded = expandedItemId === item.id;
              const affected = affectedById[item.id];
              const isLoading = affected === "loading";
              const isError =
                !!affected && typeof affected === "object" && !Array.isArray(affected) && "error" in affected;
              const vulns = Array.isArray(affected) ? affected : [];
              const worst = vulns.length > 0 ? severityOf(vulns[0]?.severity as string | null) : "unknown";
              const eolEntry = eolEnabled ? eolById[item.id] : undefined;
              const eolStatus =
                eolEntry && eolEntry !== "loading" && eolEntry.linked ? eolEntry : null;

              return (
                <div key={item.id} className={`inventory-row ${worst}`}>
                  <div
                    className="inventory-row__main"
                    role="button"
                    tabIndex={0}
                    aria-expanded={expanded}
                    onClick={() => toggleExpanded(item.id)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        toggleExpanded(item.id);
                      }
                    }}
                  >
                    <span className={`inventory-row__dot ${worst}`} aria-hidden />
                    <div className="inventory-row__id">
                      <div className="inventory-row__name">{item.name}</div>
                      <div className="inventory-row__sub muted">
                        {[item.vendorName || item.vendorSlug, item.productName || item.productSlug]
                          .filter(Boolean)
                          .join(" / ")}{" "}
                        · <strong>{item.version}</strong>
                        {item.owner ? ` · ${item.owner}` : ""}
                      </div>
                    </div>
                    <div className="inventory-row__meta">
                      <span className="chip">{deploymentLabel(item.deployment, t)}</span>
                      <span className="chip">{environmentLabel(item.environment, t)}</span>
                      <span className="chip">
                        {item.instanceCount}× {t("inst", "Inst")}
                      </span>
                    </div>
                    {eolStatus && (
                      <div
                        className="inventory-row__eol"
                        onClick={(e) => e.stopPropagation()}
                        role="presentation"
                      >
                        <EolStatusBadge status={eolStatus} t={t} />
                      </div>
                    )}
                    <span className={`inventory-row__cve ${vulns.length > 0 ? worst : "none"}`}>
                      {isLoading ? "…" : isError ? "!" : vulns.length}
                      <span className="hide-mobile"> {t("CVEs", "CVEs")}</span>
                    </span>
                    <span className="inventory-row__chevron" aria-hidden>
                      {expanded ? "▾" : "▸"}
                    </span>
                    <div
                      className="inventory-row__actions"
                      role="presentation"
                      onClick={(e) => e.stopPropagation()}
                      onKeyDown={(e) => e.stopPropagation()}
                    >
                      <button
                        type="button"
                        onClick={() => void handleOpenInList(item)}
                        disabled={dqlLoadingId === item.id}
                        title={t(
                          "Open a pre-built DQL query for this item in the Vulnerabilities list",
                          "Vorbereitete DQL-Abfrage für diesen Eintrag in der Schwachstellen-Liste öffnen",
                        )}
                        style={{ ...primaryActionStyle, cursor: dqlLoadingId === item.id ? "wait" : "pointer" }}
                      >
                        {dqlLoadingId === item.id ? t("…", "…") : t("DQL", "DQL")}
                      </button>
                      <button
                        type="button"
                        onClick={() => startEditing(item)}
                        title={t("Edit", "Bearbeiten")}
                        aria-label={t("Edit", "Bearbeiten")}
                        style={neutralActionStyle}
                      >
                        ✎
                      </button>
                      <button
                        type="button"
                        onClick={() => void handleDelete(item.id)}
                        title={t("Delete", "Löschen")}
                        aria-label={t("Delete", "Löschen")}
                        style={dangerActionStyle}
                      >
                        🗑
                      </button>
                    </div>
                  </div>

                  {item.notes && (
                    <div className="inventory-row__notes muted">{item.notes}</div>
                  )}

                  {expanded && (
                    <div className="inventory-row__expand">
                      {eolStatus && <EolDetailBlock status={eolStatus} t={t} />}
                      {isLoading ? (
                        <p className="muted" style={{ margin: 0, fontSize: "0.8125rem" }}>
                          {t("Loading affected vulnerabilities...", "Betroffene Schwachstellen werden geladen...")}
                        </p>
                      ) : isError ? (
                        <div className="alert error">{(affected as { error: string }).error}</div>
                      ) : vulns.length === 0 ? (
                        <p className="muted" style={{ margin: 0, fontSize: "0.8125rem" }}>
                          {t(
                            "No known vulnerabilities currently affect this version.",
                            "Aktuell sind keine Schwachstellen für diese Version bekannt.",
                          )}
                        </p>
                      ) : (
                        <div>
                          <div className="muted" style={{ fontSize: "0.8125rem", marginBottom: "0.5rem" }}>
                            {vulns.length}{" "}
                            {t(
                              vulns.length === 1 ? "affecting vulnerability" : "affecting vulnerabilities",
                              vulns.length === 1 ? "betroffene Schwachstelle" : "betroffene Schwachstellen",
                            )}
                          </div>
                          <div style={{ display: "flex", flexDirection: "column", gap: "0.25rem" }}>
                            {vulns.slice(0, 50).map((v) => {
                              const sev = severityOf(v.severity);
                              return (
                                <Link
                                  key={v.vulnId}
                                  to={`/vulnerability/${encodeURIComponent(v.vulnId)}`}
                                  style={{
                                    display: "flex",
                                    gap: "0.5rem",
                                    alignItems: "center",
                                    padding: "0.35rem 0.5rem",
                                    borderRadius: "4px",
                                    background: "rgba(255,255,255,0.03)",
                                    color: "rgba(255,255,255,0.85)",
                                    textDecoration: "none",
                                    fontSize: "0.8125rem",
                                    minWidth: 0,
                                  }}
                                >
                                  <strong style={{ flexShrink: 0 }}>{v.vulnId}</strong>
                                  {v.exploited && (
                                    <span
                                      className="chip"
                                      style={{
                                        background: "rgba(255,107,107,0.18)",
                                        color: "#ff6b6b",
                                        flexShrink: 0,
                                      }}
                                    >
                                      KEV
                                    </span>
                                  )}
                                  <span
                                    className="muted"
                                    style={{
                                      flex: 1,
                                      minWidth: 0,
                                      overflow: "hidden",
                                      whiteSpace: "nowrap",
                                      textOverflow: "ellipsis",
                                    }}
                                  >
                                    {v.title ?? ""}
                                  </span>
                                  <span
                                    className={`tag ${sev}`}
                                    style={{
                                      height: "1.35rem",
                                      padding: "0 0.4rem",
                                      fontSize: "0.7rem",
                                      marginLeft: "auto",
                                      flexShrink: 0,
                                    }}
                                  >
                                    {sev}
                                  </span>
                                </Link>
                              );
                            })}
                            {vulns.length > 50 && (
                              <div className="muted" style={{ fontSize: "0.75rem", marginTop: "0.25rem" }}>
                                {t("... and", "... und")} {vulns.length - 50} {t("more", "weitere")}
                              </div>
                            )}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </section>

      {/* Aggregated CVE roll-up across every configured item */}
      <section className="card">
        <h2>{t("Flagged CVEs", "Gemeldete CVEs")}</h2>
        <p className="muted">
          {t(
            "Every distinct CVE matching any configured item, sorted by severity.",
            "Jeder eindeutige CVE, der zu einem konfigurierten Eintrag passt, nach Schweregrad sortiert.",
          )}
        </p>
        {aggregatedCves.length === 0 ? (
          <p className="muted" style={{ marginTop: "0.75rem" }}>
            {aggregatedLoading
              ? t("Loading affected vulnerabilities...", "Betroffene Schwachstellen werden geladen...")
              : items.length === 0
                ? t("Add inventory items to see flagged CVEs.", "Fügen Sie Einträge hinzu, um gemeldete CVEs zu sehen.")
                : t("No known vulnerabilities affect your inventory.", "Keine bekannten Schwachstellen betreffen Ihr Inventar.")}
          </p>
        ) : (
          <>
            {aggregatedLoading && (
              <p className="muted" style={{ fontSize: "0.8125rem", marginTop: "0.5rem" }}>
                {t("Still resolving some items…", "Einige Einträge werden noch geladen…")}
              </p>
            )}
            <div style={{ overflowX: "auto", marginTop: "0.75rem" }}>
              <table className="impacted-products__table">
                <thead>
                  <tr>
                    <th>{t("CVE", "CVE")}</th>
                    <th>{t("Severity", "Schweregrad")}</th>
                    <th>{t("CVSS", "CVSS")}</th>
                    <th>{t("EPSS", "EPSS")}</th>
                    <th>{t("Published", "Veröffentlicht")}</th>
                    <th>{t("Affected items", "Betroffene Einträge")}</th>
                  </tr>
                </thead>
                <tbody>
                  {aggregatedCves.map((row) => {
                    const sev = severityOf(row.severity);
                    return (
                      <tr key={row.vulnId}>
                        <td>
                          <Link
                            to={`/vulnerability/${encodeURIComponent(row.vulnId)}`}
                            className="impacted-products__link"
                          >
                            {row.vulnId}
                          </Link>
                          {row.exploited && (
                            <span
                              className="chip"
                              style={{
                                marginLeft: "0.4rem",
                                background: "rgba(255,107,107,0.18)",
                                color: "#ff6b6b",
                              }}
                            >
                              KEV
                            </span>
                          )}
                        </td>
                        <td>
                          <span className={`tag ${sev}`}>{sev}</span>
                        </td>
                        <td>{row.cvssScore != null ? row.cvssScore.toFixed(1) : "—"}</td>
                        <td>
                          {row.epssScore != null ? `${(row.epssScore * 100).toFixed(1)}%` : "—"}
                        </td>
                        <td>{row.published ? formatDateTime(row.published) : "—"}</td>
                        <td>
                          <div className="impacted-products__version-list">
                            {row.items.map((it) => (
                              <span key={it.id} className="impacted-products__version-tag">
                                {it.product} · {it.version}
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
      </section>
    </div>
  );
};
