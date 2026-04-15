import { useCallback, useEffect, useMemo, useState, type CSSProperties } from "react";
import { Link, useNavigate } from "react-router-dom";
import AsyncSelect from "react-select/async";

import {
  createInventoryItem,
  deleteInventoryItem,
  fetchInventoryAffectedVulnerabilities,
  fetchInventoryItems,
  updateInventoryItem,
  type InventoryItemCreateInput,
} from "../api/inventory";
import { fetchProducts, fetchVendors } from "../api/assets";
import { useI18n, type TranslateFn } from "../i18n/context";
import type {
  AffectedVulnerabilityItem,
  CatalogProduct,
  CatalogVendor,
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
    zIndex: 9999,
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

const itemGridStyle: CSSProperties = {
  display: "grid",
  gap: "1rem",
  gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))",
  // Rows size to their content so expanding one card's "Show CVEs"
  // section doesn't stretch every other card in the same row.
  gridAutoRows: "min-content",
  alignItems: "start",
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
  const navigate = useNavigate();

  const [items, setItems] = useState<InventoryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [creating, setCreating] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [form, setForm] = useState<InventoryItemCreateInput>(emptyForm());
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);

  const [selectedVendor, setSelectedVendor] = useState<VendorOption | null>(null);
  const [selectedProduct, setSelectedProduct] = useState<ProductOption | null>(null);

  const [search, setSearch] = useState("");
  const [expandedItemId, setExpandedItemId] = useState<string | null>(null);
  const [affectedById, setAffectedById] = useState<
    Record<string, AffectedVulnerabilityItem[] | "loading" | { error: string }>
  >({});

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
    setCreating(false);
    setEditingId(null);
    setSaveError(null);
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
    setEditingId(item.id);
    setCreating(true);
    setSaveError(null);
  };

  const handleSave = async () => {
    if (!form.name.trim() || !form.vendorSlug.trim() || !form.productSlug.trim() || !form.version.trim()) {
      setSaveError(
        t(
          "Name, vendor, product and version are required.",
          "Name, Hersteller, Produkt und Version sind erforderlich.",
        ),
      );
      return;
    }
    setSaving(true);
    setSaveError(null);
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
      if (editingId) {
        await updateInventoryItem(editingId, payload);
      } else {
        await createInventoryItem(payload);
      }
      resetForm();
      await loadItems();
    } catch (exc: unknown) {
      const message = exc instanceof Error ? exc.message : String(exc);
      setSaveError(message);
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
    } catch (exc: unknown) {
      setError(exc instanceof Error ? exc.message : String(exc));
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

      {/* Create / edit card */}
      <section className="card">
        <h2>
          {editingId
            ? t("Edit Item", "Eintrag bearbeiten")
            : t("Add Item", "Eintrag hinzufügen")}
        </h2>
        <p className="muted">
          {t(
            "Vendor and product auto-complete from the asset catalog. Versions accept exact values (8.0.25) or wildcards (8.0.*).",
            "Hersteller und Produkt werden aus dem Asset-Katalog vervollständigt. Versionen akzeptieren exakte Werte (8.0.25) oder Wildcards (8.0.*).",
          )}
        </p>

        {!creating && editingId === null && (
          <button
            type="button"
            onClick={() => {
              resetForm();
              setCreating(true);
            }}
            style={{ marginTop: "1rem" }}
          >
            + {t("Add Inventory Item", "Inventar-Eintrag hinzufügen")}
          </button>
        )}

        {(creating || editingId !== null) && (
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

            {saveError && (
              <div style={fieldFullStyle}>
                <div className="alert error">{saveError}</div>
              </div>
            )}

            <div style={{ ...fieldFullStyle, flexDirection: "row", gap: "0.5rem", flexWrap: "wrap" }}>
              <button type="button" onClick={() => void handleSave()} disabled={saving}>
                {saving
                  ? t("Saving...", "Speichern…")
                  : editingId
                    ? t("Save", "Speichern")
                    : t("Create", "Erstellen")}
              </button>
              <button
                type="button"
                onClick={resetForm}
                style={{
                  background: "rgba(255,255,255,0.06)",
                  border: "1px solid rgba(255,255,255,0.12)",
                  color: "rgba(255,255,255,0.7)",
                }}
              >
                {t("Cancel", "Abbrechen")}
              </button>
            </div>
          </div>
        )}
      </section>

      {/* Items list */}
      <section className="card">
        <h2>{t("Your Inventory", "Ihr Inventar")}</h2>
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
              "No inventory items yet. Add your first product + version above.",
              "Noch keine Einträge. Fügen Sie oben Ihr erstes Produkt + Version hinzu.",
            )}
          </p>
        ) : filteredItems.length === 0 ? (
          <p className="muted">
            {t("No items match your search.", "Keine Einträge passen zur Suche.")}
          </p>
        ) : (
          <div style={itemGridStyle}>
            {filteredItems.map((item) => {
              const expanded = expandedItemId === item.id;
              const affected = affectedById[item.id];
              const isLoading = affected === "loading";
              const isError =
                !!affected && typeof affected === "object" && !Array.isArray(affected) && "error" in affected;
              const vulns = Array.isArray(affected) ? affected : [];

              return (
                <div
                  key={item.id}
                  className={`vuln-card ${
                    isError
                      ? "unknown"
                      : vulns.length > 0
                        ? severityOf(vulns[0]?.severity as string | null)
                        : "unknown"
                  }`}
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    gap: "0.5rem",
                    minWidth: 0,
                    // Prevent CSS grid from stretching unrelated cards in
                    // the same row when one card's "Show CVEs" section
                    // expands.
                    alignSelf: "start",
                  }}
                >
                  <div className="vuln-header">
                    <div className="vuln-id" style={{ flex: 1, flexWrap: "wrap" }}>
                      <span className="chip">{item.version}</span>
                      <span className="chip">{deploymentLabel(item.deployment, t)}</span>
                      <span className="chip">{environmentLabel(item.environment, t)}</span>
                      <span className="chip">
                        {item.instanceCount}{" "}
                        {t(
                          item.instanceCount === 1 ? "instance" : "instances",
                          item.instanceCount === 1 ? "Instanz" : "Instanzen",
                        )}
                      </span>
                    </div>
                  </div>
                  <h3 className="vuln-title" style={{ margin: 0, fontSize: "1rem", wordBreak: "break-word" }}>
                    {item.name}
                  </h3>
                  <div className="muted" style={{ fontSize: "0.8rem", wordBreak: "break-word" }}>
                    {[item.vendorName || item.vendorSlug, item.productName || item.productSlug]
                      .filter(Boolean)
                      .join(" / ")}
                    {item.owner ? ` · ${item.owner}` : ""}
                  </div>
                  {item.notes && (
                    <div className="muted" style={{ fontSize: "0.8rem", fontStyle: "italic", wordBreak: "break-word" }}>
                      {item.notes}
                    </div>
                  )}
                  <div className="muted" style={{ fontSize: "0.7rem" }}>
                    {t("Updated", "Aktualisiert")}: {formatDateTime(item.updatedAt)}
                  </div>
                  <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap", marginTop: "0.5rem" }}>
                    <button
                      type="button"
                      onClick={() => toggleExpanded(item.id)}
                      style={neutralActionStyle}
                    >
                      {expanded ? t("Hide CVEs", "CVEs ausblenden") : t("Show CVEs", "CVEs anzeigen")}
                    </button>
                    <button
                      type="button"
                      onClick={() => void handleOpenInList(item)}
                      disabled={dqlLoadingId === item.id}
                      title={t(
                        "Open a pre-built DQL query for this item in the Vulnerabilities list",
                        "Vorbereitete DQL-Abfrage für diesen Eintrag in der Schwachstellen-Liste öffnen",
                      )}
                      style={{
                        ...primaryActionStyle,
                        cursor: dqlLoadingId === item.id ? "wait" : "pointer",
                      }}
                    >
                      {dqlLoadingId === item.id ? t("…", "…") : t("DQL", "DQL")}
                    </button>
                    <button
                      type="button"
                      onClick={() => startEditing(item)}
                      style={neutralActionStyle}
                    >
                      {t("Edit", "Bearbeiten")}
                    </button>
                    <button
                      type="button"
                      onClick={() => void handleDelete(item.id)}
                      style={dangerActionStyle}
                    >
                      {t("Delete", "Löschen")}
                    </button>
                  </div>
                  {expanded && (
                    <div
                      style={{
                        marginTop: "0.75rem",
                        paddingTop: "0.75rem",
                        borderTop: "1px solid rgba(255,255,255,0.06)",
                        minWidth: 0,
                      }}
                    >
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
    </div>
  );
};
