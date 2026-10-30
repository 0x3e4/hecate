import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import AsyncSelect from "react-select/async";

import { fetchProducts, fetchVendors, fetchVersions } from "../api/assets";
import { renderCatalogOption } from "./CatalogOption";
import { primaryVendorSlug } from "../utils/catalog";
import { usePersistentState } from "../hooks/usePersistentState";
import { useI18n } from "../i18n/context";
import type {
  CatalogProduct,
  CatalogVendor,
  CatalogVersion,
} from "../types";

export interface AssetFiltersSelection {
  vendorSlugs: string[];
  productSlugs: string[];
  versionIds: string[];
}

interface Props {
  onChange: (selection: AssetFiltersSelection) => void;
  selection?: AssetFiltersSelection;
}

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

interface VersionOption {
  value: string;
  label: string;
  productSlug: string;
}

const SELECT_LIMIT = 200;
const PREFETCH_LIMIT = 200;

const uniqueByValue = <T extends { value: string }>(items: T[]): T[] => {
  const seen = new Map<string, T>();
  items.forEach((item) => {
    if (!seen.has(item.value)) {
      seen.set(item.value, item);
    }
  });
  return Array.from(seen.values());
};

const areSetsEqual = (a: Set<string>, b: Set<string>): boolean => {
  if (a.size !== b.size) {
    return false;
  }
  for (const value of a) {
    if (!b.has(value)) {
      return false;
    }
  }
  return true;
};

const buildSelectionKey = (selection?: AssetFiltersSelection): string | null => {
  if (!selection) {
    return null;
  }
  const join = (values: string[]) => values.join("\u0001");
  return [
    join(selection.vendorSlugs),
    join(selection.productSlugs),
    join(selection.versionIds),
  ].join("\u0002");
};

export const AssetFilters = ({ onChange, selection }: Props) => {
  const { t } = useI18n();
  const [selectedVendors, setSelectedVendors] = usePersistentState<VendorOption[]>(
    "assetFilter:vendors",
    [],
  );
  const [selectedProducts, setSelectedProducts] = usePersistentState<ProductOption[]>(
    "assetFilter:products",
    [],
  );
  const [selectedVersions, setSelectedVersions] = usePersistentState<VersionOption[]>(
    "assetFilter:versions",
    [],
  );

  const vendorCache = useRef<Record<string, VendorOption[]>>({});
  const productCache = useRef<Record<string, ProductOption[]>>({});
  const versionCache = useRef<Record<string, VersionOption[]>>({});

  const vendorLookup = useRef(new Map<string, VendorOption>());
  const productLookup = useRef(new Map<string, ProductOption>());
  const versionLookup = useRef(new Map<string, VersionOption>());

  const [initialProductOptions, setInitialProductOptions] = useState<ProductOption[]>([]);
  const [initialVersionOptions, setInitialVersionOptions] = useState<VersionOption[]>([]);
  const [initialVendors, setInitialVendors] = usePersistentState<VendorOption[]>(
    "assetFilter:initialVendors",
    [],
  );

  const registerVendors = useCallback((options: VendorOption[]) => {
    options.forEach((option) => {
      vendorLookup.current.set(option.value, option);
    });
  }, []);

  const registerProducts = useCallback((options: ProductOption[]) => {
    options.forEach((option) => {
      productLookup.current.set(option.value, option);
    });
  }, []);

  const registerVersions = useCallback((options: VersionOption[]) => {
    options.forEach((option) => {
      versionLookup.current.set(option.value, option);
    });
  }, []);

  const selectionKey = useMemo(() => buildSelectionKey(selection), [selection]);
  const lastAppliedSelectionKey = useRef<string | null>(null);
  const isSyncingRef = useRef<boolean>(false);

  useEffect(() => {
    registerVendors([...initialVendors, ...selectedVendors]);
  }, [initialVendors, registerVendors, selectedVendors]);

  useEffect(() => {
    registerProducts([...initialProductOptions, ...selectedProducts]);
  }, [initialProductOptions, registerProducts, selectedProducts]);

  useEffect(() => {
    registerVersions([...initialVersionOptions, ...selectedVersions]);
  }, [initialVersionOptions, registerVersions, selectedVersions]);

  useEffect(() => {
    const bootstrapVendors = async () => {
      if (initialVendors.length > 0) {
        return;
      }
      try {
        const response = await fetchVendors(null, SELECT_LIMIT);
        const options = response.items.map(mapVendorToOption);
        vendorCache.current[""] = options;
        registerVendors(options);
        setInitialVendors(options);
      } catch (error) {
        console.error("Failed to preload vendor catalog", error);
      }
    };
    bootstrapVendors();
  }, [initialVendors, registerVendors, setInitialVendors]);

  useEffect(() => {
    if (isSyncingRef.current) {
      return;
    }

    if (selection && selectionKey && selectionKey !== lastAppliedSelectionKey.current) {
      return;
    }

    const selectionState: AssetFiltersSelection = {
      vendorSlugs: selectedVendors.map((vendor) => vendor.value),
      productSlugs: selectedProducts.map((product) => product.value),
      versionIds: selectedVersions.map((version) => version.value),
    };

    onChange(selectionState);
  }, [onChange, selectedProducts, selectedVendors, selectedVersions, selection, selectionKey]);

  useEffect(() => {
    if (selectedVendors.length === 0) {
      if (selectedProducts.length > 0) {
        setSelectedProducts([]);
      }
      if (selectedVersions.length > 0) {
        setSelectedVersions([]);
      }
    } else {
      const vendorSlugs = new Set(selectedVendors.map((vendor) => vendor.value));
      const filteredProducts = selectedProducts.filter((product) =>
        product.vendorSlugs.some((slug) => vendorSlugs.has(slug)),
      );
      if (filteredProducts.length !== selectedProducts.length) {
        setSelectedProducts(filteredProducts);
      }
    }
  }, [selectedProducts, selectedVendors, selectedVersions, setSelectedProducts, setSelectedVersions]);

  useEffect(() => {
    if (selectedProducts.length === 0 && selectedVersions.length > 0) {
      setSelectedVersions([]);
      return;
    }

    const productSlugSet = new Set(selectedProducts.map((product) => product.value));
    const filteredVersions = selectedVersions.filter((version) =>
      productSlugSet.has(version.productSlug),
    );
    if (filteredVersions.length !== selectedVersions.length) {
      setSelectedVersions(filteredVersions);
    }
  }, [selectedProducts, selectedVersions, setSelectedVersions]);

  useEffect(() => {
    if (selectedVendors.length === 0) {
      setInitialProductOptions([]);
      return;
    }
    const vendorKey = selectedVendors.map((vendor) => vendor.value).sort().join("|");
    const cacheKey = `${vendorKey}::`;
    const cached = productCache.current[cacheKey];
    if (cached) {
      setInitialProductOptions(cached);
      return;
    }
    const loadInitialProducts = async () => {
      try {
        const response = await fetchProducts(
          selectedVendors.map((vendor) => vendor.value),
          null,
          SELECT_LIMIT,
        );
        const options = response.items.map(mapProductToOption);
        productCache.current[cacheKey] = options;
        registerProducts(options);
        setInitialProductOptions(options);
      } catch (error) {
        console.error("Failed to preload products for vendor selection", error);
      }
    };
    loadInitialProducts();
  }, [registerProducts, selectedVendors]);

  useEffect(() => {
    if (selectedProducts.length !== 1) {
      setInitialVersionOptions([]);
      return;
    }
    const productSlug = selectedProducts[0]?.value ?? "";
    const cacheKey = `${productSlug}::`;
    const cached = versionCache.current[cacheKey];
    if (cached) {
      setInitialVersionOptions(cached);
      return;
    }
    const loadInitialVersions = async () => {
      try {
        const response = await fetchVersions(productSlug, null, SELECT_LIMIT);
        const options = response.items.map(mapVersionToOption);
        versionCache.current[cacheKey] = options;
        registerVersions(options);
        setInitialVersionOptions(options);
      } catch (error) {
        console.error("Failed to preload versions for product selection", error);
      }
    };
    loadInitialVersions();
  }, [registerVersions, selectedProducts]);

  const resolveVendorsBySlugs = useCallback(async (slugs: string[]): Promise<VendorOption[]> => {
    if (slugs.length === 0) {
      return [];
    }

    const missing = slugs.filter((slug) => !vendorLookup.current.has(slug));
    if (missing.length > 0) {
      await Promise.all(
        missing.map(async (slug) => {
          try {
            const response = await fetchVendors(slug, PREFETCH_LIMIT);
            const options = response.items.map(mapVendorToOption);
            vendorCache.current[slug] = options;
            registerVendors(options);
          } catch (error) {
            console.error(`Failed to resolve vendor for slug "${slug}"`, error);
          }
        }),
      );
    }

    return slugs
      .map((slug) => vendorLookup.current.get(slug))
      .filter((option): option is VendorOption => Boolean(option));
  }, [registerVendors]);

  const resolveProductsBySlugs = useCallback(
    async (slugs: string[], vendorSlugs: string[]): Promise<ProductOption[]> => {
      if (slugs.length === 0 || vendorSlugs.length === 0) {
        return [];
      }

      const missing = slugs.filter((slug) => !productLookup.current.has(slug));
      if (missing.length > 0) {
        const vendorKey = vendorSlugs.slice().sort().join("|");
        for (const slug of missing) {
          const cacheKey = `${vendorKey}::${slug}`;
          let options = productCache.current[cacheKey];
          if (!options) {
            try {
              const response = await fetchProducts(vendorSlugs, slug || null, PREFETCH_LIMIT);
              options = response.items.map(mapProductToOption);
              productCache.current[cacheKey] = options;
            } catch (error) {
              console.error(`Failed to resolve product for slug "${slug}"`, error);
              options = [];
            }
          }
          registerProducts(options);
        }
      }

      return slugs
        .map((slug) => productLookup.current.get(slug))
        .filter((option): option is ProductOption => Boolean(option));
    },
    [registerProducts],
  );

  const resolveVersionsByIds = useCallback(
    async (ids: string[], productSlugs: string[]): Promise<VersionOption[]> => {
      if (ids.length === 0) {
        return [];
      }

      const missing = ids.filter((id) => !versionLookup.current.has(id));
      if (missing.length > 0 && productSlugs.length > 0) {
        for (const productSlug of productSlugs) {
          const cacheKey = `${productSlug}::`;
          let options = versionCache.current[cacheKey];
          if (!options) {
            try {
              const response = await fetchVersions(productSlug, null, PREFETCH_LIMIT);
              options = response.items.map(mapVersionToOption);
              versionCache.current[cacheKey] = options;
            } catch (error) {
              console.error(`Failed to resolve versions for product "${productSlug}"`, error);
              options = [];
            }
          }
          registerVersions(options);
        }
      }

      return ids
        .map((id) => versionLookup.current.get(id))
        .filter((option): option is VersionOption => Boolean(option));
    },
    [registerVersions],
  );

  useEffect(() => {
    if (!selection) {
      lastAppliedSelectionKey.current = null;
      isSyncingRef.current = false;
      return;
    }

    const key = selectionKey;
    if (key == null) {
      return;
    }

    if (lastAppliedSelectionKey.current === key) {
      return;
    }

    let cancelled = false;
    isSyncingRef.current = true;

    const syncSelection = async () => {
      let nextVendors = selectedVendors;
      const desiredVendorSet = new Set(selection.vendorSlugs);
      const currentVendorSet = new Set(nextVendors.map((vendor) => vendor.value));

      if (!areSetsEqual(desiredVendorSet, currentVendorSet)) {
        if (selection.vendorSlugs.length === 0) {
          nextVendors = [];
        } else {
          nextVendors = await resolveVendorsBySlugs(selection.vendorSlugs);
          if (cancelled) {
            return;
          }
        }
        setSelectedVendors(nextVendors);
      }

      let nextProducts = selectedProducts;
      const desiredProductSet = new Set(selection.productSlugs);
      const currentProductSet = new Set(nextProducts.map((product) => product.value));

      if (!areSetsEqual(desiredProductSet, currentProductSet)) {
        if (selection.productSlugs.length === 0) {
          nextProducts = [];
        } else {
          nextProducts = await resolveProductsBySlugs(selection.productSlugs, selection.vendorSlugs);
          if (cancelled) {
            return;
          }
        }
        setSelectedProducts(nextProducts);
      }

      let nextVersions = selectedVersions;
      const desiredVersionSet = new Set(selection.versionIds);
      const currentVersionSet = new Set(nextVersions.map((version) => version.value));

      if (!areSetsEqual(desiredVersionSet, currentVersionSet)) {
        if (selection.versionIds.length === 0) {
          nextVersions = [];
        } else {
          nextVersions = await resolveVersionsByIds(selection.versionIds, selection.productSlugs);
          if (cancelled) {
            return;
          }
        }
        setSelectedVersions(nextVersions);
      }

      if (!cancelled) {
        lastAppliedSelectionKey.current = key;
        isSyncingRef.current = false;
      }
    };

    void syncSelection();

    return () => {
      cancelled = true;
      isSyncingRef.current = false;
    };
  }, [
    resolveProductsBySlugs,
    resolveVendorsBySlugs,
    resolveVersionsByIds,
    selection,
    selectionKey,
    selectedProducts,
    selectedVendors,
    selectedVersions,
  ]);

  const vendorDefaultOptions = useMemo(
    () => uniqueByValue<VendorOption>([...selectedVendors, ...initialVendors]),
    [initialVendors, selectedVendors],
  );

  const productDefaultOptions = useMemo(
    () => uniqueByValue<ProductOption>([...selectedProducts, ...initialProductOptions]),
    [initialProductOptions, selectedProducts],
  );

  const versionDefaultOptions = useMemo(
    () => uniqueByValue<VersionOption>([...selectedVersions, ...initialVersionOptions]),
    [initialVersionOptions, selectedVersions],
  );

  const loadVendorOptions = useCallback(async (inputValue: string): Promise<VendorOption[]> => {
    if (vendorCache.current[inputValue]) {
      return vendorCache.current[inputValue];
    }
    try {
      const response = await fetchVendors(inputValue || null, SELECT_LIMIT);
      const options = response.items.map(mapVendorToOption);
      vendorCache.current[inputValue] = options;
      registerVendors(options);
      return options;
    } catch (error) {
      console.error("Failed to load vendor catalog", error);
      return [];
    }
  }, [registerVendors]);

  const loadProductOptions = useCallback(async (inputValue: string): Promise<ProductOption[]> => {
    if (selectedVendors.length === 0) {
      return [];
    }
    const vendorSlugs = selectedVendors.map((vendor) => vendor.value).sort().join("|");
    const cacheKey = `${vendorSlugs}::${inputValue}`;
    if (productCache.current[cacheKey]) {
      return productCache.current[cacheKey];
    }
    try {
      const response = await fetchProducts(
        selectedVendors.map((vendor) => vendor.value),
        inputValue || null,
        SELECT_LIMIT,
      );
      const options = response.items.map(mapProductToOption);
      productCache.current[cacheKey] = options;
      registerProducts(options);
      return options;
    } catch (error) {
      console.error("Failed to load product catalog", error);
      return [];
    }
  }, [registerProducts, selectedVendors]);

  const loadVersionOptions = useCallback(async (inputValue: string): Promise<VersionOption[]> => {
    if (selectedProducts.length !== 1) {
      return [];
    }
    const productSlug = selectedProducts[0]?.value ?? "";
    const cacheKey = `${productSlug}::${inputValue}`;
    if (versionCache.current[cacheKey]) {
      return versionCache.current[cacheKey];
    }
    try {
      const response = await fetchVersions(productSlug, inputValue || null, SELECT_LIMIT);
      const options = response.items.map(mapVersionToOption);
      versionCache.current[cacheKey] = options;
      registerVersions(options);
      return options;
    } catch (error) {
      console.error("Failed to load version catalog", error);
      return [];
    }
  }, [registerVersions, selectedProducts]);

  const isVersionDisabled = selectedProducts.length !== 1;

  const hasVendors = selectedVendors.length > 0;
  const hasProducts = selectedProducts.length > 0;

  return (
    <div className="vulnerability-list-asset-filters">
      <div className="vulnerability-list-asset-field">
        <span className="vulnerability-list-asset-label" id="vulnerability-list-vendors-label">
          {t("Vendors", "Vendors")}
        </span>
        <AsyncSelect<VendorOption, true>
          className="vulnerability-list-asset-control"
          aria-labelledby="vulnerability-list-vendors-label"
          isMulti
          cacheOptions
          defaultOptions={false}
          loadOptions={loadVendorOptions}
          value={selectedVendors}
          onChange={(options) => {
            setSelectedVendors(Array.isArray(options) ? options : []);
          }}
          placeholder={t("Select vendors...", "Vendors auswählen...")}
          styles={selectStyles}
          menuPortalTarget={document.body}
          menuPosition="fixed"
          noOptionsMessage={({ inputValue }) =>
            inputValue
              ? t(`No vendors found for "${inputValue}"`, `Keine Vendors gefunden für "${inputValue}"`)
              : t("Type to search", "Tippen Sie, um zu suchen")
          }
          formatOptionLabel={renderCatalogOption}
        />
      </div>

      {hasVendors && (
        <div className="vulnerability-list-asset-field">
          <span className="vulnerability-list-asset-label" id="vulnerability-list-products-label">
            {t("Products", "Produkte")}
          </span>
          <AsyncSelect<ProductOption, true>
            className="vulnerability-list-asset-control"
            aria-labelledby="vulnerability-list-products-label"
            isMulti
            cacheOptions
            defaultOptions={false}
            loadOptions={loadProductOptions}
            value={selectedProducts}
            onChange={(options) => {
              setSelectedProducts(Array.isArray(options) ? options : []);
            }}
            placeholder={t("Select products...", "Produkte auswählen...")}
            styles={selectStyles}
            menuPortalTarget={document.body}
            menuPosition="fixed"
            noOptionsMessage={({ inputValue }) =>
              inputValue
                ? t(`No products found for "${inputValue}"`, `Keine Produkte gefunden für "${inputValue}"`)
                : t("Type to search", "Tippen Sie, um zu suchen")
            }
            formatOptionLabel={renderCatalogOption}
          />
        </div>
      )}

      {hasProducts && !isVersionDisabled && (
        <div className="vulnerability-list-asset-field">
          <span className="vulnerability-list-asset-label" id="vulnerability-list-versions-label">
            {t("Versions", "Versionen")}
          </span>
          <AsyncSelect<VersionOption, true>
            className="vulnerability-list-asset-control"
            aria-labelledby="vulnerability-list-versions-label"
            isMulti
            cacheOptions
            defaultOptions={false}
            loadOptions={loadVersionOptions}
            value={selectedVersions}
            onChange={(options) => {
              setSelectedVersions(Array.isArray(options) ? options : []);
            }}
            placeholder={t("Select versions...", "Versionen auswählen...")}
            styles={selectStyles}
            menuPortalTarget={document.body}
            menuPosition="fixed"
            noOptionsMessage={({ inputValue }) =>
              inputValue
                ? t(`No versions found for "${inputValue}"`, `Keine Versionen gefunden für "${inputValue}"`)
                : t("Type to search", "Tippen Sie, um zu suchen")
            }
          />
        </div>
      )}
    </div>
  );
};

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

const mapVersionToOption = (item: CatalogVersion): VersionOption => ({
  value: item.id,
  label: item.value,
  productSlug: item.productSlug,
});

const selectStyles = {
  control: (provided: any, state: any) => ({
    ...provided,
    minHeight: "var(--control-height)",
    alignItems: "stretch",
    flexWrap: "nowrap",
    background: "var(--color-paper)",
    border: 0,
    borderRadius: "var(--radius-control)",
    color: "var(--color-ink)",
    fontSize: "var(--text-sm)",
    boxShadow: "none",
    outline: state.isFocused ? "2px solid var(--color-focus)" : "none",
    outlineOffset: "-1px",
  }),
  // The field edge is drawn on these two parts so it sits next to the input it bounds.
  valueContainer: (provided: any) => ({
    ...provided,
    padding: "0 var(--space-xs)",
    gap: "var(--space-2xs)",
    border: "var(--rule-hair) solid var(--color-field-edge)",
    borderRight: 0,
    borderRadius: "var(--radius-control) 0 0 var(--radius-control)",
  }),
  indicatorsContainer: (provided: any) => ({
    ...provided,
    border: "var(--rule-hair) solid var(--color-field-edge)",
    borderLeft: 0,
    borderRadius: "0 var(--radius-control) var(--radius-control) 0",
  }),
  menu: (provided: any) => ({
    ...provided,
    marginBlock: "var(--space-2xs)",
    background: "var(--color-paper-2)",
    border: "var(--rule-hair) solid var(--color-rule-strong)",
    borderRadius: "var(--radius-card)",
    boxShadow: "var(--shadow-pop)",
    fontSize: "var(--text-sm)",
    zIndex: "var(--z-dropdown)",
  }),
  menuPortal: (provided: any) => ({
    ...provided,
    zIndex: "var(--z-modal)",
  }),
  option: (provided: any, state: any) => ({
    ...provided,
    backgroundColor: state.isFocused ? "var(--overlay-2)" : "transparent",
    color: "var(--color-ink)",
    padding: "var(--space-xs) var(--space-sm)",
    "&:active": {
      backgroundColor: "var(--overlay-3)",
    },
  }),
  multiValue: (provided: any) => ({
    ...provided,
    margin: 0,
    background: "transparent",
    border: "var(--rule-hair) solid var(--color-rule-strong)",
    borderRadius: "var(--radius-control)",
  }),
  multiValueLabel: (provided: any) => ({
    ...provided,
    color: "var(--color-ink-2)",
    fontSize: "var(--text-xs)",
  }),
  multiValueRemove: (provided: any) => ({
    ...provided,
    color: "var(--color-muted)",
    "&:hover": {
      background: "var(--overlay-2)",
      color: "var(--color-ink)",
    },
  }),
  dropdownIndicator: (provided: any) => ({
    ...provided,
    padding: "var(--space-xs)",
    color: "var(--color-muted)",
    "&:hover": {
      color: "var(--color-ink)",
    },
  }),
  clearIndicator: (provided: any) => ({
    ...provided,
    padding: "var(--space-xs)",
    color: "var(--color-muted)",
    "&:hover": {
      color: "var(--color-ink)",
    },
  }),
  indicatorSeparator: () => ({
    display: "none",
  }),
  input: (provided: any) => ({
    ...provided,
    margin: 0,
    padding: 0,
    color: "var(--color-ink)",
    caretColor: "var(--color-accent)",
    "& input": {
      minHeight: "32px !important",
      outline: "none !important",
      boxShadow: "none !important",
      border: "none !important",
    },
  }),
  singleValue: (provided: any) => ({
    ...provided,
    color: "var(--color-ink)",
  }),
  placeholder: (provided: any) => ({
    ...provided,
    margin: 0,
    color: "var(--color-muted)",
  }),
  noOptionsMessage: (provided: any) => ({
    ...provided,
    color: "var(--color-muted)",
  }),
  loadingMessage: (provided: any) => ({
    ...provided,
    color: "var(--color-muted)",
  }),
};
