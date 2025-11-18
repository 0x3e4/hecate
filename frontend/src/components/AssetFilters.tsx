import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import AsyncSelect from "react-select/async";

import { fetchProducts, fetchVendors, fetchVersions } from "../api/assets";
import { usePersistentState } from "../hooks/usePersistentState";
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
}

interface ProductOption {
  value: string;
  label: string;
  vendorSlugs: string[];
  aliases: string[];
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
      console.log(`[Vendors] Using cached results for "${inputValue}":`, vendorCache.current[inputValue].length);
      return vendorCache.current[inputValue];
    }
    try {
      console.log(`[Vendors] Fetching vendors for "${inputValue}"...`);
      const response = await fetchVendors(inputValue || null, SELECT_LIMIT);
      console.log(`[Vendors] Received ${response.items.length} vendors for "${inputValue}"`);
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

  return (
    <section className="card" style={{ marginBottom: "0rem", overflow: "visible" }}>
      <div style={{ display: "flex", gap: "1rem", flexWrap: "wrap" }}>
        <div style={{ display: "flex", flexDirection: "column", minWidth: "240px" }}>
          <span className="meta-label" style={{ marginBottom: "0.35rem" }}>
            Vendors
          </span>
          <AsyncSelect<VendorOption, true>
            isMulti
            cacheOptions
            defaultOptions={false}
            loadOptions={loadVendorOptions}
            value={selectedVendors}
            onChange={(options) => {
              setSelectedVendors(Array.isArray(options) ? options : []);
            }}
            placeholder="Vendors auswählen…"
            styles={selectStyles}
            menuPortalTarget={document.body}
            menuPosition="fixed"
            noOptionsMessage={({ inputValue }) =>
              inputValue ? `Keine Vendors gefunden für "${inputValue}"` : "Tippen Sie, um zu suchen"
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

        <div style={{ display: "flex", flexDirection: "column", minWidth: "240px" }}>
          <span className="meta-label" style={{ marginBottom: "0.35rem" }}>
            Produkte
          </span>
          <AsyncSelect<ProductOption, true>
            isMulti
            cacheOptions
            defaultOptions={false}
            loadOptions={loadProductOptions}
            isDisabled={selectedVendors.length === 0}
            value={selectedProducts}
            onChange={(options) => {
              setSelectedProducts(Array.isArray(options) ? options : []);
            }}
            placeholder={
              selectedVendors.length === 0 ? "Erst Vendor wählen" : "Produkte auswählen…"
            }
            styles={selectStyles}
            menuPortalTarget={document.body}
            menuPosition="fixed"
            noOptionsMessage={({ inputValue }) =>
              inputValue ? `Keine Produkte gefunden für "${inputValue}"` : "Tippen Sie, um zu suchen"
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

        <div style={{ display: "flex", flexDirection: "column", minWidth: "240px" }}>
          <span className="meta-label" style={{ marginBottom: "0.35rem" }}>
            Versionen
          </span>
          <AsyncSelect<VersionOption, true>
            isMulti
            cacheOptions
            defaultOptions={false}
            loadOptions={loadVersionOptions}
            isDisabled={isVersionDisabled}
            value={selectedVersions}
            onChange={(options) => {
              setSelectedVersions(Array.isArray(options) ? options : []);
            }}
            placeholder={
              isVersionDisabled
                ? "Genau ein Produkt wählen"
                : "Versionen auswählen…"
            }
            styles={selectStyles}
            menuPortalTarget={document.body}
            menuPosition="fixed"
            noOptionsMessage={({ inputValue }) =>
              inputValue ? `Keine Versionen gefunden für "${inputValue}"` : "Tippen Sie, um zu suchen"
            }
          />
        </div>
      </div>
    </section>
  );
};

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

const mapVersionToOption = (item: CatalogVersion): VersionOption => ({
  value: item.id,
  label: item.value,
  productSlug: item.productSlug,
});

const selectStyles = {
  control: (provided: any) => ({
    ...provided,
    background: "rgba(15, 18, 30, 0.85)",
    borderColor: "rgba(255, 255, 255, 0.12)",
    borderRadius: "8px",
    color: "#f5f7fa",
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
  multiValue: (provided: any) => ({
    ...provided,
    background: "rgba(92,132,255,0.15)",
  }),
  multiValueLabel: (provided: any) => ({
    ...provided,
    color: "#f5f7fa",
  }),
  input: (provided: any) => ({
    ...provided,
    color: "#f5f7fa",
  }),
  singleValue: (provided: any) => ({
    ...provided,
    color: "#f5f7fa",
  }),
  placeholder: (provided: any) => ({
    ...provided,
    color: "rgba(255, 255, 255, 0.6)",
  }),
};
