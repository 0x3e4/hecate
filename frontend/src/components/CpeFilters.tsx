import { useEffect, useMemo, useRef, useState } from "react";
import AsyncSelect from "react-select/async";

import { fetchCpeProducts, fetchCpeVendors } from "../api/cpe";
import { usePersistentState } from "../hooks/usePersistentState";

interface Props {
  onChange: (filters: { vendors: string[]; products: string[] }) => void;
}

export const CpeFilters = ({ onChange }: Props) => {
  const [selectedVendors, setSelectedVendors] = usePersistentState<string[]>("cpe:selectedVendors", []);
  const [selectedProducts, setSelectedProducts] = usePersistentState<string[]>("cpe:selectedProducts", []);
  const [initialVendorOptions, setInitialVendorOptions] = useState<{ value: string; label: string }[]>([]);

  useEffect(() => {
    onChange({
      vendors: selectedVendors,
      products: selectedProducts,
    });
  }, [onChange, selectedProducts, selectedVendors]);

  useEffect(() => {
    if (selectedVendors.length === 0) {
      setSelectedProducts([]);
    }
  }, [selectedVendors, setSelectedProducts]);

  const defaultVendorOptions = useMemo(
    () => selectedVendors.map((value) => ({ value, label: value })),
    [selectedVendors]
  );
  const defaultProductOptions = useMemo(
    () => selectedProducts.map((value) => ({ value, label: value })),
    [selectedProducts]
  );
  const vendorOptionCache = useRef<Record<string, { value: string; label: string }[]>>({});
  const productOptionCache = useRef<Record<string, { value: string; label: string }[]>>({});

  useEffect(() => {
    const hydrateInitialVendors = async () => {
      try {
        const response = await fetchCpeVendors(null, 25);
        const options = response.items.map((value) => ({ value, label: value }));
        vendorOptionCache.current[""] = options;
        setInitialVendorOptions(options);
      } catch (error) {
        console.error("Failed to prefetch CPE vendors", error);
      }
    };

    hydrateInitialVendors();
  }, []);

  const loadVendorOptions = async (inputValue: string) => {
    if (vendorOptionCache.current[inputValue] && vendorOptionCache.current[inputValue].length) {
      return vendorOptionCache.current[inputValue];
    }
    try {
      const response = await fetchCpeVendors(inputValue || null, 25);
      const options = response.items.map((value) => ({ value, label: value }));
      vendorOptionCache.current[inputValue] = options;
      return options;
    } catch (error) {
      console.error("Failed to load CPE vendors", error);
      return [];
    }
  };

  const loadProductOptions = async (inputValue: string) => {
    if (selectedVendors.length === 0) {
      return [];
    }
    const cacheKey = `${selectedVendors.sort().join("|")}::${inputValue}`;
    if (productOptionCache.current[cacheKey] && productOptionCache.current[cacheKey].length) {
      return productOptionCache.current[cacheKey];
    }
    try {
      const response = await fetchCpeProducts(selectedVendors, inputValue || null, 25);
      const options = response.items.map((value) => ({ value, label: value }));
      const knownValues = new Set(options.map((option) => option.value));
      const merged = [...options];
      selectedProducts.forEach((value) => {
        if (!knownValues.has(value)) {
          merged.push({ value, label: value });
        }
      });
      productOptionCache.current[cacheKey] = merged;
      return merged;
    } catch (error) {
      console.error("Failed to load CPE products", error);
      return [];
    }
  };

  return (
    <section className="card" style={{ marginBottom: "1.5rem" }}>
      <h2>Asset-Filter (CPE)</h2>
      <div style={{ display: "flex", gap: "1rem", flexWrap: "wrap" }}>
        <div style={{ display: "flex", flexDirection: "column", minWidth: "250px" }}>
          <span className="meta-label" style={{ marginBottom: "0.35rem" }}>
            Vendors
          </span>
          <AsyncSelect
            isMulti
            cacheOptions
            defaultOptions={initialVendorOptions}
            loadOptions={loadVendorOptions}
            value={defaultVendorOptions}
            onChange={(options) => {
              const values = Array.isArray(options) ? options.map((option) => option.value) : [];
              setSelectedVendors(values);
            }}
            placeholder="Vendors auswählen..."
            styles={selectStyles}
          />
        </div>

        <div style={{ display: "flex", flexDirection: "column", minWidth: "250px" }}>
          <span className="meta-label" style={{ marginBottom: "0.35rem" }}>
            Produkte
          </span>
          <AsyncSelect
            isMulti
            cacheOptions
            defaultOptions={defaultProductOptions}
            loadOptions={loadProductOptions}
            isDisabled={selectedVendors.length === 0}
            value={defaultProductOptions}
            onChange={(options) => {
              const values = Array.isArray(options) ? options.map((option) => option.value) : [];
              setSelectedProducts(values);
            }}
            placeholder={
              selectedVendors.length === 0 ? "Erst Vendor wählen" : "Produkte auswählen..."
            }
            styles={selectStyles}
          />
        </div>
      </div>
    </section>
  );
};

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
