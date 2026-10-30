// Registries and placeholders that land in `vendorSlugs` without naming a maker.
const GENERIC_VENDORS = new Set([
  "cargo",
  "composer",
  "crates-io",
  "gem",
  "github",
  "go",
  "maven",
  "n-a",
  "npm",
  "nuget",
  "packagist",
  "pip",
  "pypi",
  "rubygems",
  "unknown",
]);

/**
 * The vendor a catalog product most likely belongs to. Plugin vendors pile up
 * on a product like WordPress, so the alphabetically first one is usually wrong:
 * the vendor sharing the product's name wins, then one its slug starts with.
 */
export const primaryVendorSlug = (productSlug: string, vendorSlugs: string[]): string | null => {
  const named = vendorSlugs.filter((vendor) => !GENERIC_VENDORS.has(vendor));
  return (
    named.find((vendor) => vendor === productSlug) ??
    named.find((vendor) => productSlug.startsWith(`${vendor}-`)) ??
    named[0] ??
    vendorSlugs[0] ??
    null
  );
};

/** Aliases worth showing: the catalog stores case variants of the name itself. */
export const distinctAliases = (label: string, aliases: string[]): string[] => {
  const seen = new Set([label.trim().toLowerCase()]);
  return aliases.filter((alias) => {
    const key = alias.trim().toLowerCase();
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
};
