import { useI18n } from "../i18n/context";
import { distinctAliases } from "../utils/catalog";

export interface CatalogOptionData {
  label: string;
  aliases: string[];
  vulnerabilityCount?: number | null;
  hint?: string | null;
}

/** A vendor or product in a picker, with what tells look-alikes apart. */
const CatalogOption = ({ label, aliases, vulnerabilityCount, hint }: CatalogOptionData) => {
  const { locale } = useI18n();
  const extra = distinctAliases(label, aliases).slice(0, 2).join(", ");
  return (
    <span className="catalog-option">
      <span className="catalog-option-name">
        <span>{label}</span>
        {hint ? <small>{hint}</small> : null}
        {extra ? <small>{extra}</small> : null}
      </span>
      {vulnerabilityCount != null ? (
        <small className="catalog-option-count">{vulnerabilityCount.toLocaleString(locale)} CVEs</small>
      ) : null}
    </span>
  );
};

/** For react-select's `formatOptionLabel`: the detail belongs in the menu, the field stays a name. */
export const renderCatalogOption = (
  option: CatalogOptionData,
  { context }: { context: "menu" | "value" },
) => (context === "value" ? option.label : <CatalogOption {...option} />);
