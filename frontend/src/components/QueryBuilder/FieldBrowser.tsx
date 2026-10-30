import { useState, useMemo } from "react";
import { LuChevronDown, LuChevronRight, LuSearch } from "react-icons/lu";
import { DQL_FIELD_HINTS, FIELD_CATEGORIES } from "../../constants/dqlFields";
import { useI18n } from "../../i18n/context";
import { EmptyState } from "../../ui/primitives";
import { FieldItem } from "./FieldItem";

interface FieldBrowserProps {
  onFieldClick: (fieldName: string) => void;
  onFieldExpand: (fieldName: string) => void;
  expandedFields: Set<string>;
}

export const FieldBrowser = ({ onFieldClick, onFieldExpand, expandedFields }: FieldBrowserProps) => {
  const { language, t } = useI18n();
  const [searchTerm, setSearchTerm] = useState("");
  const [expandedCategories, setExpandedCategories] = useState<Set<string>>(
    new Set(FIELD_CATEGORIES.map(c => c.name))
  );

  // Filter fields based on search term
  const filteredFields = useMemo(() => {
    if (!searchTerm.trim()) {
      return DQL_FIELD_HINTS;
    }
    const term = searchTerm.toLowerCase();
    // Search both descriptions so a term typed in either language still matches.
    return DQL_FIELD_HINTS.filter(
      field =>
        field.field.toLowerCase().includes(term) ||
        field.description.toLowerCase().includes(term) ||
        field.descriptionDe.toLowerCase().includes(term)
    );
  }, [searchTerm]);

  // Group filtered fields by category
  const categorizedFields = useMemo(() => {
    const result = FIELD_CATEGORIES.map(category => {
      const categoryFieldNames = new Set(category.fields);
      const fields = filteredFields.filter(field => categoryFieldNames.has(field.field));
      return { ...category, fields };
    }).filter(category => category.fields.length > 0);

    return result;
  }, [filteredFields]);

  const toggleCategory = (categoryName: string) => {
    setExpandedCategories(prev => {
      const next = new Set(prev);
      if (next.has(categoryName)) {
        next.delete(categoryName);
      } else {
        next.add(categoryName);
      }
      return next;
    });
  };

  return (
    <div className="query-builder-fields">
      <div className="query-builder-fields-head">
        <h2>{t("Available fields", "Verfügbare Felder")}</h2>
        <div className="query-builder-fields-search">
          <LuSearch size={16} aria-hidden="true" />
          <input
            type="text"
            aria-label={t("Search fields...", "Felder durchsuchen...")}
            placeholder={t("Search fields...", "Felder durchsuchen...")}
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>
      </div>

      <div className="query-builder-fields-list">
        {categorizedFields.map(category => {
          const isExpanded = expandedCategories.has(category.name);
          return (
            <div key={category.name} className="query-builder-category">
              <h3>
                <button
                  className="query-builder-category-toggle"
                  onClick={() => toggleCategory(category.name)}
                  type="button"
                  aria-expanded={isExpanded}
                >
                  {isExpanded ? <LuChevronDown size={16} aria-hidden="true" /> : <LuChevronRight size={16} aria-hidden="true" />}
                  <span className="query-builder-category-name">
                    {language === "de" ? category.nameDe : category.name}
                  </span>
                  <span className="query-builder-category-count">{category.fields.length}</span>
                </button>
              </h3>

              {isExpanded && (
                <div>
                  {category.fields.map(field => (
                    <FieldItem
                      key={field.field}
                      field={field}
                      onClick={() => onFieldClick(field.field)}
                      onExpand={() => onFieldExpand(field.field)}
                      isExpanded={expandedFields.has(field.field)}
                    />
                  ))}
                </div>
              )}
            </div>
          );
        })}

        {categorizedFields.length === 0 && (
          <EmptyState title={t(`No fields found for "${searchTerm}"`, `Keine Felder gefunden für "${searchTerm}"`)} />
        )}
      </div>
    </div>
  );
};
