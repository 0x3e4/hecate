import { useState, useMemo } from "react";
import { LuChevronDown, LuChevronRight, LuSearch } from "react-icons/lu";
import { DQL_FIELD_HINTS, FIELD_CATEGORIES } from "../../constants/dqlFields";
import { FieldItem } from "./FieldItem";

interface FieldBrowserProps {
  onFieldClick: (fieldName: string) => void;
  onFieldExpand: (fieldName: string) => void;
  expandedFields: Set<string>;
}

export const FieldBrowser = ({ onFieldClick, onFieldExpand, expandedFields }: FieldBrowserProps) => {
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
    return DQL_FIELD_HINTS.filter(
      field =>
        field.field.toLowerCase().includes(term) ||
        field.description.toLowerCase().includes(term)
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
    <div className="field-browser">
      <div className="field-browser-header">
        <h3>Verfügbare Felder</h3>
        <div className="field-browser-search">
          <LuSearch className="search-icon" />
          <input
            type="text"
            placeholder="Felder durchsuchen..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="search-input"
          />
        </div>
      </div>

      <div className="field-categories">
        {categorizedFields.map(category => {
          const isExpanded = expandedCategories.has(category.name);
          return (
            <div key={category.name} className="field-category">
              <button
                className="field-category-header"
                onClick={() => toggleCategory(category.name)}
                type="button"
              >
                {isExpanded ? <LuChevronDown /> : <LuChevronRight />}
                <span className="category-name">{category.name}</span>
                <span className="category-count">({category.fields.length})</span>
              </button>

              {isExpanded && (
                <div className="field-list">
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
          <div className="no-results">
            Keine Felder gefunden für "{searchTerm}"
          </div>
        )}
      </div>
    </div>
  );
};
