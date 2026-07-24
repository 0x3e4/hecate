import { LuChevronDown, LuChevronRight } from "react-icons/lu";
import type { DQLFieldHint } from "../../constants/dqlFields";
import { useI18n } from "../../i18n/context";

interface FieldItemProps {
  field: DQLFieldHint;
  onClick: () => void;
  onExpand: () => void;
  isExpanded: boolean;
}

const getTypeColor = (type: string): string => {
  switch (type) {
    case "string":
      return "#60a5fa"; // blue
    case "number":
      return "#34d399"; // green
    case "boolean":
      return "#f59e0b"; // orange
    case "date":
      return "#a78bfa"; // purple
    case "array":
      return "#ec4899"; // pink
    default:
      return "#9ca3af"; // gray
  }
};

export const FieldItem = ({ field, onClick, onExpand, isExpanded }: FieldItemProps) => {
  const { language, t } = useI18n();
  const typeColor = getTypeColor(field.type);
  const description = language === "de" ? field.descriptionDe : field.description;

  return (
    <div className="field-item">
      <div className="field-item-main">
        <div className="field-item-content" onClick={onClick}>
          <code className="field-name">{field.field}</code>
          <span className="field-type-badge" style={{ backgroundColor: typeColor }}>
            {field.type.toUpperCase()}
          </span>
          <p className="field-description">{description}</p>
        </div>

        {field.aggregatable && (
          <button
            className="field-expand-button"
            onClick={(e) => {
              e.stopPropagation();
              onExpand();
            }}
            type="button"
            title={t("Show values", "Werte anzeigen")}
          >
            {isExpanded ? <LuChevronDown /> : <LuChevronRight />}
          </button>
        )}
      </div>
    </div>
  );
};
