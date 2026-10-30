import { LuChevronDown, LuChevronRight } from "react-icons/lu";
import type { DQLFieldHint } from "../../constants/dqlFields";
import { useI18n } from "../../i18n/context";
import { IconButton } from "../../ui/primitives";

interface FieldItemProps {
  field: DQLFieldHint;
  onClick: () => void;
  onExpand: () => void;
  isExpanded: boolean;
}

export const FieldItem = ({ field, onClick, onExpand, isExpanded }: FieldItemProps) => {
  const { language, t } = useI18n();
  const description = language === "de" ? field.descriptionDe : field.description;
  const descriptionId = `query-builder-field-${field.field}`;

  return (
    <div className="query-builder-field">
      <button type="button" className="query-builder-field-insert" aria-describedby={descriptionId} onClick={onClick}>
        <code className="mono">{field.field}</code>
        <span className="query-builder-field-type">{field.type}</span>
      </button>
      <p id={descriptionId} className="query-builder-field-description">{description}</p>

      {field.aggregatable && (
        <IconButton
          className="query-builder-field-expand"
          label={t("Show values", "Werte anzeigen")}
          aria-expanded={isExpanded}
          onClick={(e) => {
            e.stopPropagation();
            onExpand();
          }}
        >
          {isExpanded ? <LuChevronDown size={16} aria-hidden="true" /> : <LuChevronRight size={16} aria-hidden="true" />}
        </IconButton>
      )}
    </div>
  );
};
