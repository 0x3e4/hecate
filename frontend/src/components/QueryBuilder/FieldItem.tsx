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

const toEnglishDescription = (description: string): string => {
  const replacements: Array<[RegExp, string]> = [
    [/z\.B\./g, "e.g."],
    [/Name der Quelle/g, "Source name"],
    [/Weitere Identifier \/ Aliasse/g, "Additional identifiers / aliases"],
    [/Schwachstellen Auftraggeber/g, "Vulnerability assigner"],
    [/Titel des Eintrags/g, "Entry title"],
    [/Beschreibungstext/g, "Description text"],
    [/CWE Klassifizierung/g, "CWE classification"],
    [/CPE Einträge/g, "CPE entries"],
    [/True\/False für aktive Exploitation \(KEV\)/g, "True/false for active exploitation (KEV)"],
    [/True\/False für abgelehnte Schwachstellen/g, "True/false for rejected vulnerabilities"],
    [/Basisscore/g, "Base score"],
    [/Vektor/g, "Vector"],
    [/Angriffsvektor/g, "Attack vector"],
    [/Angriffskomplexität/g, "Attack complexity"],
    [/Angriffsvoraussetzungen/g, "Attack requirements"],
    [/benötigte Privilegien/g, "Privileges required"],
    [/Benutzerinteraktion/g, "User interaction"],
    [/Vertraulichkeit/g, "Confidentiality"],
    [/Integrität/g, "Integrity"],
    [/Verfügbarkeit/g, "Availability"],
    [/Quelle/g, "Source"],
    [/Typ/g, "Type"],
    [/Betroffener Hersteller/g, "Affected vendor"],
    [/Betroffenes Produkt/g, "Affected product"],
    [/Betroffene Versionen/g, "Affected versions"],
    [/Betroffene Umgebungen/g, "Affected environments"],
    [/Verwundbar/g, "Vulnerable"],
    [/Liste der betroffenen Hersteller/g, "List of affected vendors"],
    [/Liste der Produkte/g, "List of products"],
    [/Produktversionen \(Text\)/g, "Product versions (text)"],
    [/Produktversions-IDs aus dem Katalog/g, "Product version IDs from the catalog"],
    [/Datum der Veröffentlichung/g, "Publication date"],
    [/Datum des Imports/g, "Ingestion date"],
  ];
  let translated = description;
  replacements.forEach(([pattern, value]) => {
    translated = translated.replace(pattern, value);
  });
  return translated;
};

export const FieldItem = ({ field, onClick, onExpand, isExpanded }: FieldItemProps) => {
  const { language, t } = useI18n();
  const typeColor = getTypeColor(field.type);
  const description = language === "de" ? field.description : toEnglishDescription(field.description);

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
