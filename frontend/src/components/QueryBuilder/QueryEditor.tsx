import { useRef, useState } from "react";
import { LuCopy, LuSave, LuPlay } from "react-icons/lu";
import { useI18n } from "../../i18n/context";

interface QueryEditorProps {
  query: string;
  onQueryChange: (query: string) => void;
  onInsertText: (text: string, cursorPosition: number) => void;
  onSave: () => void;
  onCopyURL: () => void;
  onExecute: () => void;
}

export const QueryEditor = ({
  query,
  onQueryChange,
  onInsertText,
  onSave,
  onCopyURL,
  onExecute
}: QueryEditorProps) => {
  const { t } = useI18n();
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const handleInsertOperator = (operator: string) => {
    if (textareaRef.current) {
      const cursorPos = textareaRef.current.selectionStart;
      const textBefore = query.substring(0, cursorPos);
      const textAfter = query.substring(cursorPos);

      // Add spaces around operators if needed
      const needsSpaceBefore = textBefore.length > 0 && !textBefore.endsWith(" ");
      const needsSpaceAfter = textAfter.length > 0 && !textAfter.startsWith(" ");

      const textToInsert = `${needsSpaceBefore ? " " : ""}${operator}${needsSpaceAfter ? " " : ""}`;
      const newQuery = textBefore + textToInsert + textAfter;
      const newCursorPos = cursorPos + textToInsert.length;

      onQueryChange(newQuery);

      // Set cursor position after state update
      setTimeout(() => {
        if (textareaRef.current) {
          textareaRef.current.focus();
          textareaRef.current.setSelectionRange(newCursorPos, newCursorPos);
        }
      }, 0);
    }
  };

  const getCursorPosition = (): number => {
    return textareaRef.current?.selectionStart || query.length;
  };

  return (
    <div className="query-editor-panel">
      <div className="query-editor-header">
        <h3>DQL Query</h3>
        <span className="character-count">{query.length} {t("characters", "Zeichen")}</span>
      </div>

      <textarea
        ref={textareaRef}
        className="query-input"
        value={query}
        onChange={(e) => onQueryChange(e.target.value)}
        placeholder={t(
          "Enter DQL query or click fields from the left browser...",
          "DQL Query eingeben oder Felder aus dem Browser links klicken..."
        )}
        rows={10}
        spellCheck={false}
      />

      <div className="operator-buttons">
        <span className="operator-label">{t("Operators:", "Operatoren:")}</span>
        <button type="button" onClick={() => handleInsertOperator("AND")} title={t("AND operator", "AND Operator")}>
          AND
        </button>
        <button type="button" onClick={() => handleInsertOperator("OR")} title={t("OR operator", "OR Operator")}>
          OR
        </button>
        <button type="button" onClick={() => handleInsertOperator("NOT")} title={t("NOT operator", "NOT Operator")}>
          NOT
        </button>
        <button type="button" onClick={() => handleInsertOperator("*")} title={t("Wildcard", "Wildcard")}>
          *
        </button>
        <button type="button" onClick={() => handleInsertOperator("?")} title={t("Single character wildcard", "Einzelzeichen-Wildcard")}>
          ?
        </button>
      </div>

      <div className="query-actions">
        <button
          type="button"
          className="btn btn-secondary"
          onClick={onSave}
          disabled={!query.trim()}
          title={t("Save query", "Query speichern")}
        >
          <LuSave />
          <span>{t("Save", "Speichern")}</span>
        </button>

        <button
          type="button"
          className="btn btn-secondary"
          onClick={onCopyURL}
          disabled={!query.trim()}
          title={t("Copy URL", "URL kopieren")}
        >
          <LuCopy />
          <span>{t("Copy URL", "URL kopieren")}</span>
        </button>

        <button
          type="button"
          className="btn btn-primary"
          onClick={onExecute}
          disabled={!query.trim()}
          title={t("Execute query", "Query ausführen")}
        >
          <LuPlay />
          <span>{t("Execute query", "Query ausführen")}</span>
        </button>
      </div>

      <div className="query-help">
        <p>
          <strong>{t("Syntax examples:", "Syntax-Beispiele:")}</strong> <code>vuln_id:CVE-2024-*</code>,{" "}
          <code>cvss.severity:critical</code>,{" "}
          <code>vendors:microsoft AND exploited:true</code>
        </p>
        <p>
          {t("More information:", "Mehr Informationen:")}{" "}
          <a
            href="https://docs.opensearch.org/latest/dashboards/dql/"
            target="_blank"
            rel="noopener noreferrer"
          >
            <i>OpenSearch DQL Syntax</i>
          </a>
        </p>
      </div>
    </div>
  );
};

// Export cursor position getter for parent component
export const getTextareaCursorPosition = (textareaRef: React.RefObject<HTMLTextAreaElement>): number => {
  return textareaRef.current?.selectionStart || 0;
};
