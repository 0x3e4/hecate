import { useState, useRef, useEffect } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";
import "../screens/query-builder.css";
import { FieldBrowser } from "../components/QueryBuilder/FieldBrowser";
import { QueryEditor } from "../components/QueryBuilder/QueryEditor";
import { FieldAggregation } from "../components/QueryBuilder/FieldAggregation";
import { useSavedSearches } from "../hooks/useSavedSearches";
import { useI18n } from "../i18n/context";
import { Toast, useToast } from "../components/Toast";
import { DQL_FIELD_HINTS } from "../constants/dqlFields";
import { EmptyState, PageHeader } from "../ui/primitives";

export const QueryBuilderPage = () => {
  const { t } = useI18n();
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const initialQuery = searchParams.get("search") || "";

  const [currentQuery, setCurrentQuery] = useState(initialQuery);
  const [expandedFields, setExpandedFields] = useState<Set<string>>(new Set());
  const [showSaveDialog, setShowSaveDialog] = useState(false);
  const [saveName, setSaveName] = useState("");
  const { toast, showToast, dismiss } = useToast();

  const { createSavedSearch } = useSavedSearches();
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    document.title = t("Hecate Cyber Defense - Query Builder", "Hecate Cyber Defense - Query Builder");

    return () => {
      document.title = "Hecate Cyber Defense";
    };
  }, [t]);

  // Insert text at cursor position in the query
  const handleInsertText = (text: string) => {
    const textarea = document.querySelector(".query-input") as HTMLTextAreaElement;
    if (!textarea) {
      // Fallback: append to end
      setCurrentQuery((prev) => prev + text);
      return;
    }

    const cursorPos = textarea.selectionStart;
    const textBefore = currentQuery.substring(0, cursorPos);
    const textAfter = currentQuery.substring(cursorPos);

    const newQuery = textBefore + text + textAfter;
    const newCursorPos = cursorPos + text.length;

    setCurrentQuery(newQuery);

    // Set cursor position after state update
    setTimeout(() => {
      textarea.focus();
      textarea.setSelectionRange(newCursorPos, newCursorPos);
    }, 0);
  };

  const handleFieldClick = (fieldName: string) => {
    handleInsertText(`${fieldName}:`);
  };

  const handleFieldExpand = (fieldName: string) => {
    setExpandedFields((prev) => {
      const next = new Set(prev);
      if (next.has(fieldName)) {
        next.delete(fieldName);
      } else {
        next.add(fieldName);
      }
      return next;
    });
  };

  const handleValueClick = (fieldName: string, value: string) => {
    // Check if value needs quotes (contains spaces or special characters)
    const needsQuotes = /[\s:]/.test(value);
    const formattedValue = needsQuotes ? `"${value}"` : value;
    handleInsertText(`${fieldName}:${formattedValue}`);
  };

  const handleSave = async () => {
    if (!currentQuery.trim()) return;

    if (!saveName.trim()) {
      setShowSaveDialog(true);
      return;
    }

    try {
      await createSavedSearch({
        name: saveName.trim(),
        queryParams: `mode=dql&search=${encodeURIComponent(currentQuery)}`,
        dqlQuery: currentQuery,
      });

      showToast(t("Search saved", "Suche gespeichert"), "success");
      setShowSaveDialog(false);
      setSaveName("");
    } catch (error) {
      console.error("Failed to save query:", error);
      showToast(t("Saving failed", "Speichern fehlgeschlagen"), "error");
    }
  };

  const handleCopyURL = async () => {
    if (!currentQuery.trim()) return;

    const url = `${window.location.origin}/vulnerabilities?mode=dql&search=${encodeURIComponent(currentQuery)}`;

    try {
      await navigator.clipboard.writeText(url);
      showToast(t("URL copied to clipboard", "URL in Zwischenablage kopiert"), "success");
    } catch (error) {
      console.error("Failed to copy URL:", error);
      showToast(t("Copy failed", "Kopieren fehlgeschlagen"), "error");
    }
  };

  const handleExecute = () => {
    if (!currentQuery.trim()) return;

    navigate(`/vulnerabilities?mode=dql&search=${encodeURIComponent(currentQuery)}`);
  };


  // Get the field hint for expanded fields to show aggregations
  const expandedFieldsWithAggregation = Array.from(expandedFields).filter((fieldName) => {
    const fieldHint = DQL_FIELD_HINTS.find((f) => f.field === fieldName);
    return fieldHint?.aggregatable;
  });

  return (
    <div className="page query-builder">
      <PageHeader
        title={t("Query builder", "Query Builder")}
        description={t(
          "Create DQL queries with an intuitive visual interface. Click fields to add them to the query.",
          "Erstelle DQL-Abfragen mit einem intuitiven visuellen Interface. Klicke auf Felder, um sie zur Query hinzuzufügen."
        )}
      />

      <div className="query-builder-panes">
        <section className="query-builder-pane query-builder-pane--fields">
          <FieldBrowser
            onFieldClick={handleFieldClick}
            onFieldExpand={handleFieldExpand}
            expandedFields={expandedFields}
          />
        </section>

        <section className="query-builder-pane query-builder-pane--editor">
          <QueryEditor
            query={currentQuery}
            onQueryChange={setCurrentQuery}
            onInsertText={handleInsertText}
            onSave={() => setShowSaveDialog(true)}
            onCopyURL={handleCopyURL}
            onExecute={handleExecute}
          />
        </section>

        {/* Aggregations for expanded fields */}
        <section className="query-builder-pane query-builder-pane--values">
          <h2>{t("Field values", "Feldwerte")}</h2>
          {expandedFieldsWithAggregation.length > 0 ? (
            expandedFieldsWithAggregation.map((fieldName) => (
              <div key={fieldName} className="query-builder-values">
                <h3>
                  <code className="mono">{fieldName}</code>
                </h3>
                <FieldAggregation fieldName={fieldName} onValueClick={handleValueClick} />
              </div>
            ))
          ) : (
            <EmptyState title={t("No field open", "Kein Feld geöffnet")}>
              {t(
                "Open a field to see its most common values, then click one to add it to the query.",
                "Öffne ein Feld, um seine häufigsten Werte zu sehen, und klicke einen an, um ihn zur Query hinzuzufügen."
              )}
            </EmptyState>
          )}
        </section>
      </div>

      {/* Save Dialog */}
      {showSaveDialog && (
        <div className="dialog-overlay query-builder-overlay" onClick={() => setShowSaveDialog(false)}>
          <div
            className="dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="query-builder-save-title"
            onClick={(e) => e.stopPropagation()}
          >
            <h2 id="query-builder-save-title" className="query-builder-dialog-title">
              {t("Save query", "Query speichern")}
            </h2>
            <p>{t("Enter a name for the saved query:", "Gebe einen Namen für die gespeicherte Query ein:")}</p>
            <input
              type="text"
              value={saveName}
              onChange={(e) => setSaveName(e.target.value)}
              aria-label={t("Query name...", "Query-Name...")}
              placeholder={t("Query name...", "Query-Name...")}
              maxLength={200}
              autoFocus
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  handleSave();
                } else if (e.key === "Escape") {
                  setShowSaveDialog(false);
                }
              }}
            />
            <div className="dialog-actions">
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => setShowSaveDialog(false)}
              >
                {t("Cancel", "Abbrechen")}
              </button>
              <button
                type="button"
                className="btn btn-primary"
                onClick={handleSave}
                disabled={!saveName.trim()}
              >
                {t("Save", "Speichern")}
              </button>
            </div>
          </div>
        </div>
      )}

      <Toast toast={toast} onDismiss={dismiss} />
    </div>
  );
};
