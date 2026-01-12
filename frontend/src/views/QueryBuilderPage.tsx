import { useState, useRef } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";
import { FieldBrowser } from "../components/QueryBuilder/FieldBrowser";
import { QueryEditor } from "../components/QueryBuilder/QueryEditor";
import { FieldAggregation } from "../components/QueryBuilder/FieldAggregation";
import { useSavedSearches } from "../hooks/useSavedSearches";
import { DQL_FIELD_HINTS } from "../constants/dqlFields";

export const QueryBuilderPage = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const initialQuery = searchParams.get("search") || "";

  const [currentQuery, setCurrentQuery] = useState(initialQuery);
  const [expandedFields, setExpandedFields] = useState<Set<string>>(new Set());
  const [showSaveDialog, setShowSaveDialog] = useState(false);
  const [saveName, setSaveName] = useState("");
  const [toast, setToast] = useState<{ message: string; type: "success" | "error" } | null>(null);

  const { createSearch } = useSavedSearches();
  const textareaRef = useRef<HTMLTextAreaElement>(null);

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
      await createSearch({
        name: saveName.trim(),
        queryParams: `mode=dql&search=${encodeURIComponent(currentQuery)}`,
        dqlQuery: currentQuery,
      });

      showToast("Suche gespeichert", "success");
      setShowSaveDialog(false);
      setSaveName("");
    } catch (error) {
      console.error("Failed to save query:", error);
      showToast("Speichern fehlgeschlagen", "error");
    }
  };

  const handleCopyURL = async () => {
    if (!currentQuery.trim()) return;

    const url = `${window.location.origin}/vulnerabilities?mode=dql&search=${encodeURIComponent(currentQuery)}`;

    try {
      await navigator.clipboard.writeText(url);
      showToast("URL in Zwischenablage kopiert", "success");
    } catch (error) {
      console.error("Failed to copy URL:", error);
      showToast("Kopieren fehlgeschlagen", "error");
    }
  };

  const handleExecute = () => {
    if (!currentQuery.trim()) return;

    navigate(`/vulnerabilities?mode=dql&search=${encodeURIComponent(currentQuery)}`);
  };

  const showToast = (message: string, type: "success" | "error") => {
    setToast({ message, type });
    setTimeout(() => setToast(null), 4000);
  };

  // Get the field hint for expanded fields to show aggregations
  const expandedFieldsWithAggregation = Array.from(expandedFields).filter((fieldName) => {
    const fieldHint = DQL_FIELD_HINTS.find((f) => f.field === fieldName);
    return fieldHint?.aggregatable;
  });

  return (
    <div className="page query-builder-page">
      <section className="card">
        <h2>Query Builder</h2>
        <p className="muted">
          Erstelle DQL-Abfragen mit einem intuitiven visuellen Interface. Klicke auf Felder, um sie
          zur Query hinzuzufügen.
        </p>

        <div className="query-builder-layout">
          <div className="query-builder-left">
            <FieldBrowser
              onFieldClick={handleFieldClick}
              onFieldExpand={handleFieldExpand}
              expandedFields={expandedFields}
            />
          </div>

          <div className="query-builder-right">
            <QueryEditor
              query={currentQuery}
              onQueryChange={setCurrentQuery}
              onInsertText={handleInsertText}
              onSave={() => setShowSaveDialog(true)}
              onCopyURL={handleCopyURL}
              onExecute={handleExecute}
            />

            {/* Show aggregations for expanded fields */}
            {expandedFieldsWithAggregation.length > 0 && (
              <div className="expanded-aggregations">
                <h4>Feldwerte</h4>
                {expandedFieldsWithAggregation.map((fieldName) => (
                  <div key={fieldName} className="aggregation-section">
                    <h5>
                      <code>{fieldName}</code>
                    </h5>
                    <FieldAggregation fieldName={fieldName} onValueClick={handleValueClick} />
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </section>

      {/* Save Dialog */}
      {showSaveDialog && (
        <div className="dialog-overlay" onClick={() => setShowSaveDialog(false)}>
          <div className="dialog" onClick={(e) => e.stopPropagation()}>
            <h3>Query speichern</h3>
            <p>Gebe einen Namen für die gespeicherte Query ein:</p>
            <input
              type="text"
              value={saveName}
              onChange={(e) => setSaveName(e.target.value)}
              placeholder="Query-Name..."
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
                Abbrechen
              </button>
              <button
                type="button"
                className="btn btn-primary"
                onClick={handleSave}
                disabled={!saveName.trim()}
              >
                Speichern
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Toast Notification */}
      {toast && (
        <div className={`toast toast-${toast.type}`}>
          {toast.message}
        </div>
      )}
    </div>
  );
};
