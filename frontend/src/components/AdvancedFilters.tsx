import { useCallback, useEffect, useState, type ChangeEvent } from "react";
import { getFieldAggregation } from "../api/vulnerabilities";
import { useI18n } from "../i18n/context";

/* ── State shape ─────────────────────────────────────────────── */

export interface AdvancedFiltersState {
  // Moved from parent (formerly standalone checkboxes)
  includeRejected: boolean;
  includeReserved: boolean;
  exploitedOnly: boolean;
  aiAnalysedOnly: boolean;
  // Severity & sources
  severity: string[];
  sources: string[];
  // Scoring
  epssScoreMin: string;
  epssScoreMax: string;
  cvssVersion: string;
  cvssScoreMin: string;
  cvssScoreMax: string;
  // Identification
  cwes: string;
  assigner: string;
  // Date
  publishedFrom: string;
  publishedTo: string;
  // CVSS vector (v3.x / v4.0)
  attackVector: string[];
  attackComplexity: string[];
  attackRequirements: string[];
  privilegesRequired: string[];
  userInteraction: string[];
  scope: string[];
  confidentialityImpact: string[];
  integrityImpact: string[];
  availabilityImpact: string[];
}

export const EMPTY_ADVANCED_FILTERS: AdvancedFiltersState = {
  includeRejected: false,
  includeReserved: false,
  exploitedOnly: false,
  aiAnalysedOnly: false,
  severity: [],
  sources: [],
  epssScoreMin: "",
  epssScoreMax: "",
  cvssVersion: "",
  cvssScoreMin: "",
  cvssScoreMax: "",
  cwes: "",
  assigner: "",
  publishedFrom: "",
  publishedTo: "",
  attackVector: [],
  attackComplexity: [],
  attackRequirements: [],
  privilegesRequired: [],
  userInteraction: [],
  scope: [],
  confidentialityImpact: [],
  integrityImpact: [],
  availabilityImpact: [],
};

export const countActiveAdvancedFilters = (s: AdvancedFiltersState): number => {
  let n = 0;
  if (s.includeRejected) n++;
  if (s.includeReserved) n++;
  if (s.exploitedOnly) n++;
  if (s.aiAnalysedOnly) n++;
  if (s.severity.length) n++;
  if (s.sources.length) n++;
  if (s.epssScoreMin || s.epssScoreMax) n++;
  if (s.cvssVersion) n++;
  if (s.cvssScoreMin || s.cvssScoreMax) n++;
  if (s.cwes.trim()) n++;
  if (s.assigner.trim()) n++;
  if (s.publishedFrom || s.publishedTo) n++;
  if (s.attackVector.length) n++;
  if (s.attackComplexity.length) n++;
  if (s.attackRequirements.length) n++;
  if (s.privilegesRequired.length) n++;
  if (s.userInteraction.length) n++;
  if (s.scope.length) n++;
  if (s.confidentialityImpact.length) n++;
  if (s.integrityImpact.length) n++;
  if (s.availabilityImpact.length) n++;
  return n;
};

/* ── Constants ───────────────────────────────────────────────── */

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"] as const;

const SOURCES = [
  "NVD", "EUVD", "GHSA", "OSV", "CIRCL", "KEV",
] as const;

const CVSS_VERSIONS = ["4.0", "3.1", "3.0", "2.0"] as const;

const ATTACK_VECTORS = ["NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"] as const;
const ATTACK_COMPLEXITIES = ["LOW", "HIGH"] as const;
const ATTACK_REQUIREMENTS = ["NONE", "PRESENT"] as const;
const PRIVILEGES = ["NONE", "LOW", "HIGH"] as const;
const USER_INTERACTIONS_V3 = ["NONE", "REQUIRED"] as const;
const USER_INTERACTIONS_V4 = ["NONE", "PASSIVE", "ACTIVE"] as const;
const SCOPES = ["UNCHANGED", "CHANGED"] as const;
const IMPACTS = ["NONE", "LOW", "HIGH"] as const;

// v2.0 uses different labels
const ACCESS_VECTORS_V2 = ["NETWORK", "ADJACENT_NETWORK", "LOCAL"] as const;
const ACCESS_COMPLEXITIES_V2 = ["LOW", "MEDIUM", "HIGH"] as const;
const AUTHENTICATIONS_V2 = ["NONE", "SINGLE", "MULTIPLE"] as const;
const IMPACTS_V2 = ["NONE", "PARTIAL", "COMPLETE"] as const;

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "rgba(252, 92, 101, 0.85)",
  HIGH: "rgba(255, 165, 0, 0.85)",
  MEDIUM: "rgba(255, 212, 59, 0.85)",
  LOW: "rgba(92, 184, 92, 0.85)",
  NONE: "rgba(160, 170, 190, 0.6)",
};

/* ── Component ───────────────────────────────────────────────── */

interface Props {
  value: AdvancedFiltersState;
  onChange: (next: AdvancedFiltersState) => void;
}

export const AdvancedFilters = ({ value, onChange }: Props) => {
  const { t } = useI18n();
  const [assignerSuggestions, setAssignerSuggestions] = useState<string[]>([]);

  useEffect(() => {
    let cancelled = false;
    getFieldAggregation("assigner", 50)
      .then((data) => {
        if (!cancelled) setAssignerSuggestions(data.buckets.map((b) => b.value));
      })
      .catch(() => {});
    return () => { cancelled = true; };
  }, []);

  const update = useCallback(
    (patch: Partial<AdvancedFiltersState>) => onChange({ ...value, ...patch }),
    [value, onChange],
  );

  const toggleChip = useCallback(
    (field: keyof AdvancedFiltersState, chip: string) => {
      const arr = value[field] as string[];
      const next = arr.includes(chip) ? arr.filter((v: string) => v !== chip) : [...arr, chip];
      update({ [field]: next });
    },
    [value, update],
  );

  const handleInput = useCallback(
    (field: keyof AdvancedFiltersState) => (e: ChangeEvent<HTMLInputElement>) => {
      update({ [field]: e.target.value });
    },
    [update],
  );

  const isV4 = value.cvssVersion === "4.0";
  const isV2 = value.cvssVersion === "2.0";

  const attackVectorOptions = isV2 ? ACCESS_VECTORS_V2 : ATTACK_VECTORS;
  const attackComplexityOptions = isV2 ? ACCESS_COMPLEXITIES_V2 : ATTACK_COMPLEXITIES;
  const privilegesOptions = isV2 ? AUTHENTICATIONS_V2 : PRIVILEGES;
  const userInteractions = isV4 ? USER_INTERACTIONS_V4 : USER_INTERACTIONS_V3;
  const impactOptions = isV2 ? IMPACTS_V2 : IMPACTS;

  return (
    <div className="advanced-filters-panel">
      {/* ── Toggle checkboxes (moved from parent) ─────── */}
      <div className="advanced-filter-toggles">
        <label className="advanced-filter-toggle-label">
          <input
            type="checkbox"
            checked={value.includeRejected}
            onChange={(e) => update({ includeRejected: e.target.checked })}
          />
          {t("Show rejected CVEs", "Abgelehnte CVEs")}
        </label>
        <label className="advanced-filter-toggle-label">
          <input
            type="checkbox"
            checked={value.includeReserved}
            onChange={(e) => update({ includeReserved: e.target.checked })}
          />
          {t("Show reserved CVEs", "Reservierte CVEs")}
        </label>
        <label className="advanced-filter-toggle-label">
          <input
            type="checkbox"
            checked={value.exploitedOnly}
            onChange={(e) => update({ exploitedOnly: e.target.checked })}
          />
          {t("Exploited CVEs only", "Nur exploited CVEs")}
        </label>
        <label className="advanced-filter-toggle-label">
          <input
            type="checkbox"
            checked={value.aiAnalysedOnly}
            onChange={(e) => update({ aiAnalysedOnly: e.target.checked })}
          />
          {t("AI-analysed CVEs only", "Nur AI-analysierte CVEs")}
        </label>
      </div>

      <div className="advanced-filters-grid">
        {/* ── Row 1: Severity, Sources, Published ──────── */}
        <FilterGroup label={t("Severity", "Schweregrad")}>
          <div className="advanced-filter-chips">
            {SEVERITIES.map((s) => (
              <button
                key={s}
                type="button"
                className={`advanced-filter-chip severity-chip ${value.severity.includes(s) ? "active" : ""}`}
                style={
                  value.severity.includes(s)
                    ? { background: SEVERITY_COLORS[s], borderColor: SEVERITY_COLORS[s], color: s === "MEDIUM" ? "#1a1a2e" : "#fff" }
                    : undefined
                }
                onClick={() => toggleChip("severity", s)}
              >
                {s}
              </button>
            ))}
          </div>
        </FilterGroup>

        <FilterGroup label={t("Sources", "Quellen")}>
          <div className="advanced-filter-chips">
            {SOURCES.map((s) => (
              <button
                key={s}
                type="button"
                className={`advanced-filter-chip ${value.sources.includes(s) ? "active" : ""}`}
                onClick={() => toggleChip("sources", s)}
              >
                {s}
              </button>
            ))}
          </div>
        </FilterGroup>

        <FilterGroup label={t("Published", "Veröffentlicht")}>
          <div className="advanced-filter-range">
            <input
              type="date"
              className="advanced-filter-input"
              value={value.publishedFrom}
              onChange={handleInput("publishedFrom")}
            />
            <span className="advanced-filter-range-sep">–</span>
            <input
              type="date"
              className="advanced-filter-input"
              value={value.publishedTo}
              onChange={handleInput("publishedTo")}
            />
          </div>
        </FilterGroup>

        {/* ── Row 2: EPSS, CVSS Version, CVSS Score ───── */}
        <FilterGroup label={t("EPSS Score", "EPSS-Score")}>
          <div className="advanced-filter-range">
            <input
              type="number"
              className="advanced-filter-input"
              value={value.epssScoreMin}
              onChange={handleInput("epssScoreMin")}
              placeholder="0.0"
              min={0}
              max={100}
              step={0.1}
            />
            <span className="advanced-filter-range-sep">–</span>
            <input
              type="number"
              className="advanced-filter-input"
              value={value.epssScoreMax}
              onChange={handleInput("epssScoreMax")}
              placeholder="100.0"
              min={0}
              max={100}
              step={0.1}
            />
          </div>
        </FilterGroup>

        <FilterGroup label={t("CVSS Version", "CVSS-Version")}>
          <select
            className="advanced-filter-input"
            value={value.cvssVersion}
            onChange={(e) => update({ cvssVersion: e.target.value })}
          >
            <option value="">{t("Any", "Alle")}</option>
            {CVSS_VERSIONS.map((v) => (
              <option key={v} value={v}>CVSS {v}</option>
            ))}
          </select>
        </FilterGroup>

        <FilterGroup label={t("CVSS Score", "CVSS-Score")}>
          <div className="advanced-filter-range">
            <input
              type="number"
              className="advanced-filter-input"
              value={value.cvssScoreMin}
              onChange={handleInput("cvssScoreMin")}
              placeholder="0.0"
              min={0}
              max={10}
              step={0.1}
            />
            <span className="advanced-filter-range-sep">–</span>
            <input
              type="number"
              className="advanced-filter-input"
              value={value.cvssScoreMax}
              onChange={handleInput("cvssScoreMax")}
              placeholder="10.0"
              min={0}
              max={10}
              step={0.1}
            />
          </div>
        </FilterGroup>

        {/* ── Row 3: CWE, Assigner ─────────────────────── */}
        <FilterGroup label="CWE">
          <input
            type="text"
            className="advanced-filter-input"
            value={value.cwes}
            onChange={handleInput("cwes")}
            placeholder={t("e.g. 79, 89 or CWE-79", "z.B. 79, 89 oder CWE-79")}
          />
        </FilterGroup>

        <FilterGroup label="Assigner">
          <input
            type="text"
            className="advanced-filter-input"
            value={value.assigner}
            onChange={handleInput("assigner")}
            placeholder={t("e.g. security@apache.org", "z.B. security@apache.org")}
            list="assigner-suggestions"
          />
          <datalist id="assigner-suggestions">
            {assignerSuggestions.map((s) => (
              <option key={s} value={s} />
            ))}
          </datalist>
        </FilterGroup>

        <div className="advanced-filter-spacer" />
      </div>

      {/* ── CVSS Vector section ─────────────────────────── */}
      <details className="advanced-filter-cvss-details">
        <summary className="advanced-filter-cvss-summary">
          {t("CVSS Vector Components", "CVSS-Vektor-Komponenten")}
          {isV2 && <span className="advanced-filter-version-hint"> (CVSS 2.0)</span>}
          {isV4 && <span className="advanced-filter-version-hint"> (CVSS 4.0)</span>}
        </summary>
        <div className="advanced-filters-grid" style={{ marginTop: "0.75rem" }}>
          <FilterGroup label={isV2 ? t("Access Vector", "Zugriffsvektor") : t("Attack Vector", "Angriffsvektor")}>
            <div className="advanced-filter-chips">
              {attackVectorOptions.map((v) => (
                <button
                  key={v}
                  type="button"
                  className={`advanced-filter-chip ${value.attackVector.includes(v) ? "active" : ""}`}
                  onClick={() => toggleChip("attackVector", v)}
                >
                  {v}
                </button>
              ))}
            </div>
          </FilterGroup>

          <FilterGroup label={isV2 ? t("Access Complexity", "Zugriffskomplexität") : t("Attack Complexity", "Angriffskomplexität")}>
            <div className="advanced-filter-chips">
              {attackComplexityOptions.map((v) => (
                <button
                  key={v}
                  type="button"
                  className={`advanced-filter-chip ${value.attackComplexity.includes(v) ? "active" : ""}`}
                  onClick={() => toggleChip("attackComplexity", v)}
                >
                  {v}
                </button>
              ))}
            </div>
          </FilterGroup>

          <FilterGroup label={isV2 ? t("Authentication", "Authentifizierung") : t("Privileges Required", "Erforderliche Berechtigungen")}>
            <div className="advanced-filter-chips">
              {privilegesOptions.map((v) => (
                <button
                  key={v}
                  type="button"
                  className={`advanced-filter-chip ${value.privilegesRequired.includes(v) ? "active" : ""}`}
                  onClick={() => toggleChip("privilegesRequired", v)}
                >
                  {v}
                </button>
              ))}
            </div>
          </FilterGroup>

          {isV4 && (
            <FilterGroup label={t("Attack Requirements", "Angriffsanforderungen")}>
              <div className="advanced-filter-chips">
                {ATTACK_REQUIREMENTS.map((v) => (
                  <button
                    key={v}
                    type="button"
                    className={`advanced-filter-chip ${value.attackRequirements.includes(v) ? "active" : ""}`}
                    onClick={() => toggleChip("attackRequirements", v)}
                  >
                    {v}
                  </button>
                ))}
              </div>
            </FilterGroup>
          )}

          {!isV2 && (
            <FilterGroup label={t("User Interaction", "Benutzerinteraktion")}>
              <div className="advanced-filter-chips">
                {userInteractions.map((v) => (
                  <button
                    key={v}
                    type="button"
                    className={`advanced-filter-chip ${value.userInteraction.includes(v) ? "active" : ""}`}
                    onClick={() => toggleChip("userInteraction", v)}
                  >
                    {v}
                  </button>
                ))}
              </div>
            </FilterGroup>
          )}

          {!isV4 && !isV2 && (
            <FilterGroup label={t("Scope", "Geltungsbereich")}>
              <div className="advanced-filter-chips">
                {SCOPES.map((v) => (
                  <button
                    key={v}
                    type="button"
                    className={`advanced-filter-chip ${value.scope.includes(v) ? "active" : ""}`}
                    onClick={() => toggleChip("scope", v)}
                  >
                    {v}
                  </button>
                ))}
              </div>
            </FilterGroup>
          )}

          <FilterGroup label={t("Confidentiality", "Vertraulichkeit")}>
            <div className="advanced-filter-chips">
              {impactOptions.map((v) => (
                <button
                  key={v}
                  type="button"
                  className={`advanced-filter-chip ${value.confidentialityImpact.includes(v) ? "active" : ""}`}
                  onClick={() => toggleChip("confidentialityImpact", v)}
                >
                  {v}
                </button>
              ))}
            </div>
          </FilterGroup>

          <FilterGroup label={t("Integrity", "Integrität")}>
            <div className="advanced-filter-chips">
              {impactOptions.map((v) => (
                <button
                  key={v}
                  type="button"
                  className={`advanced-filter-chip ${value.integrityImpact.includes(v) ? "active" : ""}`}
                  onClick={() => toggleChip("integrityImpact", v)}
                >
                  {v}
                </button>
              ))}
            </div>
          </FilterGroup>

          <FilterGroup label={t("Availability", "Verfügbarkeit")}>
            <div className="advanced-filter-chips">
              {impactOptions.map((v) => (
                <button
                  key={v}
                  type="button"
                  className={`advanced-filter-chip ${value.availabilityImpact.includes(v) ? "active" : ""}`}
                  onClick={() => toggleChip("availabilityImpact", v)}
                >
                  {v}
                </button>
              ))}
            </div>
          </FilterGroup>
        </div>
      </details>

      <div className="advanced-filters-footer">
        <button
          type="button"
          className="advanced-filters-clear"
          onClick={() => onChange({ ...EMPTY_ADVANCED_FILTERS })}
        >
          {t("Clear all filters", "Alle Filter zurücksetzen")}
        </button>
      </div>
    </div>
  );
};

/* ── Helpers ─────────────────────────────────────────────────── */

const FilterGroup = ({ label, children }: { label: string; children: React.ReactNode }) => (
  <div className="advanced-filter-group">
    <label className="advanced-filter-label">{label}</label>
    {children}
  </div>
);
