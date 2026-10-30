import { useCallback, useEffect, useState, type ChangeEvent, type ReactNode } from "react";
import { LuChevronRight } from "react-icons/lu";
import { getFieldAggregation } from "../api/vulnerabilities";
import { useI18n } from "../i18n/context";
import { severityLevel } from "../ui/primitives";

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

/** The API takes the enum value; the chip reads it in sentence case. */
const chipLabel = (value: string): string => {
  const words = value.toLowerCase().replace(/_/g, " ");
  return `${words.charAt(0).toUpperCase()}${words.slice(1)}`;
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
    <div className="vulnerability-list-filter-panel">
      {/* ── Toggle checkboxes (moved from parent) ─────── */}
      <div className="vulnerability-list-filter-toggles">
        <label className="vulnerability-list-filter-toggle">
          <input
            type="checkbox"
            checked={value.includeRejected}
            onChange={(e) => update({ includeRejected: e.target.checked })}
          />
          {t("Show rejected CVEs", "Abgelehnte CVEs")}
        </label>
        <label className="vulnerability-list-filter-toggle">
          <input
            type="checkbox"
            checked={value.includeReserved}
            onChange={(e) => update({ includeReserved: e.target.checked })}
          />
          {t("Show reserved CVEs", "Reservierte CVEs")}
        </label>
        <label className="vulnerability-list-filter-toggle">
          <input
            type="checkbox"
            checked={value.exploitedOnly}
            onChange={(e) => update({ exploitedOnly: e.target.checked })}
          />
          {t("Exploited CVEs only", "Nur exploited CVEs")}
        </label>
        <label className="vulnerability-list-filter-toggle">
          <input
            type="checkbox"
            checked={value.aiAnalysedOnly}
            onChange={(e) => update({ aiAnalysedOnly: e.target.checked })}
          />
          {t("AI-analysed CVEs only", "Nur AI-analysierte CVEs")}
        </label>
      </div>

      <div className="vulnerability-list-filter-grid">
        {/* ── Row 1: Severity, Sources, Published ──────── */}
        <FilterGroup label={t("Severity", "Schweregrad")}>
          <div className="vulnerability-list-filter-chips">
            {SEVERITIES.map((s) => {
              const active = value.severity.includes(s);
              return (
                <button
                  key={s}
                  type="button"
                  className={`vulnerability-list-filter-chip${active ? ` sev-${severityLevel(s)}` : ""}`}
                  aria-pressed={active}
                  onClick={() => toggleChip("severity", s)}
                >
                  {chipLabel(s)}
                </button>
              );
            })}
          </div>
        </FilterGroup>

        <FilterGroup label={t("Sources", "Quellen")}>
          <div className="vulnerability-list-filter-chips">
            {SOURCES.map((s) => (
              <button
                key={s}
                type="button"
                className="vulnerability-list-filter-chip"
                aria-pressed={value.sources.includes(s)}
                onClick={() => toggleChip("sources", s)}
              >
                {s}
              </button>
            ))}
          </div>
        </FilterGroup>

        <FilterGroup label={t("Published", "Veröffentlicht")}>
          <div className="vulnerability-list-filter-range">
            <input
              type="date"
              className="vulnerability-list-filter-input"
              value={value.publishedFrom}
              onChange={handleInput("publishedFrom")}
            />
            <span className="vulnerability-list-filter-range-separator">{t("to", "bis")}</span>
            <input
              type="date"
              className="vulnerability-list-filter-input"
              value={value.publishedTo}
              onChange={handleInput("publishedTo")}
            />
          </div>
        </FilterGroup>

        {/* ── Row 2: EPSS, CVSS Version, CVSS Score ───── */}
        <FilterGroup label={t("EPSS Score", "EPSS-Score")}>
          <div className="vulnerability-list-filter-range">
            <input
              type="number"
              className="vulnerability-list-filter-input"
              value={value.epssScoreMin}
              onChange={handleInput("epssScoreMin")}
              placeholder="0.0"
              min={0}
              max={100}
              step={0.1}
            />
            <span className="vulnerability-list-filter-range-separator">{t("to", "bis")}</span>
            <input
              type="number"
              className="vulnerability-list-filter-input"
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
            className="vulnerability-list-filter-input"
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
          <div className="vulnerability-list-filter-range">
            <input
              type="number"
              className="vulnerability-list-filter-input"
              value={value.cvssScoreMin}
              onChange={handleInput("cvssScoreMin")}
              placeholder="0.0"
              min={0}
              max={10}
              step={0.1}
            />
            <span className="vulnerability-list-filter-range-separator">{t("to", "bis")}</span>
            <input
              type="number"
              className="vulnerability-list-filter-input"
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
            className="vulnerability-list-filter-input"
            value={value.cwes}
            onChange={handleInput("cwes")}
            placeholder={t("e.g. 79, 89 or CWE-79", "z.B. 79, 89 oder CWE-79")}
          />
        </FilterGroup>

        <FilterGroup label="Assigner">
          <input
            type="text"
            className="vulnerability-list-filter-input"
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
      </div>

      {/* ── CVSS Vector section ─────────────────────────── */}
      <details className="vulnerability-list-filter-details">
        <summary className="vulnerability-list-filter-summary">
          <LuChevronRight size={14} className="vulnerability-list-filter-summary-icon" aria-hidden="true" />
          {t("CVSS Vector Components", "CVSS-Vektor-Komponenten")}
          {isV2 && <span className="vulnerability-list-filter-version-hint"> (CVSS 2.0)</span>}
          {isV4 && <span className="vulnerability-list-filter-version-hint"> (CVSS 4.0)</span>}
        </summary>
        <div className="vulnerability-list-filter-grid">
          <FilterGroup label={isV2 ? t("Access Vector", "Zugriffsvektor") : t("Attack Vector", "Angriffsvektor")}>
            <ChipGroup options={attackVectorOptions} selected={value.attackVector} onToggle={(v) => toggleChip("attackVector", v)} />
          </FilterGroup>

          <FilterGroup label={isV2 ? t("Access Complexity", "Zugriffskomplexität") : t("Attack Complexity", "Angriffskomplexität")}>
            <ChipGroup options={attackComplexityOptions} selected={value.attackComplexity} onToggle={(v) => toggleChip("attackComplexity", v)} />
          </FilterGroup>

          <FilterGroup label={isV2 ? t("Authentication", "Authentifizierung") : t("Privileges Required", "Erforderliche Berechtigungen")}>
            <ChipGroup options={privilegesOptions} selected={value.privilegesRequired} onToggle={(v) => toggleChip("privilegesRequired", v)} />
          </FilterGroup>

          {isV4 && (
            <FilterGroup label={t("Attack Requirements", "Angriffsanforderungen")}>
              <ChipGroup options={ATTACK_REQUIREMENTS} selected={value.attackRequirements} onToggle={(v) => toggleChip("attackRequirements", v)} />
            </FilterGroup>
          )}

          {!isV2 && (
            <FilterGroup label={t("User Interaction", "Benutzerinteraktion")}>
              <ChipGroup options={userInteractions} selected={value.userInteraction} onToggle={(v) => toggleChip("userInteraction", v)} />
            </FilterGroup>
          )}

          {!isV4 && !isV2 && (
            <FilterGroup label={t("Scope", "Geltungsbereich")}>
              <ChipGroup options={SCOPES} selected={value.scope} onToggle={(v) => toggleChip("scope", v)} />
            </FilterGroup>
          )}

          <FilterGroup label={t("Confidentiality", "Vertraulichkeit")}>
            <ChipGroup options={impactOptions} selected={value.confidentialityImpact} onToggle={(v) => toggleChip("confidentialityImpact", v)} />
          </FilterGroup>

          <FilterGroup label={t("Integrity", "Integrität")}>
            <ChipGroup options={impactOptions} selected={value.integrityImpact} onToggle={(v) => toggleChip("integrityImpact", v)} />
          </FilterGroup>

          <FilterGroup label={t("Availability", "Verfügbarkeit")}>
            <ChipGroup options={impactOptions} selected={value.availabilityImpact} onToggle={(v) => toggleChip("availabilityImpact", v)} />
          </FilterGroup>
        </div>
      </details>

      <div className="vulnerability-list-filter-footer">
        <button
          type="button"
          className="btn"
          onClick={() => onChange({ ...EMPTY_ADVANCED_FILTERS })}
        >
          {t("Clear all filters", "Alle Filter zurücksetzen")}
        </button>
      </div>
    </div>
  );
};

/* ── Helpers ─────────────────────────────────────────────────── */

const FilterGroup = ({ label, children }: { label: string; children: ReactNode }) => (
  <div className="vulnerability-list-filter-group" role="group" aria-label={label}>
    <span className="vulnerability-list-filter-label">{label}</span>
    {children}
  </div>
);

const ChipGroup = ({
  options,
  selected,
  onToggle,
}: {
  options: readonly string[];
  selected: string[];
  onToggle: (value: string) => void;
}) => (
  <div className="vulnerability-list-filter-chips">
    {options.map((option) => (
      <button
        key={option}
        type="button"
        className="vulnerability-list-filter-chip"
        aria-pressed={selected.includes(option)}
        onClick={() => onToggle(option)}
      >
        {chipLabel(option)}
      </button>
    ))}
  </div>
);
