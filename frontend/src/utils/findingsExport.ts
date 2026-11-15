/**
 * Client-side export of SCA scan findings (JSON / CSV).
 *
 * The rows are the merged findings the Findings tab shows (one row per
 * vulnerability + package + version across scanners), so the file matches
 * what the user selected on screen.
 */

export interface ExportableFinding {
  findingIds: string[];
  vulnerabilityId: string | null;
  severity: string;
  cvssScore: number | null;
  packageName: string;
  packageVersion: string;
  packageType: string;
  packagePath: string | null;
  fixVersion: string | null;
  fixState: string;
  advisoryFixVersions: string[];
  title: string | null;
  description: string | null;
  scanners: string[];
  dataSource: string | null;
  vexStatus: string | null;
  vexJustification: string | null;
  vexDetail: string | null;
  /** Who set the VEX status (user, vex-import, vex-source, vex-rule:<id>, ...). */
  vexUpdatedBy?: string | null;
  vexAssessedVersion?: string | null;
  vexReviewDue?: string | null;
  vexNeedsReview?: boolean;
  dependencyScope?: string | null;
  dismissed: boolean;
  dismissedReason: string | null;
  urls: string[];
}

export interface ExportScanInfo {
  id: string;
  targetId: string;
  targetName?: string | null;
  imageRef?: string | null;
  commitSha?: string | null;
  branch?: string | null;
  startedAt?: string | null;
  finishedAt?: string | null;
}

export type FindingsExportScope = "selected" | "filtered";

const CSV_COLUMNS: [header: string, value: (f: ExportableFinding) => string | number | boolean | null][] = [
  ["vulnerability_id", f => f.vulnerabilityId],
  ["severity", f => f.severity],
  ["cvss_score", f => f.cvssScore],
  ["package_name", f => f.packageName],
  ["package_version", f => f.packageVersion],
  ["package_type", f => f.packageType],
  ["package_path", f => f.packagePath],
  ["fix_version", f => f.fixVersion],
  ["fix_state", f => f.fixState],
  ["advisory_fix_versions", f => f.advisoryFixVersions.join(" ")],
  ["title", f => f.title],
  ["description", f => f.description],
  ["scanners", f => f.scanners.join(" ")],
  ["data_source", f => f.dataSource],
  ["vex_status", f => f.vexStatus],
  ["vex_justification", f => f.vexJustification],
  ["vex_detail", f => f.vexDetail],
  ["vex_set_by", f => f.vexUpdatedBy ?? null],
  ["vex_assessed_version", f => f.vexAssessedVersion ?? null],
  ["vex_review_due", f => f.vexReviewDue ?? null],
  ["vex_needs_review", f => (f.vexStatus ? !!f.vexNeedsReview : null)],
  ["dependency_scope", f => f.dependencyScope ?? null],
  ["dismissed", f => f.dismissed],
  ["dismissed_reason", f => f.dismissedReason],
  ["urls", f => f.urls.join(" ")],
];

/**
 * One CSV cell. Package names, titles and paths come from the scanned
 * artefact, so a value starting with a formula trigger is prefixed with `'`
 * (spreadsheet formula injection), then the cell is RFC 4180 quoted.
 */
export function csvCell(value: string | number | boolean | null | undefined): string {
  if (value === null || value === undefined) return "";
  let text = String(value);
  if (typeof value === "string" && /^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  if (/[",\r\n]/.test(text)) text = `"${text.replace(/"/g, '""')}"`;
  return text;
}

export function findingsToCsv(findings: ExportableFinding[]): string {
  const lines = [CSV_COLUMNS.map(([header]) => header).join(",")];
  for (const f of findings) {
    lines.push(CSV_COLUMNS.map(([, value]) => csvCell(value(f))).join(","));
  }
  // CRLF per RFC 4180; Excel and LibreOffice both read it.
  return lines.join("\r\n") + "\r\n";
}

export function findingsToJson(
  findings: ExportableFinding[],
  scan: ExportScanInfo,
  scope: FindingsExportScope,
  exportedAt: Date = new Date(),
): string {
  const payload = {
    metadata: {
      exportedAt: exportedAt.toISOString(),
      scope,
      count: findings.length,
      scan: {
        id: scan.id,
        targetId: scan.targetId,
        targetName: scan.targetName ?? null,
        imageRef: scan.imageRef ?? null,
        commitSha: scan.commitSha ?? null,
        branch: scan.branch ?? null,
        startedAt: scan.startedAt ?? null,
        finishedAt: scan.finishedAt ?? null,
      },
    },
    findings: findings.map(f => ({
      vulnerabilityId: f.vulnerabilityId,
      severity: f.severity,
      cvssScore: f.cvssScore,
      packageName: f.packageName,
      packageVersion: f.packageVersion,
      packageType: f.packageType || null,
      packagePath: f.packagePath,
      fixVersion: f.fixVersion,
      fixState: f.fixState,
      advisoryFixVersions: f.advisoryFixVersions,
      title: f.title,
      description: f.description,
      scanners: f.scanners,
      dataSource: f.dataSource,
      dependencyScope: f.dependencyScope ?? null,
      vex: f.vexStatus
        ? {
          status: f.vexStatus,
          justification: f.vexJustification,
          detail: f.vexDetail,
          setBy: f.vexUpdatedBy ?? null,
          assessedVersion: f.vexAssessedVersion ?? null,
          reviewDue: f.vexReviewDue ?? null,
          needsReview: !!f.vexNeedsReview,
        }
        : null,
      dismissed: f.dismissed,
      dismissedReason: f.dismissedReason,
      urls: f.urls,
      findingIds: f.findingIds,
    })),
  };
  return JSON.stringify(payload, null, 2);
}

/** File name like `findings-<target>-<scanId8>.csv`, safe on every OS. */
export function findingsExportFilename(scan: ExportScanInfo, format: "json" | "csv"): string {
  const base = (scan.targetName || scan.targetId || "scan")
    .replace(/^[a-z]+:\/\//i, "")
    .replace(/[^A-Za-z0-9._-]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 60) || "scan";
  return `findings-${base}-${scan.id.slice(0, 8)}.${format}`;
}
