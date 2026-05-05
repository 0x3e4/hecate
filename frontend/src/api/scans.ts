import { api } from "./client";
import type {
  ScanTargetGroupListResponse,
  ScanTargetListResponse,
  ScanTarget,
  ScanListResponse,
  Scan,
  ScanFindingListResponse,
  SbomComponentListResponse,
  ConsolidatedAlertListResponse,
  ConsolidatedFindingListResponse,
  ConsolidatedSbomListResponse,
  ScanLayerAnalysis,
  ScanHistoryResponse,
  ScanComparisonResponse,
  ScannerStats,
  SubmitScanRequest,
  SubmitScanResponse,
} from "../types";

export const fetchScanTargets = async (params?: {
  type?: string;
  group?: string;
  limit?: number;
  offset?: number;
}): Promise<ScanTargetListResponse> => {
  const response = await api.get<ScanTargetListResponse>("/v1/scans/targets", { params });
  return response.data;
};

export const fetchScanTargetGroups = async (): Promise<ScanTargetGroupListResponse> => {
  const response = await api.get<ScanTargetGroupListResponse>("/v1/scans/targets/groups");
  return response.data;
};

export const fetchScanTarget = async (targetId: string): Promise<ScanTarget> => {
  const response = await api.get<ScanTarget>(`/v1/scans/targets/${encodeURIComponent(targetId)}`);
  return response.data;
};

// Force an out-of-band scanner /check probe and return the refreshed target.
// Used by the Scanner-tab diagnostics table to let users re-run the probe on
// demand without waiting for the next 30-min auto-scan cron. Does NOT submit
// a scan even when the verdict is "changed".
export const triggerTargetCheck = async (targetId: string): Promise<ScanTarget> => {
  const response = await api.post<ScanTarget>(
    `/v1/scans/targets/${encodeURIComponent(targetId)}/check`,
  );
  return response.data;
};

export const fetchScans = async (params?: {
  targetId?: string;
  status?: string;
  limit?: number;
  offset?: number;
}): Promise<ScanListResponse> => {
  const response = await api.get<ScanListResponse>("/v1/scans", { params });
  return response.data;
};

export const fetchScan = async (scanId: string): Promise<Scan> => {
  const response = await api.get<Scan>(`/v1/scans/${scanId}`);
  return response.data;
};

export const fetchScanFindings = async (
  scanId: string,
  params?: { severity?: string; limit?: number; offset?: number; includeDismissed?: boolean }
): Promise<ScanFindingListResponse> => {
  const response = await api.get<ScanFindingListResponse>(`/v1/scans/${scanId}/findings`, { params });
  return response.data;
};

export const fetchScanSbom = async (
  scanId: string,
  params?: { search?: string; limit?: number; offset?: number }
): Promise<SbomComponentListResponse> => {
  const response = await api.get<SbomComponentListResponse>(`/v1/scans/${scanId}/sbom`, { params });
  return response.data;
};

export const fetchGlobalFindings = async (params?: {
  search?: string;
  severity?: string;
  targetId?: string;
  sortBy?: string;
  sortOrder?: string;
  limit?: number;
  offset?: number;
}): Promise<ConsolidatedFindingListResponse> => {
  const response = await api.get<ConsolidatedFindingListResponse>("/v1/scans/findings", { params });
  return response.data;
};

export const fetchGlobalSbom = async (params?: {
  search?: string;
  type?: string;
  targetId?: string;
  limit?: number;
  offset?: number;
}): Promise<ConsolidatedSbomListResponse> => {
  const response = await api.get<ConsolidatedSbomListResponse>("/v1/scans/sbom", { params });
  return response.data;
};

export const fetchGlobalAlerts = async (params?: {
  search?: string;
  severity?: string;
  category?: string;
  targetId?: string;
  sortBy?: string;
  sortOrder?: string;
  limit?: number;
  offset?: number;
}): Promise<ConsolidatedAlertListResponse> => {
  const response = await api.get<ConsolidatedAlertListResponse>("/v1/scans/alerts", { params });
  return response.data;
};

export const fetchBadgeCounts = async (): Promise<{ findings: number; sbom: number; licenses: number; alerts: number }> => {
  const response = await api.get<{ findings: number; sbom: number; licenses: number; alerts: number }>("/v1/scans/badge-counts");
  return response.data;
};

export type SbomFacet = { name: string; count: number };
export type SbomFacets = { ecosystems: SbomFacet[]; licenses: SbomFacet[]; types: SbomFacet[] };

export const fetchSbomFacets = async (targetId?: string): Promise<SbomFacets> => {
  const response = await api.get<SbomFacets>("/v1/scans/sbom/facets", {
    params: targetId ? { targetId } : undefined,
  });
  return response.data;
};

export const submitManualScan = async (request: SubmitScanRequest): Promise<SubmitScanResponse> => {
  const response = await api.post<SubmitScanResponse>("/v1/scans/manual", request);
  return response.data;
};

export const submitManualSourceArchiveScan = async (params: {
  archive: File;
  scanners?: string[];
  targetName?: string;
}): Promise<SubmitScanResponse> => {
  const sourceArchiveBase64 = await new Promise<string>((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      if (typeof reader.result !== "string") {
        reject(new Error("Failed to read archive as base64"));
        return;
      }
      const comma = reader.result.indexOf(",");
      resolve(comma >= 0 ? reader.result.slice(comma + 1) : reader.result);
    };
    reader.onerror = () => reject(reader.error ?? new Error("Failed to read archive"));
    reader.readAsDataURL(params.archive);
  });

  const derivedName = params.archive.name.replace(/\.zip$/i, "").trim();
  const response = await api.post<SubmitScanResponse>("/v1/scans/manual", {
    target: params.targetName?.trim() || derivedName || "uploaded-source",
    type: "source_repo",
    scanners: params.scanners,
    sourceArchiveBase64,
    oneTime: true,
  }, {
    timeout: 300000,
  });
  return response.data;
};

export const fetchFindingsByCve = async (
  cveId: string,
  params?: { limit?: number; offset?: number }
): Promise<ScanFindingListResponse> => {
  const response = await api.get<ScanFindingListResponse>(`/v1/scans/findings/by-cve/${encodeURIComponent(cveId)}`, { params });
  return response.data;
};

export const deleteScanTarget = async (targetId: string): Promise<void> => {
  await api.delete(`/v1/scans/targets/${encodeURIComponent(targetId)}`);
};

export const deleteScan = async (scanId: string): Promise<void> => {
  await api.delete(`/v1/scans/${encodeURIComponent(scanId)}`);
};

export const updateScanTarget = async (
  targetId: string,
  data: { autoScan?: boolean; scanners?: string[]; group?: string | null }
): Promise<ScanTarget> => {
  const response = await api.patch<ScanTarget>(
    `/v1/scans/targets/${encodeURIComponent(targetId)}`,
    data
  );
  return response.data;
};

const extractFilename = (disposition?: string): string | undefined => {
  if (!disposition) return undefined;
  const match = /filename\*=UTF-8''([^;]+)|filename="?([^\";]+)"?/i.exec(disposition);
  return match ? (decodeURIComponent(match[1] ?? match[2] ?? "").trim() || undefined) : undefined;
};

export const exportScanSbom = async (
  scanId: string,
  format: "cyclonedx-json" | "spdx-json"
): Promise<{ data: Blob; filename?: string }> => {
  const response = await api.get<Blob>(`/v1/scans/${scanId}/sbom/export`, {
    params: { format },
    responseType: "blob",
  });
  return {
    data: response.data,
    filename: extractFilename(response.headers["content-disposition"]),
  };
};

export const fetchScanLayers = async (scanId: string): Promise<ScanLayerAnalysis> => {
  const response = await api.get<ScanLayerAnalysis>(`/v1/scans/${scanId}/layers`);
  return response.data;
};

export const fetchTargetHistory = async (
  targetId: string,
  params?: { since?: string; limit?: number },
): Promise<ScanHistoryResponse> => {
  const response = await api.get<ScanHistoryResponse>(
    `/v1/scans/targets/${encodeURIComponent(targetId)}/history`,
    { params },
  );
  return response.data;
};

export const cancelScan = async (scanId: string): Promise<void> => {
  await api.post(`/v1/scans/${encodeURIComponent(scanId)}/cancel`);
};

export const fetchScannerStats = async (): Promise<ScannerStats> => {
  const response = await api.get<ScannerStats>("/v1/scans/scanner/stats");
  return response.data;
};

export const compareScans = async (
  scanIdA: string,
  scanIdB: string
): Promise<ScanComparisonResponse> => {
  const response = await api.get<ScanComparisonResponse>("/v1/scans/compare", {
    params: { scanA: scanIdA, scanB: scanIdB },
  });
  return response.data;
};

export const updateFindingVex = async (
  findingId: string,
  payload: {
    vexStatus: string | null;
    vexJustification?: string;
    vexDetail?: string;
    vexResponse?: string[];
  }
): Promise<{ success: boolean; findingId: string }> => {
  const response = await api.put(`/v1/scans/vex/findings/${findingId}`, payload);
  return response.data;
};

export const bulkUpdateVex = async (payload: {
  targetId: string;
  vulnerabilityId: string;
  vexStatus: string;
  vexJustification?: string;
}): Promise<{ updated: number }> => {
  const response = await api.post("/v1/scans/vex/bulk-update", payload);
  return response.data;
};

export const bulkUpdateVexByIds = async (payload: {
  findingIds: string[];
  vexStatus: string;
  vexJustification?: string;
  vexDetail?: string;
}): Promise<{ updated: number }> => {
  const response = await api.post("/v1/scans/vex/bulk-update-by-ids", payload);
  return response.data;
};

export const dismissFindings = async (payload: {
  findingIds: string[];
  dismissed: boolean;
  reason?: string;
}): Promise<{ updated: number }> => {
  const response = await api.post("/v1/scans/findings/dismiss", payload);
  return response.data;
};

export const exportVex = async (scanId: string): Promise<Blob> => {
  const response = await api.get(`/v1/scans/${scanId}/vex/export`, {
    responseType: "blob",
  });
  return response.data;
};

export const importVex = async (payload: {
  vexDocument: Record<string, unknown>;
  targetId: string;
  format?: string;
}): Promise<{ applied: number; skipped: number; notFound: number }> => {
  const response = await api.post("/v1/scans/vex/import", payload);
  return response.data;
};

export const importSbom = async (payload: {
  sbom: Record<string, unknown>;
  format?: string;
  targetName?: string;
  targetId?: string;
}): Promise<SubmitScanResponse> => {
  const response = await api.post<SubmitScanResponse>("/v1/scans/import-sbom", payload);
  return response.data;
};

export const triggerScanAiAnalysis = async (
  scanId: string,
  payload: { provider: string; language?: string; additionalContext?: string },
  password?: string,
): Promise<{ status: string; scanId: string }> => {
  const response = await api.post<{ status: string; scanId: string }>(
    `/v1/scans/${encodeURIComponent(scanId)}/ai-analysis`,
    payload,
    password ? { headers: { "X-AI-Analysis-Password": password } } : undefined,
  );
  return response.data;
};

export const fetchScanAttackChain = async (
  scanId: string,
  options?: { language?: string },
): Promise<import("../types").ScanAttackChainResponse> => {
  const params = new URLSearchParams();
  if (options?.language) params.set("language", options.language);
  const response = await api.get<import("../types").ScanAttackChainResponse>(
    `/v1/scans/${encodeURIComponent(scanId)}/attack-chain`,
    { params: params.toString() ? params : undefined },
  );
  return response.data;
};

export const triggerScanAttackChainNarrative = async (
  scanId: string,
  payload: { provider: string; language?: string; additionalContext?: string; triggeredBy?: string },
  password?: string,
): Promise<{ status: string; scanId: string }> => {
  const response = await api.post<{ status: string; scanId: string }>(
    `/v1/scans/${encodeURIComponent(scanId)}/attack-chain`,
    payload,
    password ? { headers: { "X-AI-Analysis-Password": password } } : undefined,
  );
  return response.data;
};

export interface ScanAiAnalysisHistoryItem {
  type: "scan";
  scan_id: string;
  target_id?: string | null;
  target_name?: string | null;
  commit_sha?: string | null;
  image_ref?: string | null;
  provider?: string;
  language?: string;
  summary: string;
  timestamp?: string;
  triggeredBy?: string | null;
  tokenUsage?: { inputTokens: number; outputTokens: number } | null;
  analysisCount?: number;
}

export const listScanAiAnalyses = async (params: { limit?: number; offset?: number } = {}): Promise<{
  items: ScanAiAnalysisHistoryItem[];
  total: number;
  limit: number;
  offset: number;
}> => {
  const response = await api.get<{
    items: ScanAiAnalysisHistoryItem[];
    total: number;
    limit: number;
    offset: number;
  }>("/v1/scans/ai-analyses", { params });
  return response.data;
};

export const importSbomFile = async (
  file: File,
  targetName?: string,
  format?: string,
): Promise<SubmitScanResponse> => {
  const formData = new FormData();
  formData.append("file", file);
  const params: Record<string, string> = {};
  if (targetName) params.targetName = targetName;
  if (format) params.format = format;
  const response = await api.post<SubmitScanResponse>(
    "/v1/scans/import-sbom/upload",
    formData,
    { params, headers: { "Content-Type": "multipart/form-data" } },
  );
  return response.data;
};
