import { api } from "./client";
import type {
  ScanTargetListResponse,
  ScanTarget,
  ScanListResponse,
  Scan,
  ScanFindingListResponse,
  SbomComponentListResponse,
  ScanLayerAnalysis,
  ScanHistoryResponse,
  ScanComparisonResponse,
  ScannerStats,
  SubmitScanRequest,
  SubmitScanResponse,
} from "../types";

export const fetchScanTargets = async (params?: {
  type?: string;
  limit?: number;
  offset?: number;
}): Promise<ScanTargetListResponse> => {
  const response = await api.get<ScanTargetListResponse>("/v1/scans/targets", { params });
  return response.data;
};

export const fetchScanTarget = async (targetId: string): Promise<ScanTarget> => {
  const response = await api.get<ScanTarget>(`/v1/scans/targets/${encodeURIComponent(targetId)}`);
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
  params?: { severity?: string; limit?: number; offset?: number }
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
  data: { autoScan?: boolean }
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

export const fetchTargetHistory = async (targetId: string): Promise<ScanHistoryResponse> => {
  const response = await api.get<ScanHistoryResponse>(
    `/v1/scans/targets/${encodeURIComponent(targetId)}/history`
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
