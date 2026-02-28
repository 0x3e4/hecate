import { api } from "./client";
import type {
  ScanTargetListResponse,
  ScanTarget,
  ScanListResponse,
  Scan,
  ScanFindingListResponse,
  SbomComponentListResponse,
  ScanHistoryResponse,
  ScanComparisonResponse,
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

export const fetchTargetHistory = async (targetId: string): Promise<ScanHistoryResponse> => {
  const response = await api.get<ScanHistoryResponse>(
    `/v1/scans/targets/${encodeURIComponent(targetId)}/history`
  );
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
