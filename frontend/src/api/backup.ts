import { api } from "./client";
import { BackupRestoreSummary } from "../types";

export type VulnerabilitySource = "NVD" | "EUVD" | "ALL";

export interface ExportResponse {
  data: Blob;
  filename?: string;
}

const extractFilename = (disposition?: string): string | undefined => {
  if (!disposition) {
    return undefined;
  }
  const match = /filename\*=UTF-8''([^;]+)|filename="?([^\";]+)"?/i.exec(disposition);
  if (!match) {
    return undefined;
  }
  return decodeURIComponent(match[1] ?? match[2] ?? "").trim() || undefined;
};

const BACKUP_TIMEOUT = 10 * 60 * 1000; // allow long-running exports/restores

export const exportVulnerabilityBackup = async (source: VulnerabilitySource): Promise<ExportResponse> => {
  const response = await api.get<Blob>(`/v1/backup/vulnerabilities/${source}/export`, {
    responseType: "blob",
    timeout: BACKUP_TIMEOUT
  });
  return {
    data: response.data,
    filename: extractFilename(response.headers["content-disposition"])
  };
};

export const restoreVulnerabilityBackup = async (
  source: VulnerabilitySource,
  payload: unknown
): Promise<BackupRestoreSummary> => {
  const response = await api.post<BackupRestoreSummary>(`/v1/backup/vulnerabilities/${source}/restore`, payload, {
    timeout: BACKUP_TIMEOUT
  });
  return response.data;
};

export const exportCpeBackup = async (): Promise<ExportResponse> => {
  const response = await api.get<Blob>("/v1/backup/cpe/export", { responseType: "blob", timeout: BACKUP_TIMEOUT });
  return {
    data: response.data,
    filename: extractFilename(response.headers["content-disposition"])
  };
};

export const restoreCpeBackup = async (payload: unknown): Promise<BackupRestoreSummary> => {
  const response = await api.post<BackupRestoreSummary>("/v1/backup/cpe/restore", payload, {
    timeout: BACKUP_TIMEOUT
  });
  return response.data;
};
