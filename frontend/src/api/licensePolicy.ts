import { api } from "./client";
import type {
  LicensePolicy,
  LicensePolicyListResponse,
  LicenseGroups,
  LicenseComplianceResult,
  LicenseOverviewResponse,
} from "../types";

export async function fetchLicensePolicies(): Promise<LicensePolicyListResponse> {
  const response = await api.get<LicensePolicyListResponse>("/v1/license-policies");
  return response.data;
}

export async function fetchLicensePolicy(policyId: string): Promise<LicensePolicy> {
  const response = await api.get<LicensePolicy>(`/v1/license-policies/${policyId}`);
  return response.data;
}

export async function createLicensePolicy(payload: {
  name: string;
  description?: string;
  allowed: string[];
  denied: string[];
  reviewed?: string[];
  defaultAction: string;
  isDefault?: boolean;
}): Promise<LicensePolicy> {
  const response = await api.post<LicensePolicy>("/v1/license-policies", payload);
  return response.data;
}

export async function updateLicensePolicy(
  policyId: string,
  payload: Partial<{
    name: string;
    description: string;
    allowed: string[];
    denied: string[];
    reviewed: string[];
    defaultAction: string;
    isDefault: boolean;
  }>
): Promise<LicensePolicy> {
  const response = await api.put<LicensePolicy>(`/v1/license-policies/${policyId}`, payload);
  return response.data;
}

export async function deleteLicensePolicy(policyId: string): Promise<void> {
  await api.delete(`/v1/license-policies/${policyId}`);
}

export async function setDefaultLicensePolicy(policyId: string): Promise<LicensePolicy> {
  const response = await api.post<LicensePolicy>(`/v1/license-policies/${policyId}/set-default`);
  return response.data;
}

export async function fetchLicenseGroups(): Promise<LicenseGroups> {
  const response = await api.get<LicenseGroups>("/v1/license-policies/groups");
  return response.data;
}

export async function fetchScanLicenseCompliance(
  scanId: string,
  policyId?: string
): Promise<LicenseComplianceResult> {
  const params = policyId ? { policyId } : {};
  const response = await api.get<LicenseComplianceResult>(
    `/v1/scans/${scanId}/license-compliance`,
    { params }
  );
  return response.data;
}

export async function fetchLicenseOverview(): Promise<LicenseOverviewResponse> {
  const response = await api.get<LicenseOverviewResponse>("/v1/scans/license-overview");
  return response.data;
}
