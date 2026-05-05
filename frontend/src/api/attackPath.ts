import { api } from "./client";
import type { AIProviderId, AttackPathResponse } from "../types";

export interface FetchAttackPathOptions {
  scanId?: string;
  targetId?: string;
  packageName?: string;
  version?: string;
  language?: string;
}

export const fetchAttackPath = async (
  vulnId: string,
  options?: FetchAttackPathOptions,
): Promise<AttackPathResponse> => {
  const params = new URLSearchParams();
  if (options?.scanId) params.set("scanId", options.scanId);
  if (options?.targetId) params.set("targetId", options.targetId);
  if (options?.packageName) params.set("package", options.packageName);
  if (options?.version) params.set("version", options.version);
  if (options?.language) params.set("language", options.language);

  const response = await api.get<AttackPathResponse>(
    `/v1/vulnerabilities/${encodeURIComponent(vulnId)}/attack-path`,
    { params: params.toString() ? params : undefined },
  );
  return response.data;
};

export interface TriggerAttackPathNarrativeOptions {
  language?: string | null;
  additionalContext?: string | null;
  triggeredBy?: string | null;
  aiAnalysisPassword?: string | null;
}

export const triggerAttackPathNarrative = async (
  vulnId: string,
  provider: AIProviderId,
  options?: TriggerAttackPathNarrativeOptions,
): Promise<void> => {
  const payload: {
    provider: AIProviderId;
    language?: string | null;
    additionalContext?: string | null;
    triggeredBy?: string | null;
  } = { provider };
  if (options?.language) payload.language = options.language;
  if (options?.additionalContext) payload.additionalContext = options.additionalContext;
  if (options?.triggeredBy) payload.triggeredBy = options.triggeredBy;

  const password = options?.aiAnalysisPassword?.trim();
  await api.post(
    `/v1/vulnerabilities/${encodeURIComponent(vulnId)}/attack-path`,
    payload,
    password ? { headers: { "X-AI-Analysis-Password": password } } : undefined,
  );
};
