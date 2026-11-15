import { api } from "./client";
import type { VexRule, VexRuleApplyResult, VexRuleInput, VexRulePresetList } from "../types";

export async function fetchVexRules(): Promise<{ items: VexRule[]; total: number }> {
  const response = await api.get<{ items: VexRule[]; total: number }>("/v1/vex-rules");
  return response.data;
}

export async function fetchVexRulePresets(): Promise<VexRulePresetList> {
  const response = await api.get<VexRulePresetList>("/v1/vex-rules/presets");
  return response.data;
}

export async function createVexRule(payload: VexRuleInput): Promise<VexRule> {
  const response = await api.post<VexRule>("/v1/vex-rules", payload);
  return response.data;
}

export async function updateVexRule(ruleId: string, payload: VexRuleInput): Promise<VexRule> {
  const response = await api.put<VexRule>(`/v1/vex-rules/${encodeURIComponent(ruleId)}`, payload);
  return response.data;
}

export async function deleteVexRule(ruleId: string): Promise<void> {
  await api.delete(`/v1/vex-rules/${encodeURIComponent(ruleId)}`);
}

/** Apply the enabled rules to the latest completed scan of every target. */
export async function applyVexRules(): Promise<VexRuleApplyResult> {
  const response = await api.post<VexRuleApplyResult>("/v1/vex-rules/apply");
  return response.data;
}
