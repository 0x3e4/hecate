import { api } from "./client";
import type {
  NotificationStatusResponse,
  NotificationTestResponse,
  NotificationRuleListResponse,
  NotificationRule,
  NotificationRuleCreate,
  NotificationChannel,
  NotificationChannelListResponse,
} from "../types";

export async function fetchNotificationStatus(): Promise<NotificationStatusResponse> {
  const response = await api.get<NotificationStatusResponse>("/v1/notifications/status");
  return response.data;
}

export async function sendTestNotification(): Promise<NotificationTestResponse> {
  const response = await api.post<NotificationTestResponse>("/v1/notifications/test");
  return response.data;
}

export async function fetchNotificationRules(): Promise<NotificationRuleListResponse> {
  const response = await api.get<NotificationRuleListResponse>("/v1/notifications/rules");
  return response.data;
}

export async function createNotificationRule(payload: NotificationRuleCreate): Promise<NotificationRule> {
  const response = await api.post<NotificationRule>("/v1/notifications/rules", payload);
  return response.data;
}

export async function updateNotificationRule(ruleId: string, payload: NotificationRuleCreate): Promise<NotificationRule> {
  const response = await api.put<NotificationRule>(`/v1/notifications/rules/${ruleId}`, payload);
  return response.data;
}

export async function deleteNotificationRule(ruleId: string): Promise<void> {
  await api.delete(`/v1/notifications/rules/${ruleId}`);
}

// --- Channel Management ---

export async function fetchNotificationChannels(): Promise<NotificationChannelListResponse> {
  const response = await api.get<NotificationChannelListResponse>("/v1/notifications/channels");
  return response.data;
}

export async function addNotificationChannel(url: string, tag: string): Promise<NotificationChannel> {
  const response = await api.post<NotificationChannel>("/v1/notifications/channels", { url, tag });
  return response.data;
}

export async function removeNotificationChannel(channelId: string): Promise<void> {
  await api.delete(`/v1/notifications/channels/${channelId}`);
}
