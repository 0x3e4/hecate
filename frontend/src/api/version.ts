import { api } from "./client";
import type { VersionInfo } from "../types";

export const fetchVersionInfo = async (): Promise<VersionInfo> => {
  const response = await api.get<VersionInfo>("/v1/version");
  return response.data;
};
