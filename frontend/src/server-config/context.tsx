import { createContext, useContext, useEffect, useState, type ReactNode } from "react";

import { api } from "../api/client";

export interface ServerConfig {
  aiEnabled: boolean;
  scaEnabled: boolean;
  scaAutoScanEnabled: boolean;
  supportPageEnabled: boolean;
  eolEnabled: boolean;
  aiBatchMaxVulns: number;
  /** Target of the sidebar's Documentation link; null hides it. */
  docsUrl: string | null;
}

const PESSIMISTIC_DEFAULTS: ServerConfig = {
  aiEnabled: false,
  scaEnabled: false,
  scaAutoScanEnabled: false,
  supportPageEnabled: false,
  eolEnabled: false,
  aiBatchMaxVulns: 10,
  docsUrl: null,
};

const ServerConfigContext = createContext<ServerConfig | null>(null);

const splashStyle: React.CSSProperties = {
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  minHeight: "100vh",
  color: "var(--color-muted)",
  fontFamily: "system-ui, sans-serif",
};

export const ServerConfigProvider = ({ children }: { children: ReactNode }) => {
  const [config, setConfig] = useState<ServerConfig | null>(null);

  useEffect(() => {
    let cancelled = false;
    api
      .get<ServerConfig>("/v1/config")
      .then((res) => {
        if (!cancelled) {
          setConfig(res.data);
        }
      })
      .catch((err) => {
        console.error("Failed to load server config, using pessimistic defaults", err);
        if (!cancelled) {
          setConfig(PESSIMISTIC_DEFAULTS);
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (!config) {
    return <div style={splashStyle}>Loading…</div>;
  }

  return <ServerConfigContext.Provider value={config}>{children}</ServerConfigContext.Provider>;
};

export const useServerConfig = (): ServerConfig => {
  const ctx = useContext(ServerConfigContext);
  if (!ctx) {
    throw new Error("useServerConfig must be used within a ServerConfigProvider");
  }
  return ctx;
};
