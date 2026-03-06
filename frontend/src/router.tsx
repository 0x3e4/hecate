import { Navigate, createBrowserRouter } from "react-router-dom";

import { config } from "./config";
import { AppLayout } from "./ui/AppLayout";
import { DashboardPage } from "./views/DashboardPage";
import { VulnerabilityDetailPage } from "./views/VulnerabilityDetailPage";
import { AuditLogPage } from "./views/AuditLogPage";
import { VulnerabilityListPage } from "./views/VulnerabilityListPage";
import { QueryBuilderPage } from "./views/QueryBuilderPage";
import { AIAnalysePage } from "./views/AIAnalysePage";
import { StatsPage } from "./views/StatsPage";
import { ChangelogPage } from "./views/ChangelogPage";
import { SystemPage } from "./views/SystemPage";
import { ScansPage } from "./views/ScansPage";
import { ScanDetailPage } from "./views/ScanDetailPage";

export const router = createBrowserRouter([
  {
    path: "/",
    element: <AppLayout />,
    children: [
      { index: true, element: <DashboardPage /> },
      { path: "vulnerabilities", element: <VulnerabilityListPage /> },
      { path: "vulnerability/:vulnId", element: <VulnerabilityDetailPage /> },
      { path: "vulnerability", element: <Navigate to="/vulnerabilities" replace /> },
      { path: "query-builder", element: <QueryBuilderPage /> },
      ...(config.aiFeatures.enabled ? [{ path: "ai-analyse", element: <AIAnalysePage /> }] : []),
      ...(config.scaFeatures.enabled ? [
        { path: "scans", element: <ScansPage /> },
        { path: "scans/:scanId", element: <ScanDetailPage /> },
      ] : []),
      { path: "audit", element: <AuditLogPage /> },
      { path: "stats", element: <StatsPage /> },
      { path: "changelog", element: <ChangelogPage /> },
      { path: "system", element: <SystemPage /> },
      { path: "*", element: <Navigate to="/" replace /> }
    ]
  }
]);
