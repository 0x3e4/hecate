import { Navigate, createBrowserRouter } from "react-router-dom";

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
import { InventoryPage } from "./views/InventoryPage";
import { ScansPage } from "./views/ScansPage";
import { ScanDetailPage } from "./views/ScanDetailPage";
import { CiCdInfoPage } from "./views/CiCdInfoPage";
import { ApiInfoPage } from "./views/ApiInfoPage";
import { McpInfoPage } from "./views/McpInfoPage";

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
      { path: "ai-analyse", element: <AIAnalysePage /> },
      { path: "inventory", element: <InventoryPage /> },
      { path: "scans", element: <ScansPage /> },
      { path: "scans/:scanId", element: <ScanDetailPage /> },
      { path: "audit", element: <AuditLogPage /> },
      { path: "stats", element: <StatsPage /> },
      { path: "changelog", element: <ChangelogPage /> },
      { path: "system", element: <SystemPage /> },
      { path: "info/cicd", element: <CiCdInfoPage /> },
      { path: "info/api", element: <ApiInfoPage /> },
      { path: "info/mcp", element: <McpInfoPage /> },
      { path: "cicd", element: <Navigate to="/info/cicd" replace /> },
      { path: "api-docs", element: <Navigate to="/info/api" replace /> },
      { path: "mcp-info", element: <Navigate to="/info/mcp" replace /> },
      { path: "*", element: <Navigate to="/" replace /> }
    ]
  }
]);
