import { createBrowserRouter } from "react-router-dom";

import { AppLayout } from "./ui/AppLayout";
import { DashboardPage } from "./views/DashboardPage";
import { VulnerabilityDetailPage } from "./views/VulnerabilityDetailPage";
import { AuditLogPage } from "./views/AuditLogPage";
import { VulnerabilityListPage } from "./views/VulnerabilityListPage";
import { StatsPage } from "./views/StatsPage";

export const router = createBrowserRouter([
  {
    path: "/",
    element: <AppLayout />,
    children: [
      { index: true, element: <DashboardPage /> },
      { path: "vulnerabilities", element: <VulnerabilityListPage /> },
      { path: "vulnerabilities/:cveId", element: <VulnerabilityDetailPage /> },
      { path: "audit", element: <AuditLogPage /> },
      { path: "stats", element: <StatsPage /> }
    ]
  }
]);
