import { createBrowserRouter } from "react-router-dom";

import { AppLayout } from "./ui/AppLayout";
import { DashboardPage } from "./views/DashboardPage";
import { VulnerabilityDetailPage } from "./views/VulnerabilityDetailPage";

export const router = createBrowserRouter([
  {
    path: "/",
    element: <AppLayout />,
    children: [
      { index: true, element: <DashboardPage /> },
      { path: "vulnerabilities/:cveId", element: <VulnerabilityDetailPage /> }
    ]
  }
]);
