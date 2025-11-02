import { useState } from "react";
import { Outlet } from "react-router-dom";

import { Header } from "./Header";
import { Sidebar } from "./Sidebar";
import { SavedSearchesProvider } from "../hooks/useSavedSearches";

export const AppLayout = () => {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  return (
    <SavedSearchesProvider>
      <div className="app-shell">
        <Sidebar
          collapsed={sidebarCollapsed}
          onToggleCollapse={() => setSidebarCollapsed((value) => !value)}
        />
        <div className="app-main">
          <Header />
          <main className="app-content">
            <Outlet />
          </main>
        </div>
      </div>
    </SavedSearchesProvider>
  );
};
