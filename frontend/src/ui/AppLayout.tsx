import { useState, useEffect } from "react";
import { Outlet } from "react-router-dom";

import { Header } from "./Header";
import { Sidebar } from "./Sidebar";
import { SavedSearchesProvider } from "../hooks/useSavedSearches";
import { ScrollToTop } from "../components/ScrollToTop";
import { useTimezone } from "../timezone/context";

export const AppLayout = () => {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const { timezone } = useTimezone();

  // Close mobile menu when clicking outside or on overlay
  useEffect(() => {
    if (mobileMenuOpen) {
      document.body.style.overflow = "hidden";
    } else {
      document.body.style.overflow = "";
    }
    return () => {
      document.body.style.overflow = "";
    };
  }, [mobileMenuOpen]);

  return (
    <SavedSearchesProvider>
      <div className="app-shell">
        <Sidebar
          collapsed={sidebarCollapsed}
          onToggleCollapse={() => setSidebarCollapsed((value) => !value)}
          mobileMenuOpen={mobileMenuOpen}
          onMobileMenuClose={() => setMobileMenuOpen(false)}
        />
        <div className="app-main">
          <Header
            onMenuToggle={() => setMobileMenuOpen((value) => !value)}
            isMobileMenuOpen={mobileMenuOpen}
          />
          <main className="app-content">
            <Outlet key={timezone} />
          </main>
        </div>
        {mobileMenuOpen && (
          <div
            className="mobile-menu-overlay"
            onClick={() => setMobileMenuOpen(false)}
            aria-hidden="true"
          />
        )}
        <ScrollToTop />
      </div>
    </SavedSearchesProvider>
  );
};
