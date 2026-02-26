import { Link } from "react-router-dom";
import { useI18n } from "../i18n/context";

type HeaderProps = {
  onMenuToggle?: () => void;
  isMobileMenuOpen?: boolean;
};

export const Header = ({ onMenuToggle, isMobileMenuOpen }: HeaderProps) => {
  const { t } = useI18n();

  return (
    <header className="app-header">
      <Link to="/" className="header-branding">
        <img src="/logo.png" alt="Hecate Logo" className="header-logo" />
        <div>
          <h1>Hecate Cyber Defense</h1>
          <p>{t("AI-powered vulnerability analysis", "KI-gestützte Schwachstellenanalyse")}</p>
        </div>
      </Link>
      {onMenuToggle && (
        <button
          type="button"
          className="mobile-menu-toggle"
          onClick={onMenuToggle}
          aria-label={isMobileMenuOpen ? t("Close menu", "Menü schließen") : t("Open menu", "Menü öffnen")}
          aria-expanded={isMobileMenuOpen}
        >
          <span className="hamburger-icon">
            <span></span>
            <span></span>
            <span></span>
          </span>
        </button>
      )}
    </header>
  );
};
