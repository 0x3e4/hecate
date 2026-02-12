import { useI18n } from "../i18n/context";

type HeaderProps = {
  onMenuToggle?: () => void;
  isMobileMenuOpen?: boolean;
};

export const Header = ({ onMenuToggle, isMobileMenuOpen }: HeaderProps) => {
  const { t } = useI18n();

  return (
    <header className="app-header">
      <div className="header-branding">
        <img src="/logo.png" alt="Hecate Logo" className="header-logo" />
        <div>
          <h1>Hecate Cyber Defense</h1>
          <p>{t("AI-powered vulnerability analysis", "KI-gestützte Schwachstellenanalyse")}</p>
        </div>
      </div>
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
