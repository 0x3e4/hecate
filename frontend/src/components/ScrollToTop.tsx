import { useEffect, useState } from "react";
import { LuArrowUp } from "react-icons/lu";

import { useI18n } from "../i18n/context";

export const ScrollToTop = () => {
  const { t } = useI18n();
  const [showScrollTop, setShowScrollTop] = useState<boolean>(false);

  useEffect(() => {
    const handleScroll = () => {
      setShowScrollTop(window.scrollY > 100);
    };

    window.addEventListener("scroll", handleScroll, { passive: true });
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  const scrollToTop = () => {
    // An explicit behaviour outranks the reduced-motion rule in base.css.
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    window.scrollTo({ top: 0, behavior: reduced ? "auto" : "smooth" });
  };

  if (!showScrollTop) {
    return null;
  }

  return (
    <button
      type="button"
      onClick={scrollToTop}
      className="scroll-to-top"
      aria-label={t("Scroll to top", "Nach oben scrollen")}
    >
      <LuArrowUp aria-hidden="true" />
    </button>
  );
};
