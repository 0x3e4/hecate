import { useId } from "react";

import type { AppLanguage } from "../i18n/language";

/**
 * A small flag beside a language name. Inline SVG (an emoji flag renders as two
 * letters on Windows), colours from the `--flag-*` tokens, decorative only:
 * the name next to it carries the meaning.
 */
export const LanguageFlag = ({ language }: { language: AppLanguage }) => {
  const id = useId();
  if (language === "de") {
    return (
      <svg className="language-flag" viewBox="0 0 5 3" aria-hidden="true" focusable="false">
        <rect className="flag-de-black" width="5" height="1" />
        <rect className="flag-de-red" y="1" width="5" height="1" />
        <rect className="flag-de-gold" y="2" width="5" height="1" />
      </svg>
    );
  }
  // English: the Union Jack, cropped to the same box as the German flag.
  const diagonals = `${id}-diagonals`;
  return (
    <svg
      className="language-flag"
      viewBox="0 0 60 30"
      preserveAspectRatio="xMidYMid slice"
      aria-hidden="true"
      focusable="false"
    >
      <clipPath id={diagonals}>
        <path d="M30,15 h30 v15 z v15 h-30 z h-30 v-15 z v-15 h30 z" />
      </clipPath>
      <rect className="flag-gb-blue" width="60" height="30" />
      <path className="flag-gb-white-stroke" d="M0,0 L60,30 M60,0 L0,30" strokeWidth="6" />
      <path className="flag-gb-red-stroke" d="M0,0 L60,30 M60,0 L0,30" clipPath={`url(#${diagonals})`} strokeWidth="4" />
      <path className="flag-gb-white-stroke" d="M30,0 v30 M0,15 h60" strokeWidth="10" />
      <path className="flag-gb-red-stroke" d="M30,0 v30 M0,15 h60" strokeWidth="6" />
    </svg>
  );
};
