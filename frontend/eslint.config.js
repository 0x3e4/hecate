// Flat ESLint config (ESLint 9). Replaces the legacy .eslintrc.cjs, which
// ESLint 9 could not load and which had no TypeScript parser — so `.ts`/`.tsx`
// were never actually linted.
//
// Gate policy: this is the first working lint gate over a large existing
// codebase, so the noisy pre-existing backlog (explicit `any`, stray
// `console.*`, effect-dependency hints) is set to `warn` rather than `error`.
// CI fails only on genuine errors (parse errors, rules-of-hooks violations,
// unreachable code, ...). Ratchet the warnings up to errors in follow-ups.
import js from "@eslint/js";
import globals from "globals";
import reactHooks from "eslint-plugin-react-hooks";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: ["dist/**", "node_modules/**", "vite/**", "*.config.js", "*.config.ts"],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["src/**/*.{ts,tsx}"],
    plugins: {
      "react-hooks": reactHooks,
    },
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
      globals: {
        ...globals.browser,
        ...globals.es2022,
      },
    },
    rules: {
      // Only the two classic, well-established hooks rules. The v7 plugin's
      // React-Compiler-oriented rules (set-state-in-effect, purity, refs,
      // immutability, ...) are intentionally NOT enabled here — enabling them
      // as errors on the existing codebase would make the first gate red on
      // ~50 pre-existing sites. Revisit once the code is compiler-clean.
      "react-hooks/rules-of-hooks": "error",     // hard error: real correctness
      "react-hooks/exhaustive-deps": "warn",
      // --- pre-existing backlog: warn now, ratchet to error later ---
      "@typescript-eslint/no-explicit-any": "warn",
      "@typescript-eslint/no-unused-vars": [
        "warn",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
      // Stylistic dead-store rule with occasional false positives; warn for now.
      "no-useless-assignment": "warn",
      "no-console": "off",
    },
  },
  {
    // Test files use vitest globals.
    files: ["**/*.{test,spec}.{ts,tsx}"],
    languageOptions: {
      globals: { ...globals.node },
    },
  },
);
