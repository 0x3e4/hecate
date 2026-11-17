/**
 * A finding's fix state, as scanners report it: `fixed`, `not_fixed`, or one
 * of the distribution's "no fix" answers (Trivy's Status, Grype's fix.state).
 */
export type NoFixState = "wont_fix" | "fix_deferred" | "end_of_life";

export const NO_FIX_STATES: NoFixState[] = ["wont_fix", "fix_deferred", "end_of_life"];

// Strongest first: one scanner's fix outweighs another's "not fixed", and the
// distribution's explicit answer outweighs a bare "not fixed".
const RANK = ["fixed", "end_of_life", "wont_fix", "fix_deferred", "not_fixed", "unknown"];

/** The fix state of a finding several scanners report (mirrors spread_fix_states in the backend). */
export const mergeFixState = (a: string | null | undefined, b: string | null | undefined): string => {
  const rank = (s: string | null | undefined) => {
    const i = RANK.indexOf(s ?? "unknown");
    return i === -1 ? RANK.length : i;
  };
  return (rank(a) <= rank(b) ? a : b) ?? "unknown";
};

export const isNoFixState = (state: string | null | undefined): state is NoFixState =>
  NO_FIX_STATES.includes(state as NoFixState);

type T = (english: string, german: string) => string;

export const noFixLabel = (state: NoFixState, t: T): string => {
  switch (state) {
    case "wont_fix":
      return t("Won't fix", "Wird nicht behoben");
    case "fix_deferred":
      return t("Fix deferred", "Fix verschoben");
    case "end_of_life":
      return t("End of life", "End of Life");
  }
};
