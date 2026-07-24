// Helpers for turning a version chip into a DQL clause on the vulnerability list.
//
// A version chip can carry two very different things:
//
//   * a concrete release token   — "7.0.1", "v2.4"
//   * an advisory range string   — ">= 7.0.0, < 7.0.2", "<= 5.0.9",
//                                   or the EUVD shapes "4.7 ≤4.7.30" / "n/a ≤5.0.0"
//
// Both should search by *range coverage* (`affectedVersion:X`, which also
// matches advisories that merely span the version) rather than an exact term
// match on the stored boundary tokens (`product_versions:X`, which never
// matches a range string). To do that we resolve either shape to a single
// version that is guaranteed to fall inside the range.

// A dotted numeric release ("7.0.1", "v2.4") that can be compared against the
// indexed version ranges.
const CONCRETE_VERSION_RE = /^v?\d+(?:\.\d+)*$/i;

export const isConcreteVersion = (value: string): boolean =>
  CONCRETE_VERSION_RE.test(value.trim());

const VERSION_TOKEN = "\\d+(?:\\.\\d+)*";
const GE_RE = new RegExp(`>=\\s*(${VERSION_TOKEN})`);
// `≤+` absorbs the doubled operator EUVD sometimes emits ("n/a ≤≤ 1.50.2").
const LE_RE = new RegExp(`(?:<=|≤+)\\s*(${VERSION_TOKEN})`);
const LT_RE = new RegExp(`<\\s*(${VERSION_TOKEN})`);
const EQ_RE = new RegExp(`^\\s*=?\\s*(${VERSION_TOKEN})\\s*$`);

/**
 * Resolve a version chip to one concrete version that lies inside its range,
 * suitable for an `affectedVersion:` query. Returns null when the chip carries
 * no usable version (broad sentinels like "*", "-", "n/a", or a lone exclusive
 * upper bound "< X" whose only named version is the excluded fixed release).
 */
export const representativeVersionInRange = (raw: string): string | null => {
  const value = raw.trim();
  if (!value) return null;
  if (isConcreteVersion(value)) return value.replace(/^v/i, "");

  // Prefer an inclusive lower bound (">= X" → X is inside), then an exact
  // value, then an inclusive upper bound ("<= X" / "≤X" → X is inside).
  const ge = GE_RE.exec(value);
  if (ge) return ge[1];
  const eq = EQ_RE.exec(value);
  if (eq) return eq[1];
  const le = LE_RE.exec(value);
  if (le) return le[1];

  // Only an exclusive upper bound ("< X"): X is the fixed release and is NOT in
  // range, so there is no concrete version we can safely search for.
  return null;
};
