/** Days between two calendar dates (`YYYY-MM-DD`), counted back from `today`. Null for an unusable value. */
export const dayOffsetFor = (today: string, picked: string): number | null => {
  const pattern = /^\d{4}-\d{2}-\d{2}$/;
  if (!pattern.test(today) || !pattern.test(picked)) return null;
  const days = Math.round((Date.parse(`${today}T00:00:00Z`) - Date.parse(`${picked}T00:00:00Z`)) / 86_400_000);
  if (Number.isNaN(days)) return null;
  // The future has no published CVEs yet: it lands on today.
  return Math.max(0, days);
};
