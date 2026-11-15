/**
 * Share-of-total figures for the bar lists on the Statistics page.
 * Which total a chart divides by is the chart's decision (see StatsPage);
 * these helpers only keep the arithmetic and the formatting in one place.
 */

/** `value / total` in 0..1, or `null` when there is no usable total. */
export const shareOf = (value: number, total: number): number | null => {
  if (!Number.isFinite(value) || !Number.isFinite(total) || total <= 0) return null;
  return Math.max(0, value / total);
};

/** Sum of the bucket counts, the total of a chart whose buckets partition one population. */
export const sumValues = (values: readonly number[]): number =>
  values.reduce((sum, value) => sum + (Number.isFinite(value) ? value : 0), 0);

const SMALLEST = 0.001;

/**
 * One decimal, locale spacing ("34.2%" in en, "34,2 %" in de). A non-zero
 * share below 0.1 % reads "<0.1%" rather than a misleading "0.0%".
 */
export const formatShare = (share: number | null, locale: string): string => {
  if (share == null) return "";
  const format = new Intl.NumberFormat(locale, { style: "percent", minimumFractionDigits: 1, maximumFractionDigits: 1 });
  if (share > 0 && share < SMALLEST) return `<${format.format(SMALLEST)}`;
  return format.format(share);
};
