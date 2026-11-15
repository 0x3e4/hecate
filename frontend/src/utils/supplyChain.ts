/**
 * Supply-chain signals on SBOM components (pure, tested).
 *
 * The backend looks every registry package up after a scan and stores three
 * flags per component: a release younger than SCA_FRESH_RELEASE_DAYS, no
 * release for SCA_UNMAINTAINED_DAYS, and (npm) a version published by an
 * account that published none of the versions before it.
 */
import type { SbomComponent } from "../types";

export type SupplyChainSignal = "fresh" | "unmaintained" | "publisher";
export const SUPPLY_CHAIN_SIGNALS: SupplyChainSignal[] = ["fresh", "publisher", "unmaintained"];

type SignalFields = Pick<SbomComponent, "freshRelease" | "unmaintained" | "publisherChanged">;

export function signalsOf(c: SignalFields): SupplyChainSignal[] {
  const out: SupplyChainSignal[] = [];
  if (c.freshRelease) out.push("fresh");
  if (c.publisherChanged) out.push("publisher");
  if (c.unmaintained) out.push("unmaintained");
  return out;
}

export function hasSignal(c: SignalFields, signal: SupplyChainSignal): boolean {
  return signalsOf(c).includes(signal);
}

export function signalCounts(items: SignalFields[]): Record<SupplyChainSignal, number> {
  const counts: Record<SupplyChainSignal, number> = { fresh: 0, unmaintained: 0, publisher: 0 };
  for (const c of items) for (const s of signalsOf(c)) counts[s] += 1;
  return counts;
}

/** Whole days between an ISO date and now (floored), or null. */
export function ageInDays(iso: string | null | undefined, now: Date = new Date()): number | null {
  if (!iso) return null;
  const at = new Date(iso).getTime();
  if (Number.isNaN(at)) return null;
  return Math.max(0, Math.floor((now.getTime() - at) / 86_400_000));
}

type Translate = (english: string, german: string) => string;

export function signalLabel(signal: SupplyChainSignal, t: Translate): string {
  switch (signal) {
    case "fresh":
      return t("Fresh release", "Frisches Release");
    case "publisher":
      return t("New publisher", "Neuer Publisher");
    default:
      return t("Unmaintained", "Unbetreut");
  }
}

/** The tooltip: what exactly the registry data says. */
export function signalDetail(signal: SupplyChainSignal, c: SbomComponent, t: Translate, now: Date = new Date()): string {
  if (signal === "fresh") {
    const days = ageInDays(c.publishedAt, now);
    return days === null
      ? t("Published only recently", "Erst kürzlich veröffentlicht")
      : t(`Published ${days} day(s) ago`, `Vor ${days} Tag(en) veröffentlicht`);
  }
  if (signal === "publisher") {
    const prev = (c.previousPublishers ?? []).join(", ");
    const added = (c.newMaintainers ?? []).length
      ? t(`; maintainers added: ${(c.newMaintainers ?? []).join(", ")}`, `; neue Maintainer: ${(c.newMaintainers ?? []).join(", ")}`)
      : "";
    return t(
      `Published by npm account ${c.publisher ?? "?"}, previous versions by ${prev || "?"}${added}`,
      `Veröffentlicht vom npm-Konto ${c.publisher ?? "?"}, die Versionen davor von ${prev || "?"}${added}`,
    );
  }
  const days = ageInDays(c.latestPublishedAt, now);
  const latest = c.latestVersion ? ` (${c.latestVersion})` : "";
  return days === null
    ? t("No release for a long time", "Seit langem kein Release")
    : t(`Latest release${latest} ${days} day(s) ago`, `Letztes Release${latest} vor ${days} Tag(en)`);
}
