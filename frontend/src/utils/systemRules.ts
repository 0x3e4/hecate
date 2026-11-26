import type { InventorySystem, NotificationRule, SystemRuleEvent } from "../types";
import type { TranslateFn } from "../i18n/context";

/** The events a `system` notification rule can watch, in form order. */
export const SYSTEM_RULE_EVENTS: SystemRuleEvent[] = ["system_findings", "system_stale", "system_retired"];

export function systemEventLabel(event: SystemRuleEvent, t: TranslateFn): string {
  switch (event) {
    case "system_findings": return t("New findings in a report", "Neue Befunde in einer Meldung");
    case "system_stale": return t("Stopped reporting", "Meldet nicht mehr");
    case "system_retired": return t("Retired by a server list", "Von einer Serverliste ausgemustert");
  }
}

/** Only the events a system rule takes, in form order; anything else (left from another rule type) is dropped. */
export function systemRuleEvents(values: string[]): SystemRuleEvent[] {
  return SYSTEM_RULE_EVENTS.filter((event) => values.includes(event));
}

/** Systems a rule can pick, retired ones left out unless the rule already names them, by name. */
export function selectableSystems(systems: InventorySystem[], selected: string[] = []): InventorySystem[] {
  return systems
    .filter((s) => !s.retiredAt || selected.includes(s.id))
    .sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: "base" }));
}

/** Every group any system carries, case-insensitively unique, sorted. */
export function knownGroups(systems: InventorySystem[], selected: string[] = []): string[] {
  const seen = new Map<string, string>();
  for (const group of [...selected, ...systems.flatMap((s) => s.groups)]) {
    const key = group.toLocaleLowerCase();
    if (!seen.has(key)) seen.set(key, group);
  }
  return [...seen.values()].sort((a, b) => a.localeCompare(b, undefined, { sensitivity: "base" }));
}

/** One line for the rule list: the events, then what narrows the systems. */
export function systemRuleDescription(rule: NotificationRule, systems: InventorySystem[], t: TranslateFn): string {
  const events = systemRuleEvents(rule.eventTypes).map((e) => systemEventLabel(e, t));
  const scope: string[] = [];
  const ids = rule.systemIds ?? [];
  if (ids.length) {
    const names = ids.map((id) => systems.find((s) => s.id === id)?.name).filter((n): n is string => Boolean(n));
    const missing = ids.length - names.length;
    scope.push(names.length <= 3 && !missing
      ? names.join(", ")
      : t(`${ids.length} systems`, `${ids.length} Systeme`));
  }
  if (rule.systemGroups?.length) scope.push(t("groups", "Gruppen") + ": " + rule.systemGroups.join(", "));
  if (rule.systemExposure === "internet") scope.push(t("internet-facing", "aus dem Internet erreichbar"));
  if (rule.systemExposure === "internal") scope.push(t("internal", "intern"));
  if (rule.scanSeverityThreshold && rule.eventTypes.includes("system_findings")) {
    scope.push(`>= ${rule.scanSeverityThreshold}`);
  }
  const head = events.join(", ") || "n/a";
  return `${head}; ${scope.join(", ") || t("all systems", "alle Systeme")}`;
}
