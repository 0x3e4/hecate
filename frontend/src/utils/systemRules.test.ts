import { describe, expect, it } from "vitest";

import type { InventorySystem, NotificationRule } from "../types";
import { knownGroups, selectableSystems, systemRuleDescription, systemRuleEvents } from "./systemRules";

const t = (en: string) => en;

const system = (overrides: Partial<InventorySystem>): InventorySystem => ({
  id: overrides.name ?? "x",
  name: "x",
  groups: [],
  source: "manual",
  reportStatus: "reporting",
  products: [],
  createdAt: "2026-11-01T00:00:00Z",
  updatedAt: "2026-11-01T00:00:00Z",
  ...overrides,
});

const rule = (overrides: Partial<NotificationRule>): NotificationRule => ({
  id: "r",
  name: "r",
  enabled: true,
  ruleType: "system",
  appriseTag: "all",
  eventTypes: [],
  createdAt: "2026-11-01T00:00:00Z",
  updatedAt: "2026-11-01T00:00:00Z",
  ...overrides,
});

describe("systemRuleEvents", () => {
  it("keeps only system events, in form order", () => {
    expect(systemRuleEvents(["scan_failed", "system_retired", "system_findings"])).toEqual(["system_findings", "system_retired"]);
  });
});

describe("selectableSystems", () => {
  const systems = [system({ name: "web-02" }), system({ name: "Db-01" }), system({ name: "old", retiredAt: "2026-11-20T00:00:00Z" })];

  it("sorts by name and leaves retired systems out", () => {
    expect(selectableSystems(systems).map((s) => s.name)).toEqual(["Db-01", "web-02"]);
  });

  it("keeps a retired system the rule already names", () => {
    expect(selectableSystems(systems, ["old"]).map((s) => s.name)).toEqual(["Db-01", "old", "web-02"]);
  });
});

describe("knownGroups", () => {
  it("merges groups case-insensitively and keeps selected ones nobody carries any more", () => {
    const systems = [system({ name: "a", groups: ["edge", "Vienna"] }), system({ name: "b", groups: ["EDGE", "db"] })];
    expect(knownGroups(systems, ["gone"])).toEqual(["db", "edge", "gone", "Vienna"]);
  });
});

describe("systemRuleDescription", () => {
  const systems = [system({ name: "web-01" }), system({ name: "web-02" })];

  it("names the events and says when it covers every system", () => {
    expect(systemRuleDescription(rule({ eventTypes: ["system_stale"] }), systems, t)).toBe("Stopped reporting; all systems");
  });

  it("lists a few systems by name, more by count", () => {
    const few = rule({ eventTypes: ["system_findings"], systemIds: ["web-01", "web-02"], scanSeverityThreshold: "high" });
    expect(systemRuleDescription(few, systems, t)).toBe("New findings in a report; web-01, web-02, >= high");
    const gone = rule({ eventTypes: ["system_findings"], systemIds: ["web-01", "deleted"] });
    expect(systemRuleDescription(gone, systems, t)).toBe("New findings in a report; 2 systems");
  });

  it("names groups and exposure, and the threshold only for findings", () => {
    const r = rule({
      eventTypes: ["system_stale", "system_retired"], systemGroups: ["edge"], systemExposure: "internet", scanSeverityThreshold: "high",
    });
    expect(systemRuleDescription(r, systems, t)).toBe(
      "Stopped reporting, Retired by a server list; groups: edge, internet-facing",
    );
  });
});
