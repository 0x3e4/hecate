import { describe, expect, it } from "vitest";

import { attentionRows, groupCves, productKey, quietFindings, type GroupableCve } from "./cveGroups";

const cve = (vulnId: string, severity: string, product?: string, vendor?: string): GroupableCve => ({
  vulnId,
  severity,
  productSlugs: product ? [product] : [],
  vendorSlugs: vendor ? [vendor] : [],
});

const byProduct = (item: GroupableCve) => productKey(item);

describe("groupCves", () => {
  it("collapses a product's CVEs into one group", () => {
    const groups = groupCves(
      [cve("CVE-1", "high", "forge"), cve("CVE-2", "high", "forge"), cve("CVE-3", "low", "forge"), cve("CVE-4", "high", "pyasn1")],
      byProduct,
    );

    expect(groups.map((group) => group.key)).toEqual(["forge", "pyasn1"]);
    expect(groups[0].cves).toHaveLength(3);
  });

  it("reports the worst severity and a tally in severity order", () => {
    const [group] = groupCves([cve("CVE-1", "low", "a"), cve("CVE-2", "critical", "a"), cve("CVE-3", "low", "a")], byProduct);

    expect(group.worst).toBe("critical");
    expect(group.tally).toEqual([
      { severity: "critical", count: 1 },
      { severity: "low", count: 2 },
    ]);
    expect(group.cves[0].vulnId).toBe("CVE-2");
  });

  it("orders groups by severity before size", () => {
    const groups = groupCves(
      [cve("CVE-1", "low", "big"), cve("CVE-2", "low", "big"), cve("CVE-3", "low", "big"), cve("CVE-4", "critical", "small")],
      byProduct,
    );

    expect(groups.map((group) => group.key)).toEqual(["small", "big"]);
  });

  it("puts a leading group first within a severity", () => {
    const groups = groupCves(
      [cve("CVE-1", "high", "other"), cve("CVE-2", "high", "other"), cve("CVE-3", "high", "mine")],
      byProduct,
      (item) => item.vulnId === "CVE-3",
    );

    expect(groups.map((group) => group.key)).toEqual(["mine", "other"]);
  });

  it("counts an unrecognised or missing severity as unknown", () => {
    const [group] = groupCves([cve("CVE-1", "none", "a"), cve("CVE-2", "", "a")], byProduct);

    expect(group.worst).toBe("unknown");
    expect(group.tally).toEqual([{ severity: "unknown", count: 2 }]);
  });
});

describe("attentionRows", () => {
  const item = (id: string, certs: number, kevListed = false, dateAdded: string | null = null, severity = "high", inventory = false) => ({
    id,
    severity,
    kevListed,
    dateAdded,
    certs: Array.from({ length: certs }, () => "cert"),
    inventoryMatchIds: inventory ? ["item-1"] : [],
  });
  const none = () => 0;
  const ids = (rows: { id: string }[]) => rows.map((row) => row.id);

  it("drops a CVE only one CERT named", () => {
    expect(ids(attentionRows([item("lone", 1), item("trending", 2)], none))).toEqual(["trending"]);
  });

  it("keeps a KEV listing without any CERT", () => {
    expect(ids(attentionRows([item("kev", 0, true)], none))).toEqual(["kev"]);
  });

  it("keeps a lone mention that hits the inventory", () => {
    expect(ids(attentionRows([item("mine", 1, false, null, "high", true)], none))).toEqual(["mine"]);
  });

  it("does not let a scan finding alone earn a row", () => {
    expect(attentionRows([item("kernel", 1)], () => 2)).toEqual([]);
  });

  it("orders by stack, then signals, then severity, then the newest listing", () => {
    const rows = attentionRows(
      [
        item("old-kev", 0, true, "2026-10-27"),
        item("new-kev", 0, true, "2026-10-30"),
        item("critical-kev", 0, true, "2026-10-20", "critical"),
        item("four-certs", 4),
        item("kev-and-cert", 2, true, "2026-10-28"),
        item("in-stack", 2),
      ],
      (row) => (row.id === "in-stack" ? 2 : 0),
    );

    expect(ids(rows)).toEqual(["in-stack", "four-certs", "kev-and-cert", "critical-kev", "new-kev", "old-kev"]);
  });
});

describe("quietFindings", () => {
  const item = (id: string, certs: number, kevListed = false) => ({ id, severity: "high", kevListed, dateAdded: null, certs: Array.from({ length: certs }, () => "cert") });

  it("takes the scan findings that did not earn a row", () => {
    const rows = quietFindings(
      [item("kernel", 1), item("trending", 2), item("listed", 1, true), item("not-scanned", 1)],
      (row) => row.id !== "not-scanned",
    );

    expect(rows.map((row) => row.id)).toEqual(["kernel"]);
  });
});

describe("productKey", () => {
  it("prefers the product the match came from", () => {
    expect(productKey({ ...cve("CVE-1", "high"), productSlugs: ["a", "b"] }, "b")).toBe("b");
  });

  it("does not merge unrelated products of one vendor", () => {
    expect(productKey(cve("CVE-1", "high", undefined, "microsoft"))).toBe("CVE-1");
  });
});
