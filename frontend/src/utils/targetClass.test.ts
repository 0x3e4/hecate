import { describe, expect, it } from "vitest";

import { exposureLabel, kindLabel, targetClassChips } from "./targetClass";

const en = (english: string) => english;

describe("targetClassChips", () => {
  it("puts internet-facing first, then the kind", () => {
    expect(targetClassChips("host", "internet", en)).toEqual([
      { key: "exposure", label: "Internet-facing", exposed: true },
      { key: "kind", label: "Host", exposed: false },
    ]);
  });

  it("adds nothing for internal or unknown exposure", () => {
    expect(targetClassChips("kubernetes-node", "internal", en)).toEqual([
      { key: "kind", label: "Kubernetes node", exposed: false },
    ]);
    expect(targetClassChips(null, null, en)).toEqual([]);
  });
});

describe("labels", () => {
  it("names every kind and both exposures", () => {
    expect(kindLabel("container", en)).toBe("Container");
    expect(kindLabel("something-new", en)).toBe("Other");
    expect(exposureLabel("internal", en)).toBe("Internal only");
  });
});
