import { describe, expect, it } from "vitest";

import { writePromptTarget } from "./writeAuth";

describe("writePromptTarget", () => {
  it("offers the target password where the target gate rejected", () => {
    expect(writePromptTarget("1", "https://github.com/x/y")).toBe("https://github.com/x/y");
  });

  it("asks for the admin password where only that helps, even on a target URL", () => {
    expect(writePromptTarget("admin", "https://github.com/x/y")).toBeNull();
  });

  it("asks for the admin password without a target", () => {
    expect(writePromptTarget("1", null)).toBeNull();
  });

  it.each([undefined, "", "0", "yes"])("leaves any other 401 to the page: %s", (marker) => {
    expect(writePromptTarget(marker, "t")).toBeUndefined();
  });
});
