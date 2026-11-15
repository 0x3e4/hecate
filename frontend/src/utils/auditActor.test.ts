import { describe, expect, it } from "vitest";

import { describeAuditActor } from "./auditActor";

const en = (english: string) => english;

describe("describeAuditActor", () => {
  it("names a signed-in user with role and e-mail", () => {
    const view = describeAuditActor(
      { actor: { type: "user", name: "Ada", email: "ada@example.com", role: "editor" } },
      en,
    );
    expect(view).toEqual({ label: "Ada (Editor)", title: "ada@example.com", kind: "user" });
  });

  it("mentions the password an under-privileged user wrote with", () => {
    const view = describeAuditActor({ actor: { type: "user", name: "Bo", role: "viewer", via: "target_password" } }, en);
    expect(view?.title).toBe("via Target password");
  });

  it("names whose session a refused cross-site write carried, without treating it as signed in", () => {
    const view = describeAuditActor(
      { actor: { type: "session_refused", name: "Ann", email: "ann@example.test", role: "admin", reason: "csrf" } },
      en,
    );
    expect(view?.label).toBe("Ann (session refused)");
    expect(view?.kind).toBe("none");
    expect(view?.title).toContain("ann@example.test");
  });

  it("names the shared credential", () => {
    expect(describeAuditActor({ actor: { type: "system_password" } }, en)?.label).toBe("System password");
    expect(describeAuditActor({ actor: { type: "api_token", name: "deploy" } }, en)?.label).toBe("API token deploy");
    expect(describeAuditActor({ actor: { type: "target_password", target: "github.com/x/y" } }, en)).toEqual({
      label: "Target password",
      title: "github.com/x/y",
      kind: "credential",
    });
  });

  it("says anonymous for fail-open installs", () => {
    expect(describeAuditActor({ actor: { type: "anonymous" } }, en)?.label).toBe("Anonymous");
  });

  it("falls back to the MCP identity", () => {
    expect(describeAuditActor({ identity: "octocat", email: "o@example.com" }, en)).toEqual({
      label: "octocat",
      title: "o@example.com",
      kind: "user",
    });
  });

  it("returns null for jobs nobody triggered", () => {
    expect(describeAuditActor({ label: "NVD sync" }, en)).toBeNull();
    expect(describeAuditActor(undefined, en)).toBeNull();
  });
});
