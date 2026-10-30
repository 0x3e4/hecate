import { describe, expect, it } from "vitest";
import { escapeForMermaid } from "./mermaidText";

describe("escapeForMermaid", () => {
  it("leaves ordinary names alone", () => {
    expect(escapeForMermaid("@scope/left-pad 1.3.0")).toBe("@scope/left-pad 1.3.0");
  });

  it("keeps markup from reaching the label", () => {
    const out = escapeForMermaid('<img src=https://evil.example/x.png><form action=y>');
    expect(out).not.toContain("<");
    expect(out).not.toContain(">");
  });

  it("breaks up directives", () => {
    expect(escapeForMermaid("%%{init: {'securityLevel':'loose'}}%%")).not.toContain("%");
  });

  it("cannot close the quoted label or start a markdown string", () => {
    const out = escapeForMermaid('a"] --> b `**x**`');
    expect(out).not.toContain('"');
    expect(out).not.toContain("`");
  });

  it("escapes the hash first, so a label cannot spell an entity", () => {
    expect(escapeForMermaid("#lt;")).toBe("#35;lt;");
  });

  it("turns every line break into a label break", () => {
    expect(escapeForMermaid("a\r%% x\nb\r\nc")).toBe("a<br/>#37;#37; x<br/>b<br/>c");
  });
});
