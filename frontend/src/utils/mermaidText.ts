// Mermaid entity codes. "#" comes along so a label cannot spell its own entity.
const MERMAID_ENTITIES: Record<string, string> = {
  "#": "#35;",
  '"': "#quot;",
  "<": "#lt;",
  ">": "#gt;",
  "%": "#37;",
  "`": "#96;",
};

/**
 * Labels are package, product and target names, all of which come from outside.
 * Mermaid renders a quoted label as HTML and reads `%%{init}%%` directives anywhere
 * in the source, so nothing of either may survive into the diagram text.
 */
export function escapeForMermaid(text: string): string {
  return text
    .replace(/[#"<>%`]/g, (char) => MERMAID_ENTITIES[char])
    .replace(/\r\n|\r|\n/g, "<br/>");
}
