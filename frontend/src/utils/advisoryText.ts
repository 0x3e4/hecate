const OSV_BOILERPLATE = /^\s*-{3,}\s*$|^\s*_-=.*=-_\s*$/;
const OSV_SOURCE_HEADING = /^\s*#{1,6}\s*Source:.*$/;

/**
 * OSV's malicious-packages records open with a machine marker and per-source
 * headings (`_-= Per source details. Do not edit below this line.=-_`,
 * `## Source: ghsa-malware (<hash>)`). Display text starts at the first real
 * sentence; the stored record is untouched.
 */
export const cleanAdvisoryText = (text: string | null | undefined): string => {
  if (!text) return "";
  return text
    .split(/\r?\n/)
    .filter((line) => !OSV_BOILERPLATE.test(line) && !OSV_SOURCE_HEADING.test(line) && !/^\s*\([0-9a-f]{32,}\)\s*$/i.test(line))
    .join("\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
};

/**
 * OSV ecosystems can carry a registry URL (`Packagist:https://packages.drupal.org/8`).
 * Shows the ecosystem and the host instead of the raw string; display only.
 */
export const formatEcosystemName = (name: string): string => {
  const match = name.match(/^([^:]+):https?:\/\/([^/]+)/i);
  return match ? `${match[1]} (${match[2]})` : name;
};

export const LIST_ITEM = /^\s*[-*] /;

/** Words that end in a period without ending the sentence. */
const ABBREVIATIONS = new Set([
  "approx", "cf", "co", "corp", "dr", "etc", "fig", "inc", "incl", "jr", "ltd", "mr", "mrs", "ms", "no", "nr", "sr", "st", "vs",
]);

/** Most advisories are a single block; past this length it is split into paragraphs. */
const PARAGRAPH_SPLIT_MIN = 400;
/** A paragraph closes once it reaches this many characters, at a sentence end. */
const PARAGRAPH_TARGET = 240;
/** A trailing sentence shorter than this joins the paragraph before it. */
const PARAGRAPH_TAIL_MIN = 80;

/** Splits prose at sentence ends, leaving `e.g.`, `Inc.`, `v1.2.3` and file names intact. */
export const splitSentences = (text: string): string[] => {
  const sentences: string[] = [];
  const boundary = /[.!?]["')\]]?\s+(?=["'([]?[A-Z])/g;
  let start = 0;
  for (let match = boundary.exec(text); match; match = boundary.exec(text)) {
    const before = text.slice(start, match.index);
    const lastWord = (before.match(/(\S+)$/)?.[1] ?? "").replace(/^["'([]+/, "");
    const isAbbreviation =
      ABBREVIATIONS.has(lastWord.toLowerCase()) ||
      /^[A-Za-z]$/.test(lastWord) || // initials, "A. Smith"
      /^(?:[A-Za-z]\.)+[A-Za-z]$/.test(lastWord); // e.g, i.e, U.S
    if (isAbbreviation) continue;
    const end = match.index + match[0].trimEnd().length;
    sentences.push(text.slice(start, end).trim());
    start = match.index + match[0].length;
  }
  const rest = text.slice(start).trim();
  if (rest) sentences.push(rest);
  return sentences;
};

/** Groups the sentences of a long single-block advisory into readable paragraphs. */
export const toParagraphs = (text: string): string[] => {
  if (text.length < PARAGRAPH_SPLIT_MIN) return [text];
  const paragraphs: string[] = [];
  let current = "";
  for (const sentence of splitSentences(text)) {
    current = current ? `${current} ${sentence}` : sentence;
    if (current.length >= PARAGRAPH_TARGET) {
      paragraphs.push(current);
      current = "";
    }
  }
  if (current) {
    if (paragraphs.length > 0 && current.length < PARAGRAPH_TAIL_MIN) {
      paragraphs[paragraphs.length - 1] += ` ${current}`;
    } else {
      paragraphs.push(current);
    }
  }
  return paragraphs;
};

/**
 * Advisory text is hard-wrapped, so it reflows to the measure: blank lines part
 * blocks, a block of bullet lines stays a list (one entry per line), and a long
 * block of prose is split into paragraphs at sentence ends.
 */
export const toAdvisoryBlocks = (text: string): string[][] =>
  cleanAdvisoryText(text)
    .split(/\n\s*\n/)
    .flatMap((block) => {
      const lines = block.split("\n").map((line) => line.trim()).filter(Boolean);
      if (lines.length === 0) return [];
      if (lines.every((line) => LIST_ITEM.test(line))) return [lines];
      return toParagraphs(lines.join(" ")).map((paragraph) => [paragraph]);
    });
