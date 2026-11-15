// Carries a search over when the vulnerability list switches between its three
// query modes (Keyword | DQL | Regex). Every conversion goes through the plain
// keyword text: keyword → DQL / regex always works, DQL / regex → keyword only
// when the query is plain text (DQL) or the exact shape this module writes
// (regex). Anything else returns null: there is no safe equivalent, and the
// caller starts the target mode empty instead of guessing.
//
// Backend reference: backend/app/services/vulnerability_service.py `_build_query`.
// - Keyword runs a `multi_match` (`bool_prefix`) over ids, title, summary,
//   vendors, products and versions.
// - DQL runs `query_string` with `default_field: "*"` and
//   `default_operator: "AND"`.
// - Regex runs one Lucene `regexp` per field of REGEX_SEARCH_FIELDS with
//   `case_insensitive: true`.

import type { QueryMode } from "./savedSearchQuery";

// Lucene query_string operators. Kept out of bare DQL terms; a term that
// contains one is quoted (keyword → DQL) or makes the DQL "not plain text"
// (DQL → keyword). `&` and `|` cover `&&` / `||`, `<>=` cover range shorthands.
const DQL_SPECIAL = new Set([
  "+", "-", "&", "|", "!", "(", ")", "{", "}", "[", "]", "^", '"', "~", "*", "?", ":", "\\", "/", "<", ">", "=",
]);
const DQL_OPERATORS = new Set(["AND", "OR", "NOT", "TO"]);

// Lucene regexp reserved characters (not PCRE): `. ? + * | { } [ ] ( ) " \ # @ & < > ~`.
const REGEX_RESERVED = new Set([
  ".", "?", "+", "*", "|", "{", "}", "[", "]", "(", ")", '"', "\\", "#", "@", "&", "<", ">", "~",
]);

const SAFE_BARE_DQL_TERM = /^[\p{L}\p{N}_.]+$/u;

const quoteDqlTerm = (word: string): string => `"${word.replace(/[\\"]/g, "\\$&")}"`;

// Keyword → DQL. The keyword search scores documents that match every word
// highest but technically ORs them (`multi_match` default operator). In DQL an
// OR of the words would turn "log4j 2.17" into every advisory that mentions
// 2.17, so the words are ANDed instead — what the top of the keyword results
// shows. A phrase ("log4j 2.17" in quotes) would be too strict: it needs the
// words adjacent in the same field. The words are joined by a space because
// the backend's `default_operator` is AND; a word with any Lucene special
// (`CVE-2021-44228`, `user:pass`, `a/b`) is quoted so it stays one term.
export const keywordToDql = (keyword: string): string =>
  keyword
    .trim()
    .split(/\s+/)
    .filter(Boolean)
    .map((word) => (SAFE_BARE_DQL_TERM.test(word) && !DQL_OPERATORS.has(word) ? word : quoteDqlTerm(word)))
    .join(" ");

// Keyword → regex: the escaped literal, wrapped as `.*literal.*` because a
// Lucene regexp must match the whole value (keyword fields) or the whole token
// (summary / title are analysed text). No case handling is needed: the backend
// sends every regexp with `case_insensitive: true`, so `.*log4j.*` finds
// "Log4j" and "LOG4J" just as the keyword search would. Known limit: summary
// and title are tokenised (english analyzer, stemmed), so a multi-word literal
// only hits whole-value fields (vendors, products, references, ids).
export const keywordToRegex = (keyword: string): string => {
  const literal = keyword.trim();
  if (!literal) return "";
  let escaped = "";
  for (const char of literal) {
    escaped += REGEX_RESERVED.has(char) ? `\\${char}` : char;
  }
  return `.*${escaped}.*`;
};

// DQL → keyword: only plain free text. Accepted: bare words without Lucene
// specials (`+`/`-` allowed inside a word, `\x` escapes unescaped), quoted
// phrases with only `\"` / `\\` escapes, and `AND` between terms (the default
// operator anyway). Fields, OR / NOT, groups, ranges, wildcards, fuzziness or
// boosts → null.
export const dqlToKeyword = (dql: string): string | null => {
  const text = dql.trim();
  if (!text) return "";
  const words: string[] = [];
  let pendingAnd = false;
  let i = 0;
  while (i < text.length) {
    if (/\s/.test(text[i])) {
      i += 1;
      continue;
    }
    if (text[i] === '"') {
      let phrase = "";
      let j = i + 1;
      let closed = false;
      while (j < text.length) {
        const char = text[j];
        if (char === "\\") {
          if (j + 1 >= text.length) return null;
          phrase += text[j + 1];
          j += 2;
          continue;
        }
        if (char === '"') {
          closed = true;
          break;
        }
        phrase += char;
        j += 1;
      }
      // Unterminated, or followed by `~2` / `^3` / anything but whitespace.
      if (!closed || (j + 1 < text.length && !/\s/.test(text[j + 1]))) return null;
      const cleaned = phrase.trim();
      if (!cleaned) return null;
      words.push(cleaned);
      pendingAnd = false;
      i = j + 1;
      continue;
    }
    let raw = "";
    while (i < text.length && !/\s/.test(text[i])) {
      raw += text[i];
      i += 1;
    }
    if (raw === "AND") {
      if (words.length === 0 || pendingAnd) return null;
      pendingAnd = true;
      continue;
    }
    if (DQL_OPERATORS.has(raw)) return null;
    let word = "";
    for (let k = 0; k < raw.length; k += 1) {
      const char = raw[k];
      if (char === "\\") {
        if (k + 1 >= raw.length) return null;
        word += raw[k + 1];
        k += 1;
        continue;
      }
      if (DQL_SPECIAL.has(char) && !(k > 0 && (char === "-" || char === "+"))) return null;
      word += char;
    }
    if (!word) return null;
    words.push(word);
    pendingAnd = false;
  }
  if (pendingAnd || words.length === 0) return null;
  return words.join(" ");
};

// Regex → keyword: only the `.*literal.*` shape keywordToRegex writes, with
// every reserved character escaped. Anything else is a real pattern → null.
export const regexToKeyword = (regex: string): string | null => {
  const text = regex.trim();
  if (!text) return "";
  if (text.length < 5 || !text.startsWith(".*") || !text.endsWith(".*")) return null;
  // `.*foo\.*` ends in an escaped dot, not in `.*`: its inner part ends in a
  // lone backslash, which the loop below rejects.
  const inner = text.slice(2, -2);
  let literal = "";
  for (let i = 0; i < inner.length; i += 1) {
    const char = inner[i];
    if (char === "\\") {
      if (i + 1 >= inner.length) return null;
      literal += inner[i + 1];
      i += 1;
      continue;
    }
    if (REGEX_RESERVED.has(char)) return null;
    literal += char;
  }
  const cleaned = literal.trim();
  return cleaned ? cleaned : null;
};

/**
 * Converts a query from one search mode to another. Returns "" for empty
 * input, the text unchanged when the modes are equal, and null when the source
 * query has no faithful equivalent in the target mode.
 */
export const convertQuery = (text: string, from: QueryMode, to: QueryMode): string | null => {
  if (!text.trim()) return "";
  if (from === to) return text;
  const keyword =
    from === "keyword" ? text.trim() : from === "dql" ? dqlToKeyword(text) : regexToKeyword(text);
  if (keyword === null) return null;
  if (to === "keyword") return keyword;
  return to === "dql" ? keywordToDql(keyword) : keywordToRegex(keyword);
};
