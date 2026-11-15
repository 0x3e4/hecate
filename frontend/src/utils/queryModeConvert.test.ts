import { describe, it, expect } from "vitest";

import {
  convertQuery,
  dqlToKeyword,
  keywordToDql,
  keywordToRegex,
  regexToKeyword,
} from "./queryModeConvert";

describe("keywordToDql", () => {
  it("keeps plain words bare and ANDs them through the default operator", () => {
    expect(keywordToDql("log4j")).toBe("log4j");
    expect(keywordToDql("  log4j   2.17 ")).toBe("log4j 2.17");
  });

  it("quotes a word with Lucene specials so it stays one term", () => {
    expect(keywordToDql("CVE-2021-44228")).toBe('"CVE-2021-44228"');
    expect(keywordToDql("vendor:apache")).toBe('"vendor:apache"');
    expect(keywordToDql("a/b (x)")).toBe('"a/b" "(x)"');
    expect(keywordToDql('say"hi\\')).toBe('"say\\"hi\\\\"');
  });

  it("quotes words that read as query operators", () => {
    expect(keywordToDql("rce OR xss")).toBe('rce "OR" xss');
    expect(keywordToDql("NOT")).toBe('"NOT"');
  });
});

describe("keywordToRegex", () => {
  it("wraps the escaped literal as a substring match", () => {
    expect(keywordToRegex("log4j")).toBe(".*log4j.*");
    expect(keywordToRegex("log4j 2.17")).toBe(".*log4j 2\\.17.*");
    expect(keywordToRegex("a+b|c")).toBe(".*a\\+b\\|c.*");
  });

  it("escapes every Lucene regexp reserved character", () => {
    expect(keywordToRegex('.?+*|{}[]()"\\#@&<>~')).toBe(
      '.*\\.\\?\\+\\*\\|\\{\\}\\[\\]\\(\\)\\"\\\\\\#\\@\\&\\<\\>\\~.*',
    );
  });

  it("leaves the case alone because the backend matches case-insensitively", () => {
    expect(keywordToRegex("Log4J")).toBe(".*Log4J.*");
  });

  it("does not escape characters Lucene regexp treats literally", () => {
    expect(keywordToRegex("CVE-2021-44228")).toBe(".*CVE-2021-44228.*");
    expect(keywordToRegex("^x$")).toBe(".*^x$.*");
  });
});

describe("dqlToKeyword", () => {
  it("unquotes plain free text", () => {
    expect(dqlToKeyword("log4j 2.17")).toBe("log4j 2.17");
    expect(dqlToKeyword('"CVE-2021-44228"')).toBe("CVE-2021-44228");
    expect(dqlToKeyword('"log4j 2.17" AND openssl')).toBe("log4j 2.17 openssl");
    expect(dqlToKeyword("CVE-2021-44228")).toBe("CVE-2021-44228");
    expect(dqlToKeyword("foo\\:bar")).toBe("foo:bar");
    expect(dqlToKeyword('"say\\"hi"')).toBe('say"hi');
  });

  it("refuses fields, operators, groups, ranges and wildcards", () => {
    expect(dqlToKeyword("vuln_id:CVE-2024-*")).toBeNull();
    expect(dqlToKeyword("rce OR xss")).toBeNull();
    expect(dqlToKeyword("NOT rce")).toBeNull();
    expect(dqlToKeyword("-rce")).toBeNull();
    expect(dqlToKeyword("(rce)")).toBeNull();
    expect(dqlToKeyword("[1 TO 5]")).toBeNull();
    expect(dqlToKeyword("log4*")).toBeNull();
    expect(dqlToKeyword("rce~2")).toBeNull();
    expect(dqlToKeyword('"log4j"~2')).toBeNull();
    expect(dqlToKeyword('"open')).toBeNull();
    expect(dqlToKeyword("/regex/")).toBeNull();
    expect(dqlToKeyword("a && b")).toBeNull();
  });

  it("refuses a dangling AND", () => {
    expect(dqlToKeyword("AND rce")).toBeNull();
    expect(dqlToKeyword("rce AND")).toBeNull();
    expect(dqlToKeyword("rce AND AND xss")).toBeNull();
  });
});

describe("regexToKeyword", () => {
  it("unescapes the shape keywordToRegex writes", () => {
    expect(regexToKeyword(".*log4j.*")).toBe("log4j");
    expect(regexToKeyword(".*log4j 2\\.17.*")).toBe("log4j 2.17");
    expect(regexToKeyword(".*a\\\\.*")).toBe("a\\");
  });

  it("refuses real patterns", () => {
    expect(regexToKeyword("(injection|rce|xss)")).toBeNull();
    expect(regexToKeyword("log4j")).toBeNull();
    expect(regexToKeyword(".*log4j")).toBeNull();
    expect(regexToKeyword(".*log.j.*")).toBeNull();
    expect(regexToKeyword(".*foo\\.*")).toBeNull();
    expect(regexToKeyword(".*.*")).toBeNull();
    expect(regexToKeyword(".* .*")).toBeNull();
  });
});

describe("convertQuery", () => {
  it("returns empty for empty input in every direction", () => {
    expect(convertQuery("", "keyword", "dql")).toBe("");
    expect(convertQuery("   ", "dql", "regex")).toBe("");
    expect(convertQuery("", "regex", "keyword")).toBe("");
  });

  it("returns the text unchanged for the same mode", () => {
    expect(convertQuery("a:b OR c", "dql", "dql")).toBe("a:b OR c");
  });

  it("converts keyword to DQL and regex", () => {
    expect(convertQuery("CVE-2021-44228", "keyword", "dql")).toBe('"CVE-2021-44228"');
    expect(convertQuery("log4j 2.17", "keyword", "regex")).toBe(".*log4j 2\\.17.*");
  });

  it("converts plain DQL to regex and its own regex shape to DQL", () => {
    expect(convertQuery('"CVE-2021-44228"', "dql", "regex")).toBe(".*CVE-2021-44228.*");
    expect(convertQuery(".*CVE-2021-44228.*", "regex", "dql")).toBe('"CVE-2021-44228"');
  });

  it("round-trips keyword through both modes", () => {
    for (const keyword of ["log4j", "CVE-2021-44228", "log4j 2.17", "a+b (c)"]) {
      expect(convertQuery(convertQuery(keyword, "keyword", "regex")!, "regex", "keyword")).toBe(keyword);
      expect(convertQuery(convertQuery(keyword, "keyword", "dql")!, "dql", "keyword")).toBe(keyword);
    }
  });

  it("returns null when there is no safe equivalent", () => {
    expect(convertQuery("vendorSlugs:\"apache\"", "dql", "keyword")).toBeNull();
    expect(convertQuery("vendorSlugs:\"apache\"", "dql", "regex")).toBeNull();
    expect(convertQuery("(rce|xss)", "regex", "keyword")).toBeNull();
    expect(convertQuery("(rce|xss)", "regex", "dql")).toBeNull();
  });
});
