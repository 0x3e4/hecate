from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable

import structlog

from app.models.vulnerability import CpeConfiguration, CpeMatch, CpeNode
from app.utils.strings import slugify

log = structlog.get_logger()


# --- Version comparison ---
#
# Hecate stores versions as free-form strings; CVE CPE configurations use the
# same format. We don't depend on ``packaging.version`` because it isn't a
# pinned backend dependency, so we ship a small self-contained comparator that
# handles the common cases seen in CPE data:
#
# - Dotted numeric strings (``1.2.3``, ``8.0.25``)
# - Pre-release suffixes separated by ``-`` or ``_`` (``8.0.25-preview.1``)
#   Pre-releases compare *less than* the same base version without a suffix.
# - Wildcards at the end (``8.0.*``) which expand to a half-open range.
#
# For version tokens that don't parse cleanly we fall back to case-folded
# lexicographic compare. That's not perfect for every ecosystem but it never
# raises, and the matcher is intentionally fail-closed (a version we can't
# compare is treated as *not* matching, see ``_compare_versions``).

_SEGMENT_SPLIT_RE = re.compile(r"[._-]")
_NUMERIC_RE = re.compile(r"^\d+$")

# Splitter used only by the branch-scoped helpers below (see
# ``_BRANCH_SCOPED_PRODUCTS``) -- unlike ``_SEGMENT_SPLIT_RE`` this also
# treats comma and whitespace as segment separators, so a value entered as
# "14.1, 66.59" tokenizes the same as "14.1.66.59".
_BRANCH_SPLIT_RE = re.compile(r"[.,_\s-]+")

# (vendor_slug, product_slug) -> number of leading dotted segments that form
# the release "branch" identifier. Confirmed: Citrix NetScaler ADC/Gateway
# run an INDEPENDENT build counter per branch, so a CVE's per-branch clause
# ">= 14.1, < 56.73" means "branch 14.1, build < 56.73" -- not "version >=
# 14.1 AND < 56.73 on one linear scale". Add an entry only when you've
# confirmed the vendor's CVE data uses this convention; anyone not in this
# table keeps the ordinary single-scale comparison.
_BRANCH_SCOPED_PRODUCTS: dict[tuple[str, str], int] = {
    ("netscaler", "adc"): 2,
    ("netscaler", "gateway"): 2,
}


@dataclass(frozen=True)
class ParsedVersion:
    """A comparable representation of a version string.

    ``release`` holds the numeric components (``8.0.25`` → ``(8, 0, 25)``).
    ``pre`` is ``()`` for final releases and a tuple for pre-releases that
    sorts *before* the empty tuple by convention (see ``_tuple_for_compare``).
    ``raw`` is the original string for lexicographic fallback.
    ``valid`` is True when the *entire* release portion (up to the first
    ``-``) parsed as numeric dot/underscore/dash-delimited segments, with no
    trailing non-numeric garbage.
    """

    release: tuple[int, ...]
    pre: tuple[Any, ...]
    raw: str
    valid: bool
    # Suffix that sorts *after* the release: OpenSSL letters (1.0.2k < 1.0.2l
    # < 1.0.2za), Arista trains (4.26.9M), PEP 440 ".postN".
    post: tuple[Any, ...] = ()


# A suffix glued to the last release segment ("2k", "9M", "0b1", "0rc1"). PEP
# 440 pre-releases carry a number or a spelled-out tag; a bare one- or
# two-letter suffix is an OpenSSL / Arista style release *after* the number.
_GLUED_SUFFIX_RE = re.compile(r"^(?P<num>\d+)(?P<tag>[A-Za-z]+)(?P<n>\d*)$")
_PRE_TAGS_NEED_NUMBER = {"a", "b", "c"}
_PRE_TAGS = {"alpha", "beta", "rc", "pre", "preview", "dev"}


def _glued_suffix(token: str) -> tuple[int, str, tuple[Any, ...]] | None:
    """``"0rc1"`` -> ``(0, "pre", ((0, "rc"), (1, 1)))``; ``"2k"`` -> ``(2, "post", ((0, "k"),))``."""
    match = _GLUED_SUFFIX_RE.match(token)
    if not match:
        return None
    num = int(match.group("num"))
    tag = match.group("tag").lower()
    number = match.group("n")
    tokens: tuple[Any, ...] = ((0, tag),) + (((1, int(number)),) if number else ())
    if tag in _PRE_TAGS or (tag in _PRE_TAGS_NEED_NUMBER and number):
        return num, "pre", tokens
    if tag == "post" and number:
        return num, "post", tokens
    if not number and len(tag) <= 2:
        return num, "post", tokens
    return None


def parse_version(raw: str) -> ParsedVersion:
    """Parse a version string into a ``ParsedVersion``.

    Never raises — returns a ``ParsedVersion`` with ``valid=False`` if the
    string doesn't start with a numeric segment.
    """
    if raw is None:
        return ParsedVersion(release=(), pre=(), raw="", valid=False)
    text = str(raw).strip()
    if not text:
        return ParsedVersion(release=(), pre=(), raw="", valid=False)

    # Strip leading "v" / "V" prefix commonly seen in tags.
    if text[0] in ("v", "V"):
        text = text[1:]

    # Split release and pre-release at the first dash (after any version suffix
    # separators). ``8.0.25-preview.1`` → release ``8.0.25``, pre ``preview.1``.
    release_part, _, pre_part = text.partition("-")

    release_tokens = [t for t in _SEGMENT_SPLIT_RE.split(release_part) if t]
    release_ints: list[int] = []
    valid = True
    glued_kind: str | None = None
    glued_tokens: tuple[Any, ...] = ()
    for index, token in enumerate(release_tokens):
        if _NUMERIC_RE.match(token):
            release_ints.append(int(token))
            continue
        glued = _glued_suffix(token) if index == len(release_tokens) - 1 and index > 0 else None
        if glued is not None:
            release_ints.append(glued[0])
            glued_kind, glued_tokens = glued[1], glued[2]
            continue
        # Trailing garbage after the numeric prefix (e.g. a stray comma
        # from a malformed "14.1, 66.59" value) makes the whole version
        # incomparable -- fail closed rather than silently truncating.
        valid = False
        break

    pre_tokens: tuple[Any, ...] = ()
    if pre_part:
        segs: list[Any] = []
        for token in _SEGMENT_SPLIT_RE.split(pre_part):
            if not token:
                continue
            if _NUMERIC_RE.match(token):
                segs.append((1, int(token)))
            else:
                segs.append((0, token.lower()))
        pre_tokens = tuple(segs)

    post_tokens: tuple[Any, ...] = ()
    if glued_kind == "pre":
        # "12.4.0b1-foo" is not a shape anyone writes; keep the glued tag first.
        pre_tokens = glued_tokens + pre_tokens
    elif glued_kind == "post":
        post_tokens = glued_tokens

    return ParsedVersion(
        release=tuple(release_ints),
        pre=pre_tokens,
        raw=text,
        valid=valid,
        post=post_tokens,
    )


def _phase(v: ParsedVersion) -> tuple[int, tuple[Any, ...]]:
    """Order within one release: pre-release < final < post-release.

    ``8.0.25-preview.1 < 8.0.25 < 8.0.25a`` (OpenSSL letters come after).
    """
    if v.pre:
        return 0, v.pre
    if v.post:
        return 2, v.post
    return 1, ()


def _tuple_for_compare(v: ParsedVersion) -> tuple[Any, ...]:
    """Return a tuple ordering release first, then :func:`_phase`.

    When comparing releases of different length we right-pad the shorter with
    zeros so ``8.0`` == ``8.0.0``.
    """
    return (v.release, *_phase(v))


def _pad(a: tuple[int, ...], b: tuple[int, ...]) -> tuple[tuple[int, ...], tuple[int, ...]]:
    length = max(len(a), len(b))
    return (a + (0,) * (length - len(a)), b + (0,) * (length - len(b)))


def _compare_versions(left: str, right: str) -> int | None:
    """Return -1/0/1 if ``left`` can be compared against ``right``, else ``None``.

    ``None`` means the comparison is undecidable — callers should treat the
    match as failed rather than guessing.
    """
    lv = parse_version(left)
    rv = parse_version(right)
    if not lv.valid or not rv.valid:
        # Fall back to case-insensitive string equality only. Ordering on
        # arbitrary strings is meaningless for version ranges and would cause
        # false positives.
        if lv.raw.lower() == rv.raw.lower():
            return 0
        return None
    la, ra = _pad(lv.release, rv.release)
    if la != ra:
        return -1 if la < ra else 1
    lt, rt = _phase(lv), _phase(rv)
    if lt == rt:
        return 0
    return -1 if lt < rt else 1


# --- Sort keys for the OpenSearch range index ---
#
# The index used to fold versions into one long (four segments, base 10000).
# Segments above 9999 were capped, so Windows builds 10.0.19044 and 10.0.19045
# collided, and pre-releases and letter suffixes could not be stored at all.
# A keyword whose byte order equals ``_compare_versions`` fixes all three, and
# OpenSearch range queries on keywords compare exactly that way:
#
#   * trailing zero segments are dropped (8.0.0 == 8.0 == 8),
#   * each segment is its digit count followed by the digits, so 9 < 10 < 100,
#   * "." separates segments and "!" ends the release; "!" sorts below ".",
#     so 8 (any phase) < 8.0.1,
#   * then "0" + pre tokens, "1" for a final release, or "2" + post tokens;
#     within tokens text sorts before numbers, like ``_phase``.
#
# Keys only use "!", ".", digits, ":"-"?" (long digit counts) and lowercase
# letters; " " sorts below all of them, so ``key + " "`` is the first key after
# ``key`` (used for exclusive starts and inclusive ends) and "~" sorts above
# every key (no upper bound).

KEY_AFTER = " "
KEY_MAX = "~"


def _key_number(value: int) -> str:
    digits = str(value)
    if len(digits) > 40:
        raise ValueError("version segment too long")
    return chr(ord("0") + len(digits)) + digits


def _key_tokens(tokens: tuple[Any, ...]) -> str:
    parts = []
    for kind, value in tokens:
        parts.append("1" + _key_number(value) if kind == 1 else "0" + value)
    return ".".join(parts)


def version_sort_key(value: str | None) -> str | None:
    """Keyword whose order matches :func:`_compare_versions`; ``None`` if unusable.

    Versions the matcher can only compare by string (``valid=False``) have no
    key; neither does a token with characters outside the key alphabet.
    """
    if not value:
        return None
    parsed = parse_version(value)
    if not parsed.valid or not parsed.release:
        return None
    release = list(parsed.release)
    while release and release[-1] == 0:
        release.pop()
    try:
        key = ".".join(_key_number(seg) for seg in release) + "!"
        if parsed.pre:
            key += "0" + _key_tokens(parsed.pre)
        elif parsed.post:
            key += "2" + _key_tokens(parsed.post)
        else:
            key += "1"
    except ValueError:
        return None
    if not all(ch.isdigit() or ch in "!.:;<=>?" or "a" <= ch <= "z" for ch in key):
        return None
    return key


# --- CPE match evaluation ---


@dataclass(frozen=True)
class InventoryKey:
    """The lookup key for an inventory item against CVE data."""

    vendor_slug: str
    product_slug: str
    version: str


def _slug(value: Any) -> str:
    """Normalize a slug the same way the asset catalog does.

    The asset catalog normalizer (``app.utils.strings.slugify``) collapses
    non-alphanumerics to ``-`` and lowercases. Using the same helper here
    ensures CPE-sourced tokens like ``.net_8.0`` and inventory slugs like
    ``net-8-0`` compare equal.
    """
    if not isinstance(value, str):
        return ""
    trimmed = value.strip()
    if not trimmed:
        return ""
    return slugify(trimmed)


def _extract_version_from_cpe(criteria: str | None) -> str | None:
    """Extract the version field (6th component) from a CPE 2.3 URI."""
    if not criteria or not isinstance(criteria, str):
        return None
    if not criteria.startswith("cpe:2.3:"):
        return None
    parts = criteria.split(":")
    if len(parts) < 6:
        return None
    version = parts[5]
    if version in ("", "*", "-", "ANY", "NA"):
        return None
    return version


def _expand_wildcard(version: str) -> tuple[str, str] | None:
    """Expand ``8.0.*`` into a half-open range ``[8.0, 8.1)``.

    Returns ``None`` for non-wildcard inputs.
    """
    if not version.endswith(".*"):
        return None
    prefix = version[:-2]
    tokens = prefix.split(".")
    if not tokens or not tokens[-1].isdigit():
        return None
    lower = ".".join(tokens)
    upper_tokens = tokens[:-1] + [str(int(tokens[-1]) + 1)]
    upper = ".".join(upper_tokens)
    return lower, upper


def _versions_equivalent(item_version: str, cpe_version: str) -> bool:
    cmp = _compare_versions(item_version, cpe_version)
    if cmp is not None:
        return cmp == 0
    # Handle wildcard in the item version against an exact CPE version.
    wc = _expand_wildcard(item_version)
    if wc is not None:
        lower, upper = wc
        return _compare_bounds(cpe_version, start_in=lower, start_ex=None, end_in=None, end_ex=upper)
    return False


def _compare_bounds(
    version: str,
    *,
    start_in: str | None,
    start_ex: str | None,
    end_in: str | None,
    end_ex: str | None,
) -> bool:
    """Return True if ``version`` falls within the supplied half-open bounds."""

    def _cmp_or_fail(a: str, b: str) -> int | None:
        return _compare_versions(a, b)

    # Expand a wildcard item version by comparing both edges of the implied
    # range against the CPE bounds. If *any* concrete version inside the item
    # range satisfies the CPE bounds we consider it a match.
    wc = _expand_wildcard(version)
    if wc is not None:
        lower, upper = wc
        # A wildcard range [lower, upper) intersects [start, end] iff
        #   lower < end(+ε)  and  upper > start(−ε)
        #
        # We approximate "(−/+ ε)" by treating the inclusive bounds as
        # equivalence and the exclusive bounds as strict.
        if end_in is not None:
            cmp_val = _cmp_or_fail(lower, end_in)
            if cmp_val is None or cmp_val > 0:
                return False
        if end_ex is not None:
            cmp_val = _cmp_or_fail(lower, end_ex)
            if cmp_val is None or cmp_val >= 0:
                return False
        if start_in is not None:
            cmp_val = _cmp_or_fail(upper, start_in)
            if cmp_val is None or cmp_val <= 0:
                return False
        if start_ex is not None:
            cmp_val = _cmp_or_fail(upper, start_ex)
            if cmp_val is None or cmp_val <= 0:
                return False
        return True

    # Concrete version — evaluate each bound directly.
    if start_in is not None:
        cmp_val = _cmp_or_fail(version, start_in)
        if cmp_val is None or cmp_val < 0:
            return False
    if start_ex is not None:
        cmp_val = _cmp_or_fail(version, start_ex)
        if cmp_val is None or cmp_val <= 0:
            return False
    if end_in is not None:
        cmp_val = _cmp_or_fail(version, end_in)
        if cmp_val is None or cmp_val > 0:
            return False
    if end_ex is not None:
        cmp_val = _cmp_or_fail(version, end_ex)
        if cmp_val is None or cmp_val >= 0:
            return False
    return True


# --- Version-range-string parser (for `impacted_products[].versions`) ---
#
# EUVD-style range strings look like:
#   - "1.2.3"              (exact)
#   - ">= 1.0.0, < 5.0.9"  (half-open range, AND semantics)
#   - "< 5.0.9"            (only upper bound)
#   - ">= 5.1.0, < 5.1.3"  (half-open range)
#   - "*" / "" / "-"       (unconstrained — we ignore these)
#
# A single ``versions: [...]`` list is evaluated with OR semantics: if *any*
# range string in the list matches the user's version, the item is vulnerable.

_VERSION_OP_RE = re.compile(
    r"(?P<op>>=|<=|!=|==|>|<|=)?\s*(?P<ver>[A-Za-z0-9][\w.+:\-*]*)"
)

# Broad, unconstrained range strings that effectively mean "all versions".
# These carry no usable version information, so we fail closed rather than
# match every version. ``>=0`` / ``>0`` are the "from zero upwards" sentinels
# emitted by EUVD / MAL normalization — the same set the rest of the codebase
# treats as broad (see ``_BROAD_VERSION_SENTINELS`` in vulnerability_service).
_BROAD_RANGE_SENTINELS = {
    "",
    "*",
    "-",
    "any",
    ">=0",
    ">= 0",
    ">0",
    "> 0",
    # EUVD writes a literal "n/a" when it has no version bound at all. Left
    # unhandled it parsed as the exact version "n" (the clause scanner stops at
    # the first non-version character), which matched nothing and read as a
    # deliberate constraint rather than missing data.
    "n/a",
    "na",
    "n.a.",
    "unknown",
    "?",
}


def _is_zero_version(value: str | None) -> bool:
    """True when ``value`` is empty or parses to an all-zero release (``0``, ``0.0``)."""
    if not value:
        return True
    parsed = parse_version(value)
    return not parsed.release or all(seg == 0 for seg in parsed.release)


# EUVD ships a chunk of its ``product_version`` strings with typographic
# comparison glyphs and an implicit lower bound rather than the ASCII
# ``">= a, <= b"`` shape ``_format_version_range`` emits:
#
#   "4.7 ≤4.7.30"     -> from 4.7 through 4.7.30
#   "0 ≤2.4.7"        -> everything up to and including 2.4.7
#   "n/a ≤6.8.2"      -> upper bound only, lower unspecified
#   "n/a ≤≤ 1.50.2"   -> same, with a doubled operator
#
# Without normalization the clause scanner reads only the leading token and
# reports ``[("=", "4.7")]`` — "exactly 4.7" — so an advisory covering the
# whole 4.7.x line matches nothing but 4.7 itself. That silently suppressed
# inventory matches for most EUVD-sourced advisories.
_UNICODE_OP_MAP = {
    "≤": "<=",
    "⩽": "<=",
    "≦": "<=",
    "≥": ">=",
    "⩾": ">=",
    "≧": ">=",
    "＜": "<",
    "＞": ">",
    "－": "-",
}

# "<=<=" / ">=>" and friends: keep only the last operator in a run.
_DUP_OP_RE = re.compile(r"(?:<=|>=|<|>)\s*(?=<=|>=|<|>)")

# "<bare token> <op> <version>" — an implicit lower bound.
_IMPLICIT_RANGE_RE = re.compile(
    r"^\s*(?P<low>[^\s<>=,]+)\s*(?P<op><=|<)\s*(?P<high>[^\s<>=,]+)\s*$"
)

# Whitespace-separated clauses (">=12.0.0 <12.0.5"): a version token, then
# whitespace, then another operator.
_LEADING_OP_RE = re.compile(r"^\s*(?:<=|>=|==|!=|<|>|=)")
_SPACE_BEFORE_OP_RE = re.compile(r"(?<=[\w*+.])\s+(?=(?:<=|>=|==|!=|<|>|=))")

# Lower-bound placeholders that carry no version information.
_IMPLICIT_LOWER_PLACEHOLDERS = {"n/a", "na", "n.a.", "*", "-", "any", "unknown", "?"}


def _normalize_range_string(value: str) -> str:
    """Rewrite typographic / implicit range shapes into the ASCII clause form."""
    s = (value or "").strip()
    if not s:
        return s
    for glyph, ascii_op in _UNICODE_OP_MAP.items():
        if glyph in s:
            s = s.replace(glyph, ascii_op)
    s = _DUP_OP_RE.sub("", s)

    match = _IMPLICIT_RANGE_RE.match(s)
    if match:
        low = match.group("low")
        op = match.group("op")
        high = match.group("high")
        # A placeholder or all-zero lower bound adds nothing; keeping it as
        # ">= 0" would also trip the unconstrained guard downstream.
        if low.lower() in _IMPLICIT_LOWER_PLACEHOLDERS or _is_zero_version(low):
            return f"{op} {high}"
        return f">= {low}, {op} {high}"
    # OSV / GHSA write ">=12.0.0 <12.0.5": clauses separated by a space, not a
    # comma. Split only splits on commas, so the upper bound vanished and the
    # range read as ">= 12.0.0" with no ceiling, matching every later release.
    if _LEADING_OP_RE.match(s):
        s = _SPACE_BEFORE_OP_RE.sub(", ", s)
    return s


def _parse_range_clauses(range_str: str) -> list[tuple[str, str]]:
    """Split a range string into ``(op, version)`` clauses.

    ``">= 1.0.0, < 5.0.9"`` -> ``[(">=", "1.0.0"), ("<", "5.0.9")]``. Returns
    ``[]`` for broad sentinels / unconstrained / unparseable input.

    Input is normalized first (see ``_normalize_range_string``) so EUVD's
    ``"4.7 ≤4.7.30"`` shape is understood as the range it actually denotes.
    """
    s = _normalize_range_string(range_str or "")
    if not s or s.lower() in _BROAD_RANGE_SENTINELS:
        return []

    clauses: list[tuple[str, str]] = []
    for part in (p.strip() for p in s.split(",")):
        if not part:
            continue
        match = _VERSION_OP_RE.match(part)
        if not match:
            continue
        op = match.group("op") or "="
        ver = match.group("ver")
        clauses.append((op, ver))
    return clauses


def _split_numeric_segments(text: str | None) -> tuple[int, ...] | None:
    """Split ``text`` on ``_BRANCH_SPLIT_RE`` and require every token to be
    numeric. Returns ``None`` on empty input or any non-numeric token (fail
    closed) -- used where a complete, unambiguous parse is required (the item
    version, and a range clause's end/threshold bound).
    """
    if not text:
        return None
    tokens = [t for t in _BRANCH_SPLIT_RE.split(text.strip()) if t]
    if not tokens:
        return None
    result: list[int] = []
    for token in tokens:
        if not _NUMERIC_RE.match(token):
            return None
        result.append(int(token))
    return tuple(result)


def _leading_numeric_segments(text: str | None, count: int) -> tuple[int, ...] | None:
    """Return the first ``count`` numeric segments of ``text``, tolerating
    non-numeric trailing content (e.g. the "-FIPS" suffix on a branch label
    like "12.1-FIPS"). Returns ``None`` if fewer than ``count`` numeric
    segments are found before hitting non-numeric content.
    """
    if not text:
        return None
    tokens = [t for t in _BRANCH_SPLIT_RE.split(text.strip()) if t]
    result: list[int] = []
    for token in tokens:
        if not _NUMERIC_RE.match(token):
            break
        result.append(int(token))
        if len(result) == count:
            break
    if len(result) < count:
        return None
    return tuple(result)


def _version_in_branch_scoped_range(version: str, range_str: str, branch_segments: int) -> bool:
    """Evaluate a range clause for vendors whose CVE data encodes an
    INDEPENDENT build counter per release branch (see
    ``_BRANCH_SCOPED_PRODUCTS``). A clause of the form ">= <branch>, <
    <threshold>" is treated as "branch must match exactly; build must be
    below threshold" rather than a single-scale comparison of the whole
    version -- otherwise an unrelated branch's threshold can numerically
    (and incorrectly) bound a different branch's build number.

    Clauses that aren't the "branch + threshold" shape (an exact version, or
    an unbounded-below-only clause like ">= 14.1" with no upper bound) have
    no branch role to play and fall back to the ordinary whole-scale
    comparison unchanged -- this is a deliberate asymmetry, not an oversight.
    """
    clauses = _parse_range_clauses(range_str)
    if not clauses:
        return False

    start_bound: str | None = None
    end_in: str | None = None
    end_ex: str | None = None
    for op, ver in clauses:
        if op in (">=", ">"):
            start_bound = ver
        elif op == "<=":
            end_in = ver
        elif op == "<":
            end_ex = ver

    if start_bound is None or (end_in is None and end_ex is None):
        return _version_in_range_string(version, range_str)

    item_all = _split_numeric_segments(version)
    if item_all is None or len(item_all) <= branch_segments:
        return False  # no branch+build info, or nothing beyond the branch

    item_branch, item_build = item_all[:branch_segments], item_all[branch_segments:]

    clause_branch = _leading_numeric_segments(start_bound, branch_segments)
    if clause_branch is None or item_branch != clause_branch:
        return False  # different branch (or unparseable) -- clause doesn't apply

    end_bound = end_ex if end_ex is not None else end_in
    end_all = _split_numeric_segments(end_bound)
    if end_all is None:
        return False
    if len(end_all) > branch_segments:
        # Fully-qualified end bound (branch repeated, e.g. "14.1.56.73") --
        # verify it's consistent with the clause's own branch, then strip it.
        if end_all[:branch_segments] != clause_branch:
            log.debug(
                "inventory_matcher.branch_scoped_end_bound_mismatch",
                range_str=range_str,
            )
            return False
        end_build = end_all[branch_segments:]
    else:
        end_build = end_all  # bare build threshold, used as-is

    a, b = _pad(item_build, end_build)
    return a < b if end_ex is not None else a <= b


@dataclass(frozen=True)
class VersionSpan:
    """One affected interval with string bounds (``None`` = unbounded side).

    Shared currency between this matcher and the OpenSearch range index
    (``app.services.version_ranges``): both turn every range source into spans,
    run them through :func:`effective_spans`, and then either compare a version
    against them or encode them as integers. Doing the branch scoping once, on
    strings, is what keeps the inventory pages and ``affectedVersion:`` queries
    from disagreeing.
    """

    start: str | None = None
    start_inclusive: bool = True
    end: str | None = None
    end_inclusive: bool = False

    def contains(self, version: str) -> bool:
        return _compare_bounds(
            version,
            start_in=self.start if self.start_inclusive else None,
            start_ex=None if self.start_inclusive else self.start,
            end_in=self.end if self.end_inclusive else None,
            end_ex=None if self.end_inclusive else self.end,
        )


def _span_from_bounds(
    *,
    start_in: str | None,
    start_ex: str | None,
    end_in: str | None,
    end_ex: str | None,
) -> VersionSpan | None:
    """Fold the four bound slots into one span; ``None`` when all are empty.

    When both an inclusive and an exclusive bound sit on the same side (never
    seen in real data) the tighter one wins, which is what evaluating both as
    an AND did before.
    """
    start, start_inclusive = start_in, True
    if start_ex is not None:
        cmp = _compare_versions(start_ex, start_in) if start_in is not None else 1
        if cmp is None or cmp >= 0:
            start, start_inclusive = start_ex, False
    end, end_inclusive = end_ex, False
    if end_in is not None:
        cmp = _compare_versions(end_in, end_ex) if end_ex is not None else -1
        if cmp is not None and cmp < 0:
            end, end_inclusive = end_in, True
    if start is None and end is None:
        return None
    return VersionSpan(start, start_inclusive, end, end_inclusive)


def _parse_range(range_str: str) -> tuple[tuple[str, ...], VersionSpan | None]:
    """Split one range string into ``(exact pins, span)``.

    ``"1.2.3"`` -> ``(("1.2.3",), None)``; ``">= 1.0, < 2.0"`` -> ``((), span)``.
    Broad / unconstrained strings (``*``, ``>=0``, ``>= 0.0``, empty) give
    ``((), None)``: they carry no version information and must not match.
    """
    clauses = _parse_range_clauses(range_str)
    if not clauses:
        return (), None

    start_in: str | None = None
    start_ex: str | None = None
    end_in: str | None = None
    end_ex: str | None = None
    exact_values: list[str] = []
    for op, ver in clauses:
        if op in ("=", "=="):
            exact_values.append(ver)
        elif op == ">=":
            start_in = ver
        elif op == ">":
            start_ex = ver
        elif op == "<=":
            end_in = ver
        elif op == "<":
            end_ex = ver
        # != is ignored — we don't model exclusions

    # Exact equality takes precedence when present (a plain "1.2.3" with no
    # relational operators).
    if not any((start_in, start_ex, end_in, end_ex)):
        return tuple(exact_values), None

    # A lower bound at version 0 with no upper bound (``>= 0`` / ``> 0`` in any
    # spacing) is "all versions" — unconstrained, so fail closed. A non-zero
    # standalone ``>= 5.1.0`` is intentionally left alone ("from 5.1.0 upwards").
    if end_in is None and end_ex is None and _is_zero_version(
        start_in if start_in is not None else start_ex
    ):
        return (), None

    return (), _span_from_bounds(start_in=start_in, start_ex=start_ex, end_in=end_in, end_ex=end_ex)


def _version_in_range_string(version: str, range_str: str) -> bool:
    """Return True if ``version`` satisfies the single range ``range_str``.

    Unknown or unconstrained strings (``*``, ``-``, ``>=0``, empty) return
    False — they provide no usable information and we fail closed rather than
    match everything. Evaluates one string in isolation; a product's whole
    version list goes through :func:`version_in_ranges`, which also applies the
    release-branch rule.
    """
    exact, span = _parse_range(range_str)
    if exact:
        return any(_compare_versions(version, v) == 0 for v in exact)
    return span is not None and span.contains(version)


# --- Release-branch scoping ---
#
# Every range used to sit on one shared axis. Products that maintain several
# release lines publish one fix per line, so a version that is fixed on its own
# line still fell into a range meant for another one:
#
#   nginx CVE-2026-90439:  ">= 1.29.2, < 1.31.6", ">= 1.30.4, < 1.30.5"
#       1.30.6 is fixed (stable 1.30.x got 1.30.5) but sits inside the first range.
#   Redis CVE-2026-81934:  "< 6.2.24", "< 7.2.16", "< 7.4.11", "< 8.10.1", …
#       the CVE record itself says {"version": "0", "lessThan": X} per line, so
#       7.4.12 matched "< 8.10.1".
#
# Rule (taken over from the nohub.lol audit): the branch of a version is its
# first two segments. A range belongs to branch B when it has an upper bound
# and all of its bounds lie on B (">= 1.30.4, < 1.30.5"). A bare upper bound
# ("< 7.4.11") counts only when the same product lists another upper bound on
# a different branch, so a lone "< 3.0" keeps meaning "everything older". When
# the product has such a range for B, only those ranges (plus exact pins)
# decide for versions on B; every other version is compared as before.
#
# Implemented as a rewrite of the spans rather than a query-time check so the
# OpenSearch index can store the result and keep its one-clause query:
#   * a branch range is clipped to its branch: "< 7.4.11" -> [7.4, 7.4.11)
#   * every range additionally keeps what lies outside all branches that have
#     their own range: [1.29.2, 1.31.6) -> [1.29.2, 1.30) + [1.31, 1.31.6)
# For a version on branch B that has its own range only the clipped branch
# ranges can contain it; for any other version only the second part can, and
# that part equals the original ranges there. That is exactly the rule above.
#
# Branch depth: two segments by default. When every upper bound of the product
# sits on a different major (Node "< 20.18.2", "< 22.12.1"; .NET ">= 8.0.0,
# < 8.0.33", ">= 9.0.0, < 9.0.22"), the vendor ships one line per major and the
# branch is the major alone; with two segments Node 20.19.0, above the 20.x fix,
# would still have fallen into "< 22.12.1". Bounds at a branch start ("< 3.0")
# don't count towards that decision. Redis (7.2 and 7.4, 8.2 and 8.10) and nginx
# (1.30 and 1.31) share majors and stay at two.


def _branch_key(version: str | None, depth: int = 2) -> tuple[int, ...] | None:
    if not version:
        return None
    parsed = parse_version(version)
    if not parsed.valid or not parsed.release:
        return None
    release = parsed.release + (0,) * depth
    return tuple(release[:depth])


def _branch_window(key: tuple[int, ...]) -> tuple[str, str]:
    upper = key[:-1] + (key[-1] + 1,)
    return ".".join(map(str, key)), ".".join(map(str, upper))


def _above_branch_start(end: str, key: tuple[int, ...]) -> bool:
    """"< 7.4" / "< 7.4.0" ends where branch 7.4 starts: "everything before 7.4"."""
    cmp = _compare_versions(end, _branch_window(key)[0])
    return cmp is not None and cmp > 0


def _branch_depth(spans: list[VersionSpan]) -> int:
    majors: list[tuple[int, ...]] = []
    for span in spans:
        if span.end is None:
            continue
        key = _branch_key(span.end, 1)
        if key is not None and _above_branch_start(span.end, key):
            majors.append(key)
    if len(majors) >= 2 and len(set(majors)) == len(majors):
        return 1
    return 2


def _scoped_branch(
    span: VersionSpan, spans: list[VersionSpan], depth: int = 2
) -> tuple[int, ...] | None:
    """The branch ``span`` belongs to under the rule above, or ``None``."""
    if span.end is None:
        return None
    key = _branch_key(span.end, depth)
    if key is None or not _above_branch_start(span.end, key):
        return None
    if span.start is not None and not _is_zero_version(span.start):
        return key if _branch_key(span.start, depth) == key else None
    for other in spans:
        if other is span or other.end is None:
            continue
        other_key = _branch_key(other.end, depth)
        if other_key is not None and other_key != key:
            return key
    return None


def _subtract_window(span: VersionSpan, lo: str, hi: str) -> list[VersionSpan] | None:
    """``span`` minus ``[lo, hi)``; ``None`` when a comparison is undecidable."""
    if span.start is not None:
        cmp_hi = _compare_versions(span.start, hi)
        if cmp_hi is None:
            return None
        if cmp_hi >= 0:
            return [span]
    if span.end is not None:
        cmp_lo = _compare_versions(span.end, lo)
        if cmp_lo is None:
            return None
        if cmp_lo < 0 or (cmp_lo == 0 and not span.end_inclusive):
            return [span]

    pieces: list[VersionSpan] = []
    start_below = span.start is None or (_compare_versions(span.start, lo) or 0) < 0
    if start_below:
        pieces.append(VersionSpan(span.start, span.start_inclusive, lo, False))
    if span.end is None:
        pieces.append(VersionSpan(hi, True, None, False))
    else:
        cmp_end = _compare_versions(span.end, hi)
        if cmp_end is not None and (cmp_end > 0 or (cmp_end == 0 and span.end_inclusive)):
            pieces.append(VersionSpan(hi, True, span.end, span.end_inclusive))
    return pieces


def effective_spans(spans: list[VersionSpan]) -> list[VersionSpan]:
    """Apply the release-branch rule to one product's spans within one CVE."""
    depth = _branch_depth(spans)
    scoped = {
        i: key for i, span in enumerate(spans) if (key := _scoped_branch(span, spans, depth)) is not None
    }
    if not scoped:
        return list(spans)
    windows = [_branch_window(key) for key in sorted(set(scoped.values()))]

    out: list[VersionSpan] = []
    for i, span in enumerate(spans):
        key = scoped.get(i)
        if key is not None:
            lo, _ = _branch_window(key)
            if span.start is None or _is_zero_version(span.start):
                out.append(VersionSpan(lo, True, span.end, span.end_inclusive))
            else:
                out.append(span)
        pieces = [span]
        for lo, hi in windows:
            carved: list[VersionSpan] = []
            for piece in pieces:
                result = _subtract_window(piece, lo, hi)
                carved.extend(result if result is not None else [piece])
            pieces = carved
        out.extend(pieces)
    return out


def coalesce_pins(exact: Iterable[str]) -> tuple[list[str], list[VersionSpan]]:
    """Fold runs of consecutive exact pins into closed spans.

    The NuGet runtime advisories list every .NET release one by one ("8.0.0",
    "8.0.1", … "8.0.8", "8.0.10", …), several hundred per CVE. As single
    points they overflowed the index's per-document cap, so later packages
    were never indexed. A run of pins whose last segment counts up by one
    becomes ``[first, last]``; a gap (8.0.9 missing) ends the run. Pins never
    go through the branch rule, and matcher and index both call this.

    The span also holds versions one segment deeper ("8.0.5.1"), so runs are
    only folded where none can exist: at least three segments ("17.0", "17.1"
    are release lines whose patches are real versions), and no pin in the
    list is deeper than the run (Akka lists "2.4.11.1" next to "2.4.10").
    """
    singles: list[str] = []
    parsed: list[tuple[tuple[int, ...], str]] = []
    deepest = 0
    for pin in exact:
        p = parse_version(pin)
        if p.valid and p.release:
            deepest = max(deepest, len(p.release))
        if p.valid and len(p.release) >= 3 and not p.pre and not p.post:
            parsed.append((p.release, pin))
        else:
            singles.append(pin)
    shallow = [entry for entry in parsed if len(entry[0]) < deepest]
    singles.extend(pin for _, pin in shallow)
    parsed = [entry for entry in parsed if len(entry[0]) == deepest]

    spans: list[VersionSpan] = []
    run: list[tuple[tuple[int, ...], str]] = []

    def flush() -> None:
        if len(run) >= 2:
            spans.append(VersionSpan(run[0][1], True, run[-1][1], True))
        else:
            singles.extend(pin for _, pin in run)
        run.clear()

    for release, pin in sorted(set(parsed)):
        if run:
            prev = run[-1][0]
            if release == prev:
                continue
            if not (
                len(release) == len(prev)
                and release[:-1] == prev[:-1]
                and release[-1] == prev[-1] + 1
            ):
                flush()
        run.append((release, pin))
    flush()
    return singles, spans


def _matches_spans(
    version: str,
    exact: Iterable[str],
    spans: list[VersionSpan],
    *,
    branch_rule: bool = True,
) -> bool:
    pins, pin_spans = coalesce_pins(exact)
    if any(_versions_equivalent(version, pin) for pin in pins):
        return True
    if any(span.contains(version) for span in pin_spans):
        return True
    candidates = effective_spans(spans) if branch_rule else spans
    return any(span.contains(version) for span in candidates)


def version_in_ranges(version: str, range_strs: Iterable[str], *, branch_rule: bool = True) -> bool:
    """Return True if ``version`` is affected by one product's version list.

    Unlike evaluating each string on its own, this applies the release-branch
    rule (see :func:`effective_spans`) across the whole list, unless
    ``branch_rule`` is off (see :func:`multi_target_pairs`).
    """
    exact: list[str] = []
    spans: list[VersionSpan] = []
    for raw in range_strs:
        if not isinstance(raw, str):
            continue
        pins, span = _parse_range(raw)
        exact.extend(pins)
        if span is not None:
            spans.append(span)
    return _matches_spans(version, exact, spans, branch_rule=branch_rule)


# One product name can stand for several packages. NVD files the Azure
# Identity SDK of every language under ``microsoft:azure_identity`` and tells
# them apart only by ``target_sw`` (python, java, …); the impactedProducts
# aggregation then merges their fixes into one list ("< 1.10.2", "< 1.14.1",
# "< 3.3.1") that looks exactly like Redis' one-fix-per-branch list. Read as
# branches, Python 1.10.3 (fixed in 1.14.1) would drop out. So the branch rule
# runs per target_sw on CPE matches and is off for an impactedProducts list
# whose product the CPE data shows on more than one target.

# "*" is ANY; "-" is NA, i.e. explicitly no target (gRPC's C core next to
# grpc-go), so it counts as a target of its own.
_WILDCARD_TARGETS = {"", "*"}


def _cpe_target(match: CpeMatch) -> str:
    # Read from the URI first: the normalizer stores NA ("-") as no target_sw.
    parts = match.criteria.split(":") if isinstance(match.criteria, str) else []
    raw = parts[10] if len(parts) > 10 and match.criteria.startswith("cpe:2.3:") else match.target_sw
    target = (raw or "").strip().lower()
    return "" if target in _WILDCARD_TARGETS else target


def multi_target_pairs(cpe_configurations: Iterable[CpeConfiguration]) -> set[tuple[str, str]]:
    """Products whose vulnerable CPE matches name more than one ``target_sw``."""
    targets: dict[tuple[str, str], set[str]] = {}
    for config in cpe_configurations or []:
        for match in _iter_matches(config.nodes):
            if is_marked_not_vulnerable(match):
                continue
            target = _cpe_target(match)
            if not target:
                continue
            pair = (_slug(match.vendor), _slug(match.product))
            if not pair[0] or not pair[1]:
                pair = _cpe_uri_pair(match.criteria) or ("", "")
            targets.setdefault(pair, set()).add(target)
    return {pair for pair, found in targets.items() if len(found) > 1}


# --- Platform entries (``vulnerable: false``) ---
#
# NVD lists the software a vulnerable product runs on as a non-vulnerable CPE
# match in the same configuration ("Next.js < 12.0.5 running on Node.js >
# 15.0.0"). Those carry ranges too, and treating them as affected flagged every
# current Node.js / Python for Next.js and Odoo CVEs. An explicit ``False``
# marks such an entry; a missing flag keeps meaning "affected".


def is_marked_not_vulnerable(obj: Any) -> bool:
    """True only for an explicit ``vulnerable: False`` (dict or model)."""
    if isinstance(obj, dict):
        return obj.get("vulnerable") is False
    if getattr(obj, "vulnerable", None) is not False:
        return False
    # ``CpeMatch.vulnerable`` defaults to False, so a stored match without the
    # key would read as a platform. Only trust a value the data actually set.
    fields_set = getattr(obj, "model_fields_set", None)
    return fields_set is None or "vulnerable" in fields_set


def impacted_entry_pairs(entry: dict[str, Any]) -> list[tuple[str, str]]:
    """All (vendor, product) slug spellings an impacted-products entry answers to."""
    vendor_obj = entry.get("vendor")
    product_obj = entry.get("product")
    if not isinstance(vendor_obj, dict) or not isinstance(product_obj, dict):
        return []
    vendors = {_slug(vendor_obj.get("slug")), _slug(vendor_obj.get("name"))}
    products = {_slug(product_obj.get("slug")), _slug(product_obj.get("name"))}
    vendors.discard("")
    products.discard("")
    return [(v, p) for v in sorted(vendors) for p in sorted(products)]


def _cpe_uri_pair(criteria: str | None) -> tuple[str, str] | None:
    if not isinstance(criteria, str) or not criteria.startswith("cpe:2.3:"):
        return None
    parts = criteria.split(":")
    if len(parts) < 6:
        return None
    vendor, product = _slug(parts[3]), _slug(parts[4])
    if not vendor or not product:
        return None
    return vendor, product


def platform_cpe_filter(
    impacted_products: list[dict[str, Any]],
    cpe_configurations: list[CpeConfiguration],
) -> tuple[set[str], set[tuple[str, str]]]:
    """Flat CPEs that only ever appear as a platform, by criteria and by pair.

    The flat ``cpes`` list is every criteria string of every configuration, the
    platform ones included, with no flag of its own. A pair counts as platform
    when it shows up only with ``vulnerable: False``; a criteria string when
    every match carrying it is ``False`` (the cpematch API ships no flag, the
    normalizer stores ``False`` there, and those copies always sit next to the
    flagged NVD match with the same criteria).
    """
    false_pairs: set[tuple[str, str]] = set()
    true_pairs: set[tuple[str, str]] = set()
    false_criteria: set[str] = set()
    true_criteria: set[str] = set()

    for entry in impacted_products:
        target = false_pairs if is_marked_not_vulnerable(entry) else true_pairs
        target.update(impacted_entry_pairs(entry))

    for config in cpe_configurations:
        for match in _iter_matches(config.nodes):
            not_vulnerable = is_marked_not_vulnerable(match)
            pair = (_slug(match.vendor), _slug(match.product))
            if not pair[0] or not pair[1]:
                pair = _cpe_uri_pair(match.criteria) or ("", "")
            if pair[0] and pair[1]:
                (false_pairs if not_vulnerable else true_pairs).add(pair)
            if isinstance(match.criteria, str):
                (false_criteria if not_vulnerable else true_criteria).add(match.criteria)

    return false_criteria - true_criteria, false_pairs - true_pairs


def cpe_match_span(match: CpeMatch) -> tuple[tuple[str, ...], VersionSpan | None]:
    """``(exact pins, span)`` of one CPE match; both empty for a bare wildcard.

    A version-less ``vendor:product:*`` (or ``:-:``) match carries no version
    evidence and yields nothing (fail closed). Background: matching every
    version there flagged phpBB 3.3.17 for CVEs about third-party phpBB
    *modules* that reference ``cpe:2.3:a:phpbb:phpbb:*`` as a platform.
    """
    span = _span_from_bounds(
        start_in=match.version_start_including,
        start_ex=match.version_start_excluding,
        end_in=match.version_end_including,
        end_ex=match.version_end_excluding,
    )
    if span is not None:
        return (), span
    exact = _extract_version_from_cpe(match.criteria)
    if exact is None and isinstance(match.version, str):
        candidate = match.version.strip()
        if candidate not in ("", "*", "-", "ANY", "NA"):
            exact = candidate
    return ((exact,) if exact else ()), None


def _coerce_impacted_products(value: Any) -> list[dict[str, Any]]:
    """Normalize ``impacted_products`` / ``impactedProducts`` entries to dicts.

    Accepts three shapes:

    - raw dicts (what MongoDB returns for pipelines that inject API JSON)
    - Pydantic models (``ImpactedProduct`` instances from
      ``VulnerabilityDetail``, loaded via
      ``VulnerabilityService.get_by_id``)
    - mixed lists

    Pydantic entries are dumped via ``model_dump(by_alias=False)`` so the
    resulting dicts always use snake_case keys (``versions``, ``vendor``,
    ``product``), which the tier-1 evaluation expects.
    """
    if not isinstance(value, list):
        return []
    result: list[dict[str, Any]] = []
    for entry in value:
        if isinstance(entry, dict):
            result.append(entry)
            continue
        dump = getattr(entry, "model_dump", None)
        if callable(dump):
            try:
                result.append(dump(by_alias=False))
                continue
            except Exception:  # pragma: no cover - defensive
                pass
    return result


def _iter_matches(nodes: Iterable[CpeNode]) -> Iterable[CpeMatch]:
    for node in nodes or []:
        if node is None:
            continue
        for match in node.matches or []:
            if match is not None:
                yield match
        if node.nodes:
            yield from _iter_matches(node.nodes)


def branch_scoped_product_span(
    range_str: str, segments: int
) -> tuple[tuple[str, ...], VersionSpan | None]:
    """Span form of :func:`_version_in_branch_scoped_range` (NetScaler).

    ``">= 14.1, < 56.73"`` means "14.1 builds below 56.73", i.e. ``(14.1,
    14.1.56.73)``. Shapes that aren't "branch + threshold" fall back to the
    ordinary parse, as in the matcher. Used by the index; the matcher keeps
    evaluating the raw strings, which also accept "14.1, 66.59" item values.
    """
    start_bound: str | None = None
    end_in: str | None = None
    end_ex: str | None = None
    for op, ver in _parse_range_clauses(range_str):
        if op in (">=", ">"):
            start_bound = ver
        elif op == "<=":
            end_in = ver
        elif op == "<":
            end_ex = ver
    if start_bound is None or (end_in is None and end_ex is None):
        return _parse_range(range_str)

    branch = _leading_numeric_segments(start_bound, segments)
    end_all = _split_numeric_segments(end_ex if end_ex is not None else end_in)
    if branch is None or end_all is None:
        return (), None
    if len(end_all) > segments:
        if end_all[:segments] != branch:
            return (), None
        build = end_all[segments:]
    else:
        build = end_all
    low = ".".join(str(seg) for seg in branch)
    high = ".".join(str(seg) for seg in branch + build)
    # Exclusive start: "14.1" alone is not a NetScaler build.
    return (), VersionSpan(low, False, high, end_ex is None)


@dataclass
class ProductEvidence:
    """What decides for one (vendor, product) pair of one vulnerability.

    ``groups`` holds ``(pins, spans)`` per package: one group for tiers 1 and
    3, one per ``target_sw`` for tier 2. ``branch_segments`` is set for
    NetScaler, whose raw tier-1 strings the matcher evaluates itself.
    """

    tier: int
    groups: list[tuple[list[str], list[VersionSpan]]]
    branch_rule: bool = True
    raw_ranges: list[str] | None = None
    branch_segments: int | None = None


def _cpe_match_pair(match: CpeMatch) -> tuple[str, str] | None:
    vendor, product = _slug(match.vendor), _slug(match.product)
    if vendor and product:
        return vendor, product
    return _cpe_uri_pair(match.criteria)


def collect_product_evidence(
    impacted_products: Any,
    cpe_configurations: Any,
    flat_cpes: Iterable[str] | None,
) -> dict[tuple[str, str], ProductEvidence]:
    """Per (vendor, product): the first tier that has version evidence.

    Shared by the inventory matcher and the OpenSearch range index, so both
    pick the same tier and the same ranges:

    1. ``impactedProducts`` (curated: EUVD, CIRCL, OSV, GHSA, NVD-derived),
    2. ``cpeConfigurations`` matches, grouped per ``target_sw``,
    3. the flat ``cpes`` list (concrete versions only, platforms dropped).

    The index used to union all three. Checked on 450 documents: where tiers
    1 and 2 disagreed, tier 2 was mostly the one naming the *fixed* release
    (Windows Server builds, gRPC 1.56.3 / 1.58.3), so the union indexed fixed
    versions as affected.

    A tier only decides for a product when it has evidence: an entry whose
    versions are ``[]`` or only broad (``*``, ``n/a``) passes the product on.
    """
    impacted = _coerce_impacted_products(impacted_products)
    configs = _coerce_cpe_configurations(cpe_configurations)
    mixed_targets = multi_target_pairs(configs)

    # "from X upwards" CPE matches. The NVD aggregation used to write them into
    # impactedProducts as a bare "X", which reads as the exact version X; the
    # formatter is fixed, stored documents keep the old string until their next
    # NVD write, so the bare pin is read as the open range it came from.
    open_starts: dict[tuple[str, str], set[str]] = {}
    for config in configs:
        for match in _iter_matches(config.nodes):
            if is_marked_not_vulnerable(match):
                continue
            if (
                match.version_start_including
                and not match.version_start_excluding
                and not match.version_end_including
                and not match.version_end_excluding
            ):
                pair = _cpe_match_pair(match)
                if pair is not None:
                    open_starts.setdefault(pair, set()).add(match.version_start_including.strip())

    evidence: dict[tuple[str, str], ProductEvidence] = {}

    # --- Tier 1: impactedProducts ---
    tier1: dict[tuple[str, str], list[str]] = {}
    for entry in impacted:
        if is_marked_not_vulnerable(entry):
            continue
        versions = entry.get("versions")
        ranges = [v for v in versions if isinstance(v, str)] if isinstance(versions, list) else []
        for pair in impacted_entry_pairs(entry):
            tier1.setdefault(pair, []).extend(ranges)
    for pair, ranges in tier1.items():
        segments = _BRANCH_SCOPED_PRODUCTS.get(pair)
        pins: list[str] = []
        spans: list[VersionSpan] = []
        for raw in ranges:
            try:
                found, span = branch_scoped_product_span(raw, segments) if segments else _parse_range(raw)
            except Exception as exc:  # pragma: no cover - defensive
                log.debug("inventory_matcher.range_string_error", range_str=raw, error=str(exc))
                continue
            for pin in found:
                if pin in open_starts.get(pair, ()):
                    spans.append(VersionSpan(pin, True, None, False))
                else:
                    pins.append(pin)
            if span is not None:
                spans.append(span)
        if pins or spans:
            evidence[pair] = ProductEvidence(
                tier=1,
                groups=[(pins, spans)],
                branch_rule=pair not in mixed_targets,
                raw_ranges=ranges,
                branch_segments=segments,
            )

    # --- Tier 2: CPE configuration matches, one group per target_sw ---
    tier2: dict[tuple[str, str], dict[str, tuple[list[str], list[VersionSpan]]]] = {}
    for config in configs:
        for match in _iter_matches(config.nodes):
            if is_marked_not_vulnerable(match):
                continue
            pair = _cpe_match_pair(match)
            if pair is None or pair in evidence:
                continue
            found, span = cpe_match_span(match)
            group = tier2.setdefault(pair, {}).setdefault(_cpe_target(match), ([], []))
            group[0].extend(found)
            if span is not None:
                group[1].append(span)
    for pair, by_target in tier2.items():
        groups = [group for group in by_target.values() if group[0] or group[1]]
        if groups:
            evidence[pair] = ProductEvidence(tier=2, groups=groups)

    # --- Tier 3: flat CPEs with a concrete version ---
    if flat_cpes:
        platform_criteria, platform_pairs = platform_cpe_filter(impacted, configs)
        for cpe in flat_cpes:
            if not isinstance(cpe, str) or cpe in platform_criteria:
                continue
            pair = _cpe_uri_pair(cpe)
            if pair is None or pair in platform_pairs:
                continue
            if pair in evidence and evidence[pair].tier != 3:
                continue
            version = _extract_version_from_cpe(cpe)
            if version is None:
                continue
            evidence.setdefault(pair, ProductEvidence(tier=3, groups=[([], [])])).groups[0][0].append(version)

    return evidence


def match_in_configuration(
    item: InventoryKey,
    cpe_configurations: list[CpeConfiguration],
    flat_cpes: list[str] | None = None,
    *,
    impacted_products: list[dict[str, Any]] | None = None,
) -> bool:
    """Return True if any data source confirms the item is affected.

    Priority order (fail-closed when an authoritative source says "no"):

    1. ``impacted_products`` — curated vendor/product/version range strings
       from EUVD. When an entry matches the item's vendor+product slug, its
       ``versions`` list is evaluated; if none match we stop and return
       False without consulting the CPE data (the entry is authoritative).

    2. ``cpe_configurations`` — structured NVD range data. Same semantic:
       if a match entry for the item's vendor+product exists but none of
       its range bounds satisfy the version, we return False.

    3. ``flat_cpes`` — plain CPE 2.3 URIs, evaluated **only** as a
       last-resort fallback when neither of the above yielded any
       vendor/product-matching entries. Wildcards (``*`` / ``-``) in the
       version component are **ignored** rather than matched: an unbounded
       wildcard CPE tells us nothing about a specific version.

    A tier decides only when it carries version evidence for the product (a
    pin or a range); an entry with ``[]`` or only ``*`` hands over to the next
    tier. Entries and matches with ``vulnerable: False`` (platforms) are
    skipped, and each tier's ranges go through :func:`effective_spans`
    (release-branch rule). The tier selection lives in
    :func:`collect_product_evidence`, which ``build_version_ranges`` uses as
    well, so ``affectedVersion:`` queries and inventory pages agree.
    """
    item_vendor = _slug(item.vendor_slug)
    item_product = _slug(item.product_slug)
    item_version = item.version.strip()
    if not item_vendor or not item_product or not item_version:
        return False
    evidence = collect_product_evidence(
        impacted_products or [], cpe_configurations or [], flat_cpes or []
    ).get((item_vendor, item_product))
    return evidence_matches(item_version, evidence)


def evidence_matches(item_version: str, evidence: ProductEvidence | None) -> bool:
    """Decide one version against the evidence of its product."""
    if evidence is None:
        return False
    try:
        if evidence.branch_segments is not None:
            return any(
                _version_in_branch_scoped_range(item_version, raw, evidence.branch_segments)
                for raw in evidence.raw_ranges or []
            )
        return any(
            _matches_spans(item_version, pins, spans, branch_rule=evidence.branch_rule)
            for pins, spans in evidence.groups
        )
    except Exception as exc:  # pragma: no cover - defensive
        log.debug("inventory_matcher.match_error", version=item_version, error=str(exc))
        return False


# --- High-level query helpers ---


def items_for_vuln(
    vuln: Any,
    inventory: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return the subset of ``inventory`` items affected by ``vuln``.

    ``vuln`` may be a ``VulnerabilityDocument``, a ``VulnerabilityDetail``, or
    a raw ``dict`` from MongoDB/OpenSearch. The pre-filter union-set combines
    the denormalized slug arrays, the raw display-name arrays, and every
    vendor/product slug referenced by ``impacted_products`` — any of these
    may be the only place a given product identifier shows up. The full
    matcher then validates each surviving candidate against all three data
    sources (impacted_products → cpe_configurations → flat cpes).
    """
    impacted_products = _coerce_impacted_products(
        _get_attr(vuln, "impacted_products", "impactedProducts")
    )
    cpe_configurations = _coerce_cpe_configurations(
        _get_attr(vuln, "cpe_configurations", "cpeConfigurations")
    )
    flat_cpes = _coerce_string_list(_get_attr(vuln, "cpes"))

    vendor_slug_set = _coerce_slug_set(_get_attr(vuln, "vendor_slugs", "vendorSlugs"))
    product_slug_set = _coerce_slug_set(_get_attr(vuln, "product_slugs", "productSlugs"))
    vendor_slug_set |= _coerce_slug_set(_get_attr(vuln, "vendors"))
    product_slug_set |= _coerce_slug_set(_get_attr(vuln, "products"))
    # Also pull vendor/product identifiers out of impacted_products entries —
    # the Microsoft/.NET CVE stores everything there and nothing in the
    # top-level slug arrays.
    for entry in impacted_products:
        vendor_obj = entry.get("vendor") or {}
        product_obj = entry.get("product") or {}
        for k in ("slug", "name"):
            v = _slug(vendor_obj.get(k))
            if v:
                vendor_slug_set.add(v)
            p = _slug(product_obj.get(k))
            if p:
                product_slug_set.add(p)

    if not cpe_configurations and not flat_cpes and not vendor_slug_set and not impacted_products:
        return []

    # One evidence pass per CVE, not per inventory item.
    evidence = collect_product_evidence(impacted_products, cpe_configurations, flat_cpes)
    results: list[dict[str, Any]] = []
    for raw in inventory:
        if not isinstance(raw, dict):
            continue
        vendor = _slug(raw.get("vendor_slug"))
        product = _slug(raw.get("product_slug"))
        if not vendor or not product:
            continue
        if vendor_slug_set and vendor not in vendor_slug_set:
            continue
        if product_slug_set and product not in product_slug_set:
            continue
        key = InventoryKey(
            vendor_slug=vendor,
            product_slug=product,
            version=str(raw.get("version") or ""),
        )
        if not key.version.strip():
            continue
        if evidence_matches(key.version.strip(), evidence.get((key.vendor_slug, key.product_slug))):
            results.append(raw)
    return results


async def vulns_for_item(
    vuln_repo: Any,
    item: InventoryKey,
    *,
    projection: dict[str, int] | None = None,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    """Return raw vulnerability documents affected by the inventory item.

    The Mongo pre-filter queries both the denormalized slug arrays
    (``vendor_slugs`` / ``product_slugs``) and the raw display-name arrays
    (``vendors`` / ``products``). Historic CPE tags frequently store a
    different slug than the asset catalog exposes to the user (e.g. the
    catalog lists ``graylog``/``graylog`` while old CPEs use
    ``graylog2``/``graylog2-server``), so a slug-only filter misses those
    records entirely. The matcher then uses the actual CPE data to decide.
    """
    if projection is None:
        projection = {
            "_id": 1,
            "vuln_id": 1,
            "title": 1,
            "cvss": 1,
            "epss_score": 1,
            "exploited": 1,
            "published": 1,
            "cpe_configurations": 1,
            "cpes": 1,
            "vendor_slugs": 1,
            "product_slugs": 1,
            "vendors": 1,
            "products": 1,
            "impacted_products": 1,
            "impactedProducts": 1,
        }

    vendor = _slug(item.vendor_slug)
    product = _slug(item.product_slug)
    # The CVE may reference the product via the denormalized vendor_slugs/
    # product_slugs arrays OR the raw display-name vendors/products arrays.
    # Both sets of fields are indexed, so the query planner can use either
    # side of the $or without falling back to a collection scan. We
    # intentionally do NOT query the nested ``impacted_products.*.slug``
    # paths here (no index exists) — in practice every CVE we've seen has
    # at least one of the denormalized arrays populated with a slug the
    # matcher can hit; the nested-path data is then read from the returned
    # document and evaluated in Python by the full matcher.
    query = {
        "$and": [
            {"$or": [{"vendor_slugs": vendor}, {"vendors": vendor}]},
            {"$or": [{"product_slugs": product}, {"products": product}]},
        ],
    }
    # ``limit`` caps the *hits*, never the cursor: the pre-filter only knows
    # vendor/product, so a popular product (WordPress: hundreds of core CVEs)
    # puts far more candidates through it than affect any one version. A
    # cursor limit checked only the first N in natural order — the oldest —
    # and reported "no known vulnerabilities" for a current release that the
    # detail page (``items_for_vuln``) correctly flagged.
    cursor = vuln_repo.collection.find(query, projection=projection)

    hits: list[dict[str, Any]] = []
    async for doc in cursor:
        cpe_configurations = _coerce_cpe_configurations(doc.get("cpe_configurations"))
        flat_cpes = _coerce_string_list(doc.get("cpes"))
        # camelCase first, like the read path (``_get_impacted_products_or_build``)
        # and therefore ``items_for_vuln`` on the detail page: the writers only
        # maintain ``impactedProducts``, a lingering snake_case key is stale.
        impacted_products = _coerce_impacted_products(
            doc.get("impactedProducts") or doc.get("impacted_products")
        )
        if match_in_configuration(
            item,
            cpe_configurations,
            flat_cpes,
            impacted_products=impacted_products,
        ):
            hits.append(doc)
            if limit and len(hits) >= limit:
                break
    return hits


# --- Coercion helpers (raw dict documents vs. Pydantic models) ---


def _get_attr(obj: Any, *names: str) -> Any:
    for name in names:
        if isinstance(obj, dict):
            if name in obj:
                return obj[name]
        else:
            value = getattr(obj, name, None)
            if value is not None:
                return value
    return None


def _coerce_string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value if isinstance(v, (str, int))]
    return []


def _coerce_slug_set(value: Any) -> set[str]:
    if not isinstance(value, list):
        return set()
    return {_slug(v) for v in value if isinstance(v, str) and v}


def _coerce_cpe_configurations(value: Any) -> list[CpeConfiguration]:
    """Accept raw dict/list structures from Mongo or already-parsed models."""
    if not value:
        return []
    result: list[CpeConfiguration] = []
    for entry in value:
        if isinstance(entry, CpeConfiguration):
            result.append(entry)
            continue
        if isinstance(entry, dict):
            try:
                result.append(CpeConfiguration.model_validate(entry))
            except Exception:  # pragma: no cover - defensive
                continue
    return result
