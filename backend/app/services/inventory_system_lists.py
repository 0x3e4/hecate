"""Server lists for the inventory's systems: CSV, text, Ansible and Hecate JSON.

A list names systems and, optionally, what they are. It comes from a file
someone keeps (static) or from a script on their side that pushes it on a
schedule (``POST /inventory/systems/import`` with an ``inventory:sync``
token); Hecate never runs a script itself.

Formats (``LIST_FORMATS``, detected when not named):

- ``csv``: a header row, ``name`` (or ``host``, ``hostname``, ``fqdn``) and
  any of ``kind``, ``exposure``, ``environment`` (``env``), ``owner``,
  ``groups`` (separated by ``;`` or ``|``), ``notes``.
- ``text``: one name per line, ``#`` starts a comment.
- ``ansible-ini``: an Ansible INI inventory: ``[group]`` sections,
  ``[group:children]``, ``[group:vars]``, host ranges such as ``web[01:20]``.
- ``ansible-yaml``: an Ansible YAML inventory (``all: hosts / children / vars``).
- ``ansible-json``: the output of ``ansible-inventory --list`` (any inventory
  source, plugins included, comes out in this shape).
- ``json``: ``{"systems": [{"name": …, "kind": …, "groups": […]}]}`` or the list
  alone; the ``systems`` of an inventory backup read the same way.

In the Ansible formats a host's groups are every group it is in (parents
included, ``all`` and ``ungrouped`` left out), and ``hecate_kind``,
``hecate_exposure``, ``hecate_environment``, ``hecate_owner`` and
``hecate_notes`` set its fields: as host variables, or as group variables
for every host of the group (host variables win).
"""
from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import dataclass, field
from typing import Any

LIST_FORMATS = ("csv", "text", "ansible-ini", "ansible-yaml", "ansible-json", "json")
MAX_LIST_SYSTEMS = 10_000
MAX_LIST_BYTES = 5 * 1024 * 1024

KINDS = ("host", "kubernetes-node", "container", "other")
EXPOSURES = ("internet", "internal")
_FIELDS = ("kind", "exposure", "environment", "owner", "notes")
_LIMITS = {"environment": 50, "owner": 200, "notes": 2000}
_IMPLICIT_GROUPS = {"all", "ungrouped"}
_NAME_ALIASES = ("name", "host", "hostname", "fqdn", "system")
_COLUMN_ALIASES = {"env": "environment", "group": "groups"}
_RANGE = re.compile(r"\[([0-9]+|[a-zA-Z]):([0-9]+|[a-zA-Z])\]")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class ListError(ValueError):
    """The list cannot be read at all (unknown format, broken syntax, too big)."""


@dataclass
class ListedSystem:
    name: str
    groups: list[str] = field(default_factory=list)
    fields: dict[str, str] = field(default_factory=dict)


@dataclass
class ParsedList:
    format: str
    systems: list[ListedSystem]
    skipped: list[dict[str, Any]]


# ---------------------------------------------------------------- shared rules


def _clean_name(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    name = value.strip()
    if not name or len(name) > 200 or _CONTROL.search(name):
        return None
    return name


def _clean_fields(raw: dict[str, Any], where: str, skipped: list[dict[str, Any]]) -> dict[str, str]:
    """The known fields with valid values; an invalid value is reported and left out."""
    out: dict[str, str] = {}
    for key in _FIELDS:
        value = raw.get(key)
        if value is None or (isinstance(value, str) and not value.strip()):
            continue
        text = str(value).strip()
        if key == "kind":
            text = text.lower()
            if text not in KINDS:
                skipped.append({"where": where, "reason": f"kind {text!r} is not one of {', '.join(KINDS)}; ignored"})
                continue
        elif key == "exposure":
            text = text.lower()
            if text not in EXPOSURES:
                skipped.append({"where": where, "reason": f"exposure {text!r} is not internet or internal; ignored"})
                continue
        else:
            text = text[: _LIMITS[key]]
        out[key] = text
    return out


def _clean_groups(values: Any) -> list[str]:
    out: list[str] = []
    for value in values or []:
        text = str(value).strip()[:60] if value is not None else ""
        if text and text.lower() not in _IMPLICIT_GROUPS and text.casefold() not in {g.casefold() for g in out}:
            out.append(text)
    return out[:20]


def _hecate_vars(variables: Any) -> dict[str, Any]:
    if not isinstance(variables, dict):
        return {}
    return {key[len("hecate_"):]: value for key, value in variables.items()
            if isinstance(key, str) and key.startswith("hecate_") and key[len("hecate_"):] in _FIELDS}


def expand_host_pattern(pattern: str, budget: int = MAX_LIST_SYSTEMS) -> list[str]:
    """Ansible host ranges: ``web[01:03]`` -> web01, web02, web03; ``db-[a:c]`` -> db-a … db-c."""
    match = _RANGE.search(pattern)
    if not match:
        return [pattern]
    start, end = match.group(1), match.group(2)
    if start.isdigit() and end.isdigit():
        width = len(start) if start.startswith("0") and len(start) > 1 else 0
        values = [str(i).zfill(width) for i in range(int(start), int(end) + 1)]
    elif start.isalpha() and end.isalpha():
        values = [chr(c) for c in range(ord(start), ord(end) + 1)]
    else:
        return [pattern]
    out: list[str] = []
    for value in values:
        for name in expand_host_pattern(pattern[: match.start()] + value + pattern[match.end():], budget - len(out)):
            out.append(name)
            if len(out) >= budget:
                return out
    return out


# ---------------------------------------------------------------- the formats


def _merge(systems: dict[str, ListedSystem], name: str, groups: list[str], fields: dict[str, str]) -> None:
    """One entry per name (case-insensitive): groups add up, later fields win."""
    key = name.casefold()
    entry = systems.get(key)
    if entry is None:
        systems[key] = ListedSystem(name=name, groups=_clean_groups(groups), fields=dict(fields))
        return
    entry.groups = _clean_groups([*entry.groups, *groups])
    entry.fields.update(fields)


def _parse_csv(content: str, skipped: list[dict[str, Any]]) -> list[ListedSystem]:
    reader = csv.DictReader(io.StringIO(content))
    if not reader.fieldnames:
        raise ListError("The CSV has no header row.")
    columns = {}
    for column in reader.fieldnames:
        key = (column or "").strip().lower()
        columns[column] = _COLUMN_ALIASES.get(key, key)
    name_column = next((c for c, key in columns.items() if key in _NAME_ALIASES), None)
    if name_column is None:
        raise ListError("The CSV needs a name column (name, host, hostname or fqdn).")
    systems: dict[str, ListedSystem] = {}
    for line, row in enumerate(reader, start=2):
        name = _clean_name(row.get(name_column))
        if name is None:
            if any((v or "").strip() for v in row.values() if isinstance(v, str)):
                skipped.append({"where": f"line {line}", "reason": "no usable name"})
            continue
        values = {columns[c]: v for c, v in row.items() if c in columns}
        groups = re.split(r"[;|]", values.get("groups") or "")
        _merge(systems, name, groups, _clean_fields(values, f"line {line}", skipped))
    return list(systems.values())


def _parse_text(content: str, skipped: list[dict[str, Any]]) -> list[ListedSystem]:
    systems: dict[str, ListedSystem] = {}
    for line, raw in enumerate(content.splitlines(), start=1):
        text = raw.split("#", 1)[0].strip()
        if not text:
            continue
        name = _clean_name(text)
        if name is None or " " in name:
            skipped.append({"where": f"line {line}", "reason": "not a single name"})
            continue
        _merge(systems, name, [], {})
    return list(systems.values())


class _Groups:
    """Ansible groups as read from any of the three inventory formats."""

    def __init__(self) -> None:
        self.hosts: dict[str, set[str]] = {}       # group -> host names
        self.children: dict[str, set[str]] = {}    # group -> child groups
        self.vars: dict[str, dict[str, Any]] = {}  # group -> variables
        self.host_vars: dict[str, dict[str, Any]] = {}
        self.order: list[str] = []                 # hosts in the order they appear

    def add_host(self, group: str, host: str, variables: dict[str, Any] | None = None) -> None:
        self.hosts.setdefault(group, set()).add(host)
        if host not in self.host_vars:
            self.host_vars[host] = {}
            self.order.append(host)
        if variables:
            self.host_vars[host].update(variables)

    def systems(self, skipped: list[dict[str, Any]]) -> list[ListedSystem]:
        parents: dict[str, set[str]] = {}
        for parent, kids in self.children.items():
            for kid in kids:
                parents.setdefault(kid, set()).add(parent)

        def ancestors(group: str, seen: set[str]) -> set[str]:
            for parent in parents.get(group, ()):
                if parent not in seen:
                    seen.add(parent)
                    ancestors(parent, seen)
            return seen

        # Group values are checked once per group, host values per host, so an
        # invalid host value leaves the group's valid one in place.
        group_fields = {
            group: _clean_fields(_hecate_vars(variables), f"group {group}", skipped)
            for group, variables in self.vars.items()
        }
        host_groups: dict[str, set[str]] = {host: set() for host in self.order}
        for group, hosts in self.hosts.items():
            for host in hosts:
                host_groups[host] |= {group} | ancestors(group, set())
        systems: dict[str, ListedSystem] = {}
        for host in self.order:
            name = _clean_name(host)
            if name is None:
                skipped.append({"where": f"host {host[:60]!r}", "reason": "not a usable name"})
                continue
            groups = sorted(host_groups[host], key=str.casefold)
            merged: dict[str, str] = {}
            # "all" first (its variables count, it is no group of the list), then
            # parents before children, then the host: the most specific value wins.
            for group in ["all", *sorted(groups, key=lambda g: len(ancestors(g, set())))]:
                merged.update(group_fields.get(group, {}))
            merged.update(_clean_fields(_hecate_vars(self.host_vars.get(host)), f"host {name}", skipped))
            _merge(systems, name, groups, merged)
            if len(systems) >= MAX_LIST_SYSTEMS:
                break
        return list(systems.values())


def _ini_vars(tokens: list[str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for token in tokens:
        if "=" in token:
            key, value = token.split("=", 1)
            out[key.strip()] = value.strip().strip("'\"")
    return out


def _parse_ansible_ini(content: str, skipped: list[dict[str, Any]]) -> list[ListedSystem]:
    import shlex

    groups = _Groups()
    section, kind = "ungrouped", "hosts"
    for line, raw in enumerate(content.splitlines(), start=1):
        text = raw.strip()
        if not text or text.startswith(("#", ";")):
            continue
        if text.startswith("[") and text.endswith("]"):
            header = text[1:-1].strip()
            section, _, suffix = header.partition(":")
            kind = {"children": "children", "vars": "vars"}.get(suffix, "hosts")
            if suffix and kind == "hosts":
                skipped.append({"where": f"line {line}", "reason": f"unknown section [{header}]"})
            continue
        try:
            tokens = shlex.split(text, comments=True, posix=True)
        except ValueError:
            skipped.append({"where": f"line {line}", "reason": "unreadable line"})
            continue
        if not tokens:
            continue
        if kind == "children":
            groups.children.setdefault(section, set()).add(tokens[0])
        elif kind == "vars":
            groups.vars.setdefault(section, {}).update(_ini_vars(tokens))
        else:
            for host in expand_host_pattern(tokens[0], MAX_LIST_SYSTEMS - len(groups.order)):
                groups.add_host(section, host, _ini_vars(tokens[1:]))
    return groups.systems(skipped)


def _walk_yaml_group(groups: _Groups, name: str, node: Any, depth: int = 0) -> None:
    if depth > 50 or not isinstance(node, dict):
        return
    hosts = node.get("hosts")
    if isinstance(hosts, dict):
        for pattern, variables in hosts.items():
            for host in expand_host_pattern(str(pattern), MAX_LIST_SYSTEMS - len(groups.order)):
                groups.add_host(name, host, variables if isinstance(variables, dict) else None)
    elif isinstance(hosts, list):
        for pattern in hosts:
            for host in expand_host_pattern(str(pattern), MAX_LIST_SYSTEMS - len(groups.order)):
                groups.add_host(name, host)
    if isinstance(node.get("vars"), dict):
        groups.vars.setdefault(name, {}).update(node["vars"])
    children = node.get("children")
    if isinstance(children, dict):
        for child, child_node in children.items():
            groups.children.setdefault(name, set()).add(str(child))
            _walk_yaml_group(groups, str(child), child_node, depth + 1)


def _parse_ansible_yaml(content: str, skipped: list[dict[str, Any]]) -> list[ListedSystem]:
    import yaml

    try:
        data = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        raise ListError(f"The YAML cannot be read: {str(exc).splitlines()[0][:200]}") from exc
    if not isinstance(data, dict):
        raise ListError("An Ansible YAML inventory is a mapping of groups (usually starting with all:).")
    groups = _Groups()
    for name, node in data.items():
        _walk_yaml_group(groups, str(name), node)
    return groups.systems(skipped)


def _parse_ansible_json(data: dict[str, Any], skipped: list[dict[str, Any]]) -> list[ListedSystem]:
    groups = _Groups()
    hostvars = (data.get("_meta") or {}).get("hostvars") if isinstance(data.get("_meta"), dict) else None
    for name, node in data.items():
        if name == "_meta":
            continue
        if isinstance(node, list):  # the old shorthand: group -> [hosts]
            node = {"hosts": node}
        if not isinstance(node, dict):
            continue
        for host in node.get("hosts") or []:
            groups.add_host(name, str(host))
        for child in node.get("children") or []:
            groups.children.setdefault(name, set()).add(str(child))
        if isinstance(node.get("vars"), dict):
            groups.vars.setdefault(name, {}).update(node["vars"])
    for host, variables in (hostvars or {}).items():
        if isinstance(variables, dict) and host in groups.host_vars:
            groups.host_vars[host].update(variables)
    return groups.systems(skipped)


def _parse_hecate_json(data: Any, skipped: list[dict[str, Any]]) -> list[ListedSystem]:
    rows = data.get("systems") if isinstance(data, dict) else data
    if not isinstance(rows, list):
        raise ListError('A Hecate list is {"systems": [{"name": …}, …]}.')
    systems: dict[str, ListedSystem] = {}
    for index, row in enumerate(rows, start=1):
        name = _clean_name(row.get("name")) if isinstance(row, dict) else _clean_name(row)
        if name is None:
            skipped.append({"where": f"entry {index}", "reason": "no usable name"})
            continue
        values = row if isinstance(row, dict) else {}
        groups = values.get("groups") if isinstance(values.get("groups"), list) else []
        _merge(systems, name, groups, _clean_fields(values, f"entry {index}", skipped))
    return list(systems.values())


# ---------------------------------------------------------------- entry points


def detect_list_format(content: str) -> str:
    text = content.lstrip("\ufeff").strip()
    if text.startswith(("{", "[")):
        try:
            data = json.loads(text)
        except json.JSONDecodeError:  # an INI section header starts with "[" too
            data = None
        if isinstance(data, dict) and ("_meta" in data or any(
            isinstance(v, dict) and ("hosts" in v or "children" in v) for v in data.values()
        )):
            return "ansible-json"
        if data is not None:
            return "json"
    first = next((line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#")), "")
    if re.match(r"^\[[^\]]+\]$", first):
        return "ansible-ini"
    if re.match(r"^[A-Za-z0-9_.-]+:\s*$", first) or re.search(r"^\s+hosts:\s*$", text, re.MULTILINE):
        return "ansible-yaml"
    if "," in first and any(alias in [c.strip().lower() for c in first.split(",")] for alias in _NAME_ALIASES):
        return "csv"
    if any("=" in line and not line.strip().startswith("#") for line in text.splitlines()[:50]):
        return "ansible-ini"
    return "text"


def parse_system_list(content: str, fmt: str | None = None) -> ParsedList:
    """Systems named by a list; ``ListError`` when it cannot be read."""
    if len(content.encode("utf-8", errors="ignore")) > MAX_LIST_BYTES:
        raise ListError(f"The list is larger than {MAX_LIST_BYTES // (1024 * 1024)} MB.")
    content = content.lstrip("\ufeff")
    fmt = fmt or detect_list_format(content)
    if fmt not in LIST_FORMATS:
        raise ListError(f"Unknown format {fmt!r}; use one of {', '.join(LIST_FORMATS)}.")
    skipped: list[dict[str, Any]] = []
    if fmt == "csv":
        systems = _parse_csv(content, skipped)
    elif fmt == "text":
        systems = _parse_text(content, skipped)
    elif fmt == "ansible-ini":
        systems = _parse_ansible_ini(content, skipped)
    elif fmt == "ansible-yaml":
        systems = _parse_ansible_yaml(content, skipped)
    else:
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ListError(f"The JSON cannot be read: {exc.msg} (line {exc.lineno}).") from exc
        if fmt == "ansible-json":
            if not isinstance(data, dict):
                raise ListError("ansible-inventory --list writes an object of groups.")
            systems = _parse_ansible_json(data, skipped)
        else:
            systems = _parse_hecate_json(data, skipped)
    if len(systems) > MAX_LIST_SYSTEMS:
        raise ListError(f"The list names {len(systems)} systems; the limit is {MAX_LIST_SYSTEMS}.")
    return ParsedList(format=fmt, systems=systems, skipped=skipped[:200])
