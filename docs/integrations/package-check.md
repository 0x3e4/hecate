# Package check for agents and CI

AI coding assistants add dependencies on their own, and worms like Shai-Hulud spread through exactly
that path: a fresh release from a taken-over maintainer account, installed minutes after it was
published. Hecate's **package check** answers "may I install this?" before the install happens, for
an assistant (MCP tool or a hook) and for CI.

```
GET /api/v1/packages/check?ecosystem=npm&name=left-pad&version=1.3.0
```

| Parameter | |
| --- | --- |
| `ecosystem` | `npm`, `pypi`, `go`, `maven`, `cargo`, `nuget`, `rubygems` or `packagist` (aliases such as `pip`, `golang`, `crates.io`, `gem`, `composer` work too) |
| `name` | the package name: npm `@scope/name`, Maven `group:artifact`, a Go module path |
| `version` | optional; without it the registry's latest release is checked, which is what an unpinned install fetches (`versionSource: "latest"`) |

The answer carries a `verdict` and the `reasons` behind it:

| Verdict | Reasons |
| --- | --- |
| `block` | a known malicious package (`malicious`: an OSV `MAL-*` record covering the version or the whole package), a vulnerability affecting the version that CISA lists as exploited (`kev`), a critical vulnerability (`critical`) |
| `warn` | other vulnerabilities affecting the version (`vulnerable`); a release younger than `SCA_FRESH_RELEASE_DAYS` (`fresh_release`); an npm version published by an account that published none of the versions before it (`publisher_changed`); no release for `SCA_UNMAINTAINED_DAYS` (`unmaintained`); a deprecated version (`deprecated`); a package the registry doesn't know, often a typo or a name an assistant made up (`unknown_package`); an unknown version (`unknown_version`); some versions of the package are malicious (`malicious_versions`) |
| `ok` | none of these |

`info` reasons explain without changing the verdict: a fresh release that an advisory names as its fix
waives the cooldown (`fresh_release_fix`, the "zero-day override"), and maintainers added since the
previous npm version are listed (`new_maintainers`).

Beside the verdict the answer lists `malicious` (each record, whether it covers the version or the whole
package), `vulnerabilities` affecting the version (severity, CVSS, EPSS, KEV, the fixed versions the
advisory names), `release` (`publishedAt`, `ageDays`, `latestVersion`, `freshRelease`, `unmaintained`,
`publisherChanged`, `publisher`, `deprecated`, `packageFound`) and `recommendedVersion`: the lowest
named fix (or the latest release) that none of the matched advisories covers.

Advisories are matched the way "Affected in your scans" matches an SBOM: the version has to lie in an
advisory's affected range, and a registry package only takes the ranges of an advisory entry whose vendor
is that registry or the package's own namespace, so npm `console` never borrows the ranges of Citrix
NetScaler Console. Release data comes from deps.dev, Packagist and the npm registry, cached like the
[supply-chain signals](../sca-scanning.md#supply-chain-signals) of a scan. The endpoint is a read: it
is public unless the instance requires a login, and then takes the same credentials as every other read.

## MCP: `check_package`

The MCP server exposes the same check as the read tool `check_package(ecosystem, name, version?)`
(any authenticated MCP user, rate-limited like every tool). Its description tells the assistant to call
it before adding or upgrading a dependency and to follow the verdict. A line in your project's
`CLAUDE.md` or agent instructions makes that explicit:

```markdown
Before adding or upgrading a dependency, call the Hecate MCP tool `check_package`.
Do not install on `block`; on `warn`, tell me the reasons and prefer `recommendedVersion`.
```

## Claude Code hook

Instructions can be ignored; a **PreToolUse hook** runs on every shell command the agent wants to run.
The script below reads the command from the hook input, picks out `npm install`, `pnpm add`, `yarn add`,
`bun add`, `pip install`, `uv add` and `poetry add`, asks Hecate about each package and then blocks the
command (exit code 2, the reasons go back to the agent) or asks you to confirm it on `warn`.

Save it as `~/.claude/hooks/hecate-package-check.py`:

```python
#!/usr/bin/env python3
"""Claude Code PreToolUse hook: ask Hecate before a package gets installed."""
import json
import os
import re
import shlex
import sys
import urllib.parse
import urllib.request

HECATE_URL = os.environ.get("HECATE_URL", "https://hecate.pw").rstrip("/")
API_KEY = os.environ.get("HECATE_API_KEY")  # only needed when the instance requires a login
FAIL_CLOSED = os.environ.get("HECATE_FAIL_CLOSED") == "1"

INSTALLERS = {
    ("npm", "install"): "npm", ("npm", "i"): "npm", ("npm", "add"): "npm",
    ("pnpm", "add"): "npm", ("yarn", "add"): "npm", ("bun", "add"): "npm",
    ("pip", "install"): "pypi", ("pip3", "install"): "pypi",
    ("uv", "add"): "pypi", ("poetry", "add"): "pypi",
}
EXACT = re.compile(r"^v?\d+(\.\d+)*([-.+]\w+)*$")
# Flags whose value is not a package (requirements files, indexes, workspaces).
VALUE_FLAGS = {"-r", "--requirement", "-c", "--constraint", "-e", "--editable", "-i", "--index-url",
               "--extra-index-url", "--registry", "-w", "--workspace", "--filter", "--group", "-G"}


def packages(command):
    for part in re.split(r"&&|\|\||;|\|", command):
        try:
            argv = shlex.split(part)
        except ValueError:
            continue
        if len(argv) > 2 and os.path.basename(argv[0]).startswith("python") and argv[1] == "-m":
            argv = argv[2:]
        ecosystem = INSTALLERS.get((os.path.basename(argv[0]), argv[1])) if len(argv) > 1 else None
        if not ecosystem:
            continue
        skip = False
        for arg in argv[2:]:
            if skip:
                skip = False
                continue
            if arg in VALUE_FLAGS:
                skip = True
                continue
            if arg.startswith("-") or "://" in arg or arg.startswith((".", "/", "git+", "file:")):
                continue
            if arg.endswith((".txt", ".tgz", ".tar.gz", ".whl", ".zip")):
                continue
            yield (ecosystem, *split(ecosystem, arg))


def split(ecosystem, spec):
    if ecosystem == "npm":
        scope, rest = ("@", spec[1:]) if spec.startswith("@") else ("", spec)
        name, _, version = rest.partition("@")
        return scope + name, version if EXACT.match(version) else None
    name, sep, version = spec.partition("==")
    name = re.split(r"[<>=!~\[;@ ]", name)[0]
    return name, version if sep and EXACT.match(version) else None


def check(ecosystem, name, version):
    query = {"ecosystem": ecosystem, "name": name}
    if version:
        query["version"] = version
    request = urllib.request.Request(f"{HECATE_URL}/api/v1/packages/check?{urllib.parse.urlencode(query)}")
    if API_KEY:
        request.add_header("X-API-Key", API_KEY)
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.load(response)


def main():
    event = json.load(sys.stdin)
    command = (event.get("tool_input") or {}).get("command") or ""
    blocked, warned = [], []
    for ecosystem, name, version in packages(command):
        try:
            result = check(ecosystem, name, version)
        except Exception as exc:  # Hecate unreachable: let the install run unless told otherwise
            if FAIL_CLOSED:
                blocked.append(f"{name}: package check failed ({exc})")
            continue
        label = f"{name}@{result.get('version') or 'latest'}"
        reasons = "; ".join(r["message"] for r in result.get("reasons", []) if r["level"] != "info")
        if result.get("verdict") == "block":
            blocked.append(f"{label}: {reasons}")
        elif result.get("verdict") == "warn":
            hint = f" Hecate suggests {result['recommendedVersion']}." if result.get("recommendedVersion") else ""
            warned.append(f"{label}: {reasons}{hint}")
    if blocked:
        print("Hecate blocked the install:\n" + "\n".join(blocked), file=sys.stderr)
        sys.exit(2)
    if warned:
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask",
            "permissionDecisionReason": "Hecate: " + " | ".join(warned),
        }}))


if __name__ == "__main__":
    main()
```

and register it in `~/.claude/settings.json` (or the project's `.claude/settings.json`):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "python3 ~/.claude/hooks/hecate-package-check.py" }
        ]
      }
    ]
  },
  "env": { "HECATE_URL": "https://hecate.pw" }
}
```

Point `HECATE_URL` at your own instance; `https://hecate.pw` is the public demo. The hook is
deliberately fail-open: when Hecate can't be reached the command runs, unless `HECATE_FAIL_CLOSED=1`.
A check never waits longer than `PACKAGE_CHECK_RELEASE_TIMEOUT_SECONDS` (5) for registry data; past that the
verdict rests on the advisories alone. Callers without a session get `PACKAGE_CHECK_RATE_PER_MINUTE` (120)
checks per minute per client and a 429 beyond that, so a CI job checking a large lockfile should sign its
requests or pace them.
Version ranges (`^1.2`, `>=2`) are checked as the latest release, which is what they usually resolve to.

## CI

In a job that adds or updates dependencies, check every changed package and fail on `block`. A minimal
shell step:

```bash
check() {  # ecosystem name [version]
  curl -fsS --get "${HECATE_URL}/api/v1/packages/check" \
    --data-urlencode "ecosystem=$1" --data-urlencode "name=$2" ${3:+--data-urlencode "version=$3"}
}

RESULT=$(check npm left-pad 1.3.0)
echo "${RESULT}" | jq -r '.reasons[] | "\(.level): \(.message)"'
[ "$(echo "${RESULT}" | jq -r '.verdict')" = "block" ] && exit 1
```

For the dependencies a scan already found, the [supply-chain gate](cicd.md#supply-chain-gate) reads the
same signals from the scan's SBOM.

## Related pages

- [SCA Scanning](../sca-scanning.md#supply-chain-signals) — supply-chain signals on scanned SBOMs.
- [MCP Server](mcp.md) — connecting an assistant to Hecate.
- [Malware Detection & Feed](../sca/malware.md) — where the `MAL-*` records come from.
