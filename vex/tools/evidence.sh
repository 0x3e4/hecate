#!/bin/sh
# Runs inside an image (collect.sh mounts vex/tools at /vex-tools) and prints
# the OS packages a service actually uses, one per line:
#   - every shared object the service's Python process maps after importing
#     its whole package tree (maps.py), and
#   - every given executable plus its ldd closure.
# Arguments may be globs; they are expanded inside the image.
#   evidence.sh <python-root|-> <executable-or-glob>...
# SEMGREP=1 additionally imports semgrep from /opt/semgrep.
set -u
roots="$1"
shift
out=/tmp/vex-evidence
: > "$out"
if [ "$roots" != "-" ]; then
    (cd / && PYTHONPATH=/:/scanner python3 /vex-tools/maps.py $roots) >> "$out" 2>/dev/null
fi
if [ "${SEMGREP:-0}" = 1 ] && [ -x /opt/semgrep/bin/python ]; then
    /opt/semgrep/bin/python /vex-tools/maps.py semgrep >> "$out" 2>/dev/null
fi
for pattern in "$@"; do
    for e in $pattern; do
        p=$(command -v "$e" 2>/dev/null || echo "$e")
        [ -e "$p" ] || continue
        p=$(readlink -f "$p")
        echo "$p" >> "$out"
        ldd "$p" 2>/dev/null | awk '/=>/ {print $3} /^[ \t]*\// {print $1}' >> "$out"
    done
done
for f in $(sort -u "$out"); do
    # Only real files: ldd prints "not found" for a missing library, and
    # `dpkg -S not` would pattern-match some unrelated package's path.
    case "$f" in /*) ;; *) continue ;; esac
    [ -e "$f" ] || continue
    r=$(readlink -f "$f")
    if command -v dpkg >/dev/null 2>&1; then
        { dpkg -S "$f" 2>/dev/null; dpkg -S "$r" 2>/dev/null; } | grep -v '^diversion' | head -1 | cut -d: -f1 | cut -d, -f1
    else
        apk info -W "$r" 2>/dev/null | sed -n 's/.* is owned by //p' | sed 's/-[0-9][^-]*-r[0-9]*$//'
    fi
done | sed '/^$/d' | sort -u
