#!/usr/bin/env bash
# Collects everything vex/tools/generate.py needs for one image into
# vex/.work/<name>/ (gitignored):
#   trivy.json, grype.json   scanner findings (the two Hecate itself uses)
#   loaded.txt               OS packages the service loads or executes
#   govulncheck/<bin>.json   govulncheck -mode=binary per Go binary
#
#   vex/tools/collect.sh <backend|frontend|docs|scanner> [image-ref]
# image-ref defaults to ghcr.io/0x3e4/hecate-<name>:latest. Needs Docker; the
# scanners run from their pinned images, nothing is installed on the host.
set -euo pipefail

TRIVY_IMAGE=aquasec/trivy:0.76.1
GRYPE_IMAGE=anchore/grype:v0.121.1
GO_IMAGE=golang:1.27.3-trixie
GOVULNCHECK_VERSION=v1.1.4

name=${1:?usage: collect.sh <backend|frontend|docs|scanner> [image-ref]}
image=${2:-ghcr.io/0x3e4/hecate-$name:latest}
here=$(cd "$(dirname "$0")" && pwd)
work="$here/../.work/$name"
rm -rf "$work"
mkdir -p "$work/govulncheck" "$work/gobin"
# Keeps the scratch directory out of git in any clone; git honours an
# untracked .gitignore.
printf '*\n' > "$here/../.work/.gitignore"

# Docker Desktop on Windows (Git Bash) needs Windows paths and no path mangling.
hostpath() { if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else echo "$1"; fi; }
export MSYS_NO_PATHCONV=1
sock=/var/run/docker.sock

if [ "$name" = source ]; then
    # The repository's own dependencies: a clean export of HEAD, so a local
    # node_modules or .venv does not count.
    repo=$(cd "$here/../.." && pwd)
    src="$work/tree"
    mkdir -p "$src"
    git -C "$(hostpath "$repo")" archive --format=tar -o "$(hostpath "$work/tree.tar")" HEAD
    tar -xf "$work/tree.tar" -C "$src" && rm -f "$work/tree.tar"
    echo "[source] trivy"
    docker run --rm -v "$(hostpath "$src"):/src:ro" -v hecate-vex-trivy:/root/.cache "$TRIVY_IMAGE" \
        fs -q --scanners vuln --format json /src > "$work/trivy.json"
    echo "[source] grype"
    docker run --rm -v "$(hostpath "$src"):/src:ro" -v hecate-vex-grype:/root/.cache/grype "$GRYPE_IMAGE" \
        -q -o json dir:/src > "$work/grype.json"
    git -C "$(hostpath "$repo")" rev-parse HEAD > "$work/digest.txt"
    rm -rf "$src" "$work/gobin" "$work/govulncheck"
    echo "[source] done: $work"
    exit 0
fi

gobins=()
case "$name" in
    backend)
        roots=app; semgrep=0
        execs=(sh cat python3.14) ;;
    scanner)
        roots=app; semgrep=1
        execs=(sh cat sed git /usr/lib/git-core/git-remote-http /usr/lib/git-core/git-remote-https
               /usr/share/dotnet/dotnet '/usr/share/dotnet/shared/Microsoft.NETCore.App/*/*.so'
               '/usr/local/lib/devskim/runtimes/linux-x64/native/*.so'
               '/opt/semgrep/lib/python3.14/site-packages/semgrep/bin/*')
        gobins=(trivy grype syft osv-scanner dive dockle trufflehog skopeo) ;;
    frontend|docs)
        roots=-; semgrep=0
        execs=(nginx sh /docker-entrypoint.sh '/docker-entrypoint.d/*') ;;
    *) echo "unknown image name: $name" >&2; exit 2 ;;
esac

echo "[$name] trivy"
docker run --rm -v "$sock:$sock" -v hecate-vex-trivy:/root/.cache "$TRIVY_IMAGE" \
    image -q --scanners vuln --timeout 30m --format json "$image" > "$work/trivy.json"
echo "[$name] grype"
docker run --rm -v "$sock:$sock" -v hecate-vex-grype:/root/.cache/grype "$GRYPE_IMAGE" \
    -q -o json "$image" > "$work/grype.json"

echo "[$name] runtime evidence"
docker run --rm --entrypoint sh -e SEMGREP="$semgrep" -v "$(hostpath "$here"):/vex-tools:ro" "$image" \
    /vex-tools/evidence.sh "$roots" "${execs[@]}" > "$work/loaded.txt"
# binary package -> source package, so a loaded libc6 also covers libc-bin
docker run --rm --entrypoint sh "$image" -c '
    if command -v dpkg-query >/dev/null 2>&1; then dpkg-query -W -f "\${binary:Package} \${source:Package}\n"
    else apk list -I 2>/dev/null | sed -E "s/^([^ ]+)-[0-9][^ ]*-r[0-9]+ [^ ]+ \{([^}]+)\}.*/\1 \2/"; fi' > "$work/sources.txt"

if [ "${#gobins[@]}" -gt 0 ]; then
    echo "[$name] govulncheck"
    docker run --rm --entrypoint sh -v "$(hostpath "$work/gobin"):/out" "$image" \
        -c 'for b in "$@"; do cp "$(command -v "$b")" /out/; done' sh "${gobins[@]}"
    docker run --rm -v "$(hostpath "$work"):/w" -v hecate-vex-go:/go "$GO_IMAGE" sh -c "
        go install golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION >/dev/null 2>&1
        for b in /w/gobin/*; do
            n=\$(basename \"\$b\")
            /go/bin/govulncheck -mode=binary -format json \"\$b\" > /w/govulncheck/\$n.json 2> /w/govulncheck/\$n.err || true
        done"
fi
rm -rf "$work/gobin"
docker image inspect --format '{{index .RepoDigests 0}}' "$image" > "$work/digest.txt" 2>/dev/null \
    || docker image inspect --format '{{.Id}}' "$image" > "$work/digest.txt"
echo "[$name] done: $work"
