from __future__ import annotations

import asyncio
import base64
import binascii
import io
import json
import logging
import os
import re
import shutil
import tempfile
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

from app.hecate_analyzer import run_analysis
from app.malware_detector import run_detection
from app.provenance import check_provenance_batch
from app.models import ScannerResult


def setup_auth(auth_entries: str) -> None:
    """Configure authentication for both container registries and git cloning.

    Format: host:token[,host2:token2]
    Sets up ~/.docker/config.json (for Trivy/Grype/Syft) and
    ~/.git-credentials (for git clone of private repos).
    """
    docker_auths: dict[str, dict[str, str]] = {}
    git_credentials: list[str] = []

    for entry in auth_entries.split(","):
        entry = entry.strip()
        if not entry:
            continue
        parts = entry.split(":", 1)
        if len(parts) != 2:
            continue
        host, token = parts

        # Docker registry auth
        encoded = base64.b64encode(f"{token}:".encode()).decode()
        docker_auths[host] = {"auth": encoded}

        # Git credential
        git_credentials.append(f"https://oauth2:{token}@{host}")

    # Write ~/.docker/config.json
    docker_dir = Path.home() / ".docker"
    docker_dir.mkdir(parents=True, exist_ok=True)
    config_path = docker_dir / "config.json"
    config_path.write_text(json.dumps({"auths": docker_auths}, indent=2))

    # Write ~/.git-credentials
    if git_credentials:
        cred_path = Path.home() / ".git-credentials"
        cred_path.write_text("\n".join(git_credentials) + "\n")
        cred_path.chmod(0o600)

        gitconfig_path = Path.home() / ".gitconfig"
        gitconfig_content = "[credential]\n\thelper = store\n"
        if gitconfig_path.exists():
            existing = gitconfig_path.read_text()
            if "helper = store" not in existing:
                gitconfig_path.write_text(existing + "\n" + gitconfig_content)
        else:
            gitconfig_path.write_text(gitconfig_content)


def extract_source_archive(source_archive_base64: str) -> str:
    """Extract a base64-encoded zip archive into a temporary directory."""
    try:
        archive_bytes = base64.b64decode(source_archive_base64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise RuntimeError(f"Invalid source archive data: {exc}") from exc

    tmp_dir = tempfile.mkdtemp(prefix="hecate-upload-")
    root = Path(tmp_dir).resolve()
    extracted_files = 0

    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as zf:
            for member in zf.infolist():
                member_path = Path(member.filename)
                if member_path.is_absolute() or ".." in member_path.parts:
                    raise RuntimeError("Archive contains unsafe paths")

                destination = (root / member_path).resolve()
                if destination != root and root not in destination.parents:
                    raise RuntimeError("Archive contains unsafe paths")

                if member.is_dir():
                    destination.mkdir(parents=True, exist_ok=True)
                    continue

                destination.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(member, "r") as source_file, destination.open("wb") as output_file:
                    shutil.copyfileobj(source_file, output_file)
                extracted_files += 1
    except Exception as exc:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise RuntimeError(f"Invalid ZIP archive: {exc}") from exc

    if extracted_files == 0:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise RuntimeError("Uploaded archive is empty")

    return tmp_dir


async def run_scanner(
    scanner_name: str,
    target: str,
    target_type: str,
    source_dir: str | None = None,
) -> ScannerResult:
    """Run a scanner tool and return parsed results."""
    if scanner_name == "trivy":
        return await _run_trivy(target, target_type, source_dir)
    elif scanner_name == "grype":
        return await _run_grype(target, target_type, source_dir)
    elif scanner_name == "syft":
        return await _run_syft(target, target_type, source_dir)
    elif scanner_name == "osv-scanner":
        return await _run_osv_scanner(target, target_type, source_dir)
    elif scanner_name == "hecate":
        return await _run_hecate_analyzer(target, target_type, source_dir)
    elif scanner_name == "dockle":
        return await _run_dockle(target, target_type)
    elif scanner_name == "dive":
        return await _run_dive(target, target_type)
    elif scanner_name == "semgrep":
        return await _run_semgrep(target, target_type, source_dir)
    elif scanner_name == "trufflehog":
        return await _run_trufflehog(target, target_type, source_dir)
    else:
        return ScannerResult(scanner=scanner_name, format="unknown", report={}, error=f"Unknown scanner: {scanner_name}")


async def _run_command(cmd: list[str], timeout: int = 600) -> tuple[str, str, int]:
    """Run a subprocess command and return stdout, stderr, returncode."""
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        return "", f"Command not found: {cmd[0]}", -1
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        process.kill()
        await process.communicate()
        return "", f"Scanner timed out after {timeout}s", -1
    return stdout.decode(errors="replace"), stderr.decode(errors="replace"), process.returncode or 0


async def _clone_repo(url: str) -> str:
    """Clone a git repository to a temporary directory. Returns the path."""
    tmp_dir = tempfile.mkdtemp(prefix="hecate-scan-")
    _, stderr, rc = await _run_command(["git", "clone", "--depth", "1", url, tmp_dir], timeout=120)
    if rc != 0:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise RuntimeError(f"Failed to clone {url}: {stderr}")
    return tmp_dir


async def get_git_commit_sha(repo_dir: str) -> str | None:
    """Get HEAD commit SHA from a cloned repo."""
    stdout, _, rc = await _run_command(["git", "-C", repo_dir, "rev-parse", "HEAD"], timeout=10)
    if rc == 0 and stdout.strip():
        return stdout.strip()
    return None


async def get_remote_commit_sha(url: str) -> str | None:
    """Get HEAD commit SHA from a remote repo via ls-remote (no clone needed)."""
    stdout, _, rc = await _run_command(["git", "ls-remote", url, "HEAD"], timeout=30)
    if rc == 0 and stdout.strip():
        # Output format: "<sha>\tHEAD"
        return stdout.strip().split()[0]
    return None


async def get_image_digest(image_ref: str) -> str | None:
    """Get image digest via skopeo or docker inspect. Falls back to trivy/grype metadata."""
    # Try docker inspect first (works if image is pulled)
    stdout, _, rc = await _run_command(
        ["docker", "inspect", "--format", "{{index .RepoDigests 0}}", image_ref], timeout=30,
    )
    if rc == 0 and stdout.strip() and "@" in stdout.strip():
        # Extract just the digest part: registry/name@sha256:abc... -> sha256:abc...
        return stdout.strip().split("@", 1)[1]
    # Try skopeo (doesn't require pulling)
    stdout, _, rc = await _run_command(
        ["skopeo", "inspect", "--format", "{{.Digest}}", f"docker://{image_ref}"], timeout=30,
    )
    if rc == 0 and stdout.strip():
        return stdout.strip()
    return None


def _sanitize_error(stderr: str, max_len: int = 300) -> str:
    """Extract a human-readable error from scanner stderr, truncating stack traces."""
    if not stderr:
        return stderr
    # Go panics: keep only the first line (before goroutine dump)
    if "panic:" in stderr:
        for line in stderr.splitlines():
            line = line.strip()
            if line.startswith("panic:"):
                return line
        # Fallback: first line containing "panic"
        return next((l.strip() for l in stderr.splitlines() if "panic" in l.lower()), stderr[:max_len])
    # Java / Python tracebacks: keep the last meaningful line
    if "Traceback" in stderr or "Exception" in stderr:
        lines = [l.strip() for l in stderr.strip().splitlines() if l.strip()]
        return lines[-1] if lines else stderr[:max_len]
    # Generic: first non-empty line, truncated
    first = next((l.strip() for l in stderr.splitlines() if l.strip()), stderr)
    return first[:max_len]


def _parse_json_output(stdout: str, scanner: str, fmt: str) -> ScannerResult:
    """Parse JSON output from a scanner, handling errors gracefully."""
    if not stdout.strip():
        return ScannerResult(scanner=scanner, format=fmt, report={}, error="No output from scanner")
    try:
        report = json.loads(stdout)
        return ScannerResult(scanner=scanner, format=fmt, report=report)
    except json.JSONDecodeError as exc:
        return ScannerResult(scanner=scanner, format=fmt, report={}, error=f"Invalid JSON output: {exc}")


async def _run_trivy(target: str, target_type: str, source_dir: str | None = None) -> ScannerResult:
    """Run Trivy scanner."""
    clone_dir: str | None = None
    try:
        if target_type == "container_image":
            cmd = ["trivy", "image", "--format", "json", "--quiet", "--list-all-pkgs", target]
        else:
            scan_dir = source_dir
            if not scan_dir:
                clone_dir = await _clone_repo(target)
                scan_dir = clone_dir
            cmd = ["trivy", "fs", "--format", "json", "--quiet", "--list-all-pkgs", scan_dir]

        stdout, stderr, rc = await _run_command(cmd)
        if rc != 0 and not stdout.strip():
            return ScannerResult(scanner="trivy", format="trivy-json", report={}, error=f"Trivy failed (exit {rc}): {_sanitize_error(stderr)}")
        return _parse_json_output(stdout, "trivy", "trivy-json")
    except RuntimeError as exc:
        return ScannerResult(scanner="trivy", format="trivy-json", report={}, error=str(exc))
    finally:
        if clone_dir:
            shutil.rmtree(clone_dir, ignore_errors=True)


async def _run_grype(target: str, target_type: str, source_dir: str | None = None) -> ScannerResult:
    """Run Grype scanner."""
    clone_dir: str | None = None
    try:
        if target_type == "container_image":
            cmd = ["grype", target, "-o", "json", "--quiet"]
        else:
            scan_dir = source_dir
            if not scan_dir:
                clone_dir = await _clone_repo(target)
                scan_dir = clone_dir
            cmd = ["grype", f"dir:{scan_dir}", "-o", "json", "--quiet"]

        stdout, stderr, rc = await _run_command(cmd)
        if rc != 0 and not stdout.strip():
            return ScannerResult(scanner="grype", format="grype-json", report={}, error=f"Grype failed (exit {rc}): {_sanitize_error(stderr)}")
        return _parse_json_output(stdout, "grype", "grype-json")
    except RuntimeError as exc:
        return ScannerResult(scanner="grype", format="grype-json", report={}, error=str(exc))
    finally:
        if clone_dir:
            shutil.rmtree(clone_dir, ignore_errors=True)


async def _run_syft(target: str, target_type: str, source_dir: str | None = None) -> ScannerResult:
    """Run Syft SBOM generator."""
    clone_dir: str | None = None
    try:
        if target_type == "container_image":
            cmd = ["syft", target, "-o", "cyclonedx-json", "--quiet"]
        else:
            scan_dir = source_dir
            if not scan_dir:
                clone_dir = await _clone_repo(target)
                scan_dir = clone_dir
            cmd = ["syft", f"dir:{scan_dir}", "-o", "cyclonedx-json", "--quiet"]

        stdout, stderr, rc = await _run_command(cmd)
        if rc != 0 and not stdout.strip():
            return ScannerResult(scanner="syft", format="cyclonedx-json", report={}, error=f"Syft failed (exit {rc}): {_sanitize_error(stderr)}")
        return _parse_json_output(stdout, "syft", "cyclonedx-json")
    except RuntimeError as exc:
        return ScannerResult(scanner="syft", format="cyclonedx-json", report={}, error=str(exc))
    finally:
        if clone_dir:
            shutil.rmtree(clone_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# requirements.txt pre-processing for OSV Scanner
# ---------------------------------------------------------------------------

# Matches bare package names without version specifiers: "flask", "passlib[argon2]"
# Does NOT match lines with ==, >=, <=, ~=, !=, <, > operators
_BARE_PKG_RE = re.compile(
    r"^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?(\[[^\]]+\])?)\s*(#.*)?$"
)

_SKIP_DIRS_REQ = frozenset({
    "node_modules", ".git", "vendor", "dist", "build",
    "__pycache__", ".venv", "venv", ".tox", ".next",
})


async def _get_latest_pypi_version(package_name: str) -> str | None:
    """Fetch latest version from PyPI JSON API. Returns None on failure."""
    loop = asyncio.get_event_loop()

    def _fetch() -> str | None:
        url = f"https://pypi.org/pypi/{package_name}/json"
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            return data.get("info", {}).get("version")

    try:
        return await loop.run_in_executor(None, _fetch)
    except Exception:
        return None


async def _pin_requirements_files(scan_dir: str) -> list[str]:
    """Resolve unpinned requirements.txt packages to latest PyPI version.

    OSV Scanner's osv-scalibr resolves unpinned packages to minimum/oldest
    satisfying versions, producing false positive CVEs. This pre-processor
    pins bare package names to their actual latest version before scanning.

    Returns list of modified file paths.
    """
    root = Path(scan_dir)
    modified: list[str] = []

    for req_path in root.rglob("requirements*.txt"):
        if any(part in _SKIP_DIRS_REQ for part in req_path.parts):
            continue

        try:
            content = req_path.read_text(errors="replace")
        except OSError:
            continue

        lines = content.splitlines()
        new_lines: list[str] = []
        changed = False

        for line in lines:
            stripped = line.strip()
            # Skip empty, comments, flags, URLs, editable installs
            if not stripped or stripped.startswith(("#", "-", "git+", "http")):
                new_lines.append(line)
                continue

            m = _BARE_PKG_RE.match(stripped)
            if m:
                pkg_name = m.group(1).split("[")[0]  # strip extras like [argon2]
                latest = await _get_latest_pypi_version(pkg_name)
                if latest:
                    new_lines.append(f"{stripped}=={latest}")
                    changed = True
                    logger.info("Pinned %s to latest version %s", pkg_name, latest)
                    continue

            new_lines.append(line)

        if changed:
            req_path.write_text("\n".join(new_lines) + "\n")
            modified.append(str(req_path.relative_to(root)))

    return modified


async def _run_osv_scanner(
    target: str,
    target_type: str,
    source_dir: str | None = None,
) -> ScannerResult:
    """Run OSV Scanner. Only supports source repos (lockfile scanning)."""
    if target_type == "container_image":
        return ScannerResult(
            scanner="osv-scanner", format="osv-json", report={},
            error="OSV Scanner does not support container image scanning — use it with source repositories",
        )

    clone_dir: str | None = None
    try:
        scan_dir = source_dir
        if not scan_dir:
            clone_dir = await _clone_repo(target)
            scan_dir = clone_dir
        # Resolve unpinned requirements.txt packages to latest PyPI versions
        # so OSV checks real versions instead of minimum/oldest
        pinned = await _pin_requirements_files(scan_dir)
        if pinned:
            logger.info("Pre-pinned %d requirements file(s): %s", len(pinned), pinned)

        # --no-resolve: prevent OSV's transitive dep resolver from guessing
        # minimum versions for manifest files (produces false positives)
        cmd = ["osv-scanner", "scan", "--format", "json", "--no-resolve", "-r", scan_dir]

        stdout, stderr, rc = await _run_command(cmd)
        # osv-scanner returns exit code 1 when vulnerabilities are found (expected)
        # exit 128 with "No package sources found" means the repo has no lockfiles/manifests — not an error
        if rc not in (0, 1):
            if "No package sources found" in stderr:
                return ScannerResult(scanner="osv-scanner", format="osv-json", report={})
            if not stdout.strip():
                return ScannerResult(scanner="osv-scanner", format="osv-json", report={}, error=f"OSV Scanner failed (exit {rc}): {_sanitize_error(stderr)}")
        return _parse_json_output(stdout, "osv-scanner", "osv-json")
    except RuntimeError as exc:
        return ScannerResult(scanner="osv-scanner", format="osv-json", report={}, error=str(exc))
    finally:
        if clone_dir:
            shutil.rmtree(clone_dir, ignore_errors=True)


async def _run_hecate_analyzer(
    target: str,
    target_type: str,
    source_dir: str | None = None,
) -> ScannerResult:
    """Run Hecate's own infrastructure analyzer + malware detection."""
    if target_type == "container_image":
        return ScannerResult(
            scanner="hecate", format="hecate-json", report={},
            error="Hecate Analyzer only supports source repository scanning",
        )

    clone_dir: str | None = None
    try:
        scan_dir = source_dir
        if not scan_dir:
            clone_dir = await _clone_repo(target)
            scan_dir = clone_dir

        # SBOM component extraction (existing)
        sbom = run_analysis(scan_dir)

        # Provenance verification for SBOM components
        components = sbom.get("components", [])
        if components:
            try:
                await check_provenance_batch(components)
            except Exception:
                pass  # provenance is best-effort, don't fail the scan

        # Malware detection (new)
        findings = run_detection(scan_dir)

        report = {
            "components": components,
            "findings": findings,
            "bomFormat": sbom.get("bomFormat", "CycloneDX"),
            "specVersion": sbom.get("specVersion", "1.5"),
        }
        return ScannerResult(scanner="hecate", format="hecate-json", report=report)
    except Exception as exc:
        return ScannerResult(scanner="hecate", format="hecate-json", report={}, error=str(exc))
    finally:
        if clone_dir:
            shutil.rmtree(clone_dir, ignore_errors=True)


async def _run_dockle(target: str, target_type: str) -> ScannerResult:
    """Run Dockle container image linter (CIS Docker Benchmarks)."""
    if target_type != "container_image":
        return ScannerResult(
            scanner="dockle", format="dockle-json", report={},
            error="Dockle only supports container image scanning",
        )

    try:
        cmd = ["dockle", "--format", "json", "--exit-code", "0", target]
        stdout, stderr, rc = await _run_command(cmd)
        if rc != 0 and not stdout.strip():
            return ScannerResult(
                scanner="dockle", format="dockle-json", report={},
                error=f"Dockle failed (exit {rc}): {_sanitize_error(stderr)}",
            )
        return _parse_json_output(stdout, "dockle", "dockle-json")
    except RuntimeError as exc:
        return ScannerResult(scanner="dockle", format="dockle-json", report={}, error=str(exc))


async def _run_dive(target: str, target_type: str) -> ScannerResult:
    """Run Dive image layer analysis.

    Dive cannot pull from registries directly (needs Docker daemon).
    We use skopeo to fetch the image as a docker-archive tar first,
    then pass it to Dive with --source docker-archive.
    """
    if target_type != "container_image":
        return ScannerResult(
            scanner="dive", format="dive-json", report={},
            error="Dive only supports container image scanning",
        )

    output_file = "/tmp/dive-output.json"
    archive_file = "/tmp/dive-image.tar"
    try:
        # Clean up stale files from previous runs
        for f in (output_file, archive_file):
            if os.path.exists(f):
                os.remove(f)

        # Step 1: Pull image via skopeo as docker-archive tar
        skopeo_cmd = [
            "skopeo", "--tmpdir", "/tmp", "copy", "--insecure-policy",
            f"docker://{target}", f"docker-archive:{archive_file}",
        ]
        _, stderr, rc = await _run_command(skopeo_cmd, timeout=300)
        if rc != 0:
            return ScannerResult(
                scanner="dive", format="dive-json", report={},
                error=f"Failed to fetch image via skopeo (exit {rc}): {_sanitize_error(stderr)}",
            )

        # Step 2: Run Dive on the local archive
        cmd = ["dive", f"docker-archive://{archive_file}", "--json", output_file, "--ci"]
        _, stderr, rc = await _run_command(cmd)

        # Dive exit code 1 means CI checks failed (expected), only treat as error
        # if no output file was produced
        if not os.path.exists(output_file):
            if rc != 0:
                return ScannerResult(
                    scanner="dive", format="dive-json", report={},
                    error=f"Dive failed (exit {rc}): {_sanitize_error(stderr)}",
                )
            return ScannerResult(scanner="dive", format="dive-json", report={}, error="No output from Dive")

        try:
            with open(output_file) as f:
                report = json.load(f)
        except (json.JSONDecodeError, OSError) as exc:
            return ScannerResult(scanner="dive", format="dive-json", report={}, error=f"Invalid Dive output: {exc}")

        return ScannerResult(scanner="dive", format="dive-json", report=report)
    except RuntimeError as exc:
        return ScannerResult(scanner="dive", format="dive-json", report={}, error=str(exc))
    finally:
        for f in (output_file, archive_file):
            if os.path.exists(f):
                os.remove(f)


async def _run_semgrep(
    target: str,
    target_type: str,
    source_dir: str | None = None,
) -> ScannerResult:
    """Run Semgrep SAST scanner. Only supports source repos."""
    if target_type == "container_image":
        return ScannerResult(
            scanner="semgrep", format="semgrep-json", report={},
            error="Semgrep only supports source repository scanning",
        )

    clone_dir: str | None = None
    try:
        scan_dir = source_dir
        if not scan_dir:
            clone_dir = await _clone_repo(target)
            scan_dir = clone_dir

        # Use security-audit + secrets rulesets by default;
        # configurable via SEMGREP_RULES env var.
        rules = os.environ.get("SEMGREP_RULES", "p/security-audit")
        cmd = [
            "semgrep", "scan",
            "--json", "--quiet",
            f"--config={rules}",
            "--max-target-bytes=1048576",  # skip files > 1MB
            scan_dir,
        ]

        stdout, stderr, rc = await _run_command(cmd)
        # Semgrep exit codes: 0 = no findings, 1 = findings found, other = error
        if rc not in (0, 1):
            if not stdout.strip():
                return ScannerResult(
                    scanner="semgrep", format="semgrep-json", report={},
                    error=f"Semgrep failed (exit {rc}): {_sanitize_error(stderr)}",
                )
        return _parse_json_output(stdout, "semgrep", "semgrep-json")
    except RuntimeError as exc:
        return ScannerResult(scanner="semgrep", format="semgrep-json", report={}, error=str(exc))
    finally:
        if clone_dir:
            shutil.rmtree(clone_dir, ignore_errors=True)


async def _run_trufflehog(
    target: str,
    target_type: str,
    source_dir: str | None = None,
) -> ScannerResult:
    """Run TruffleHog secret scanner. Only supports source repos."""
    if target_type == "container_image":
        return ScannerResult(
            scanner="trufflehog", format="trufflehog-json", report={},
            error="TruffleHog only supports source repository scanning",
        )

    clone_dir: str | None = None
    try:
        scan_dir = source_dir
        if not scan_dir:
            clone_dir = await _clone_repo(target)
            scan_dir = clone_dir

        cmd = [
            "trufflehog", "filesystem",
            "--json", "--no-update",
            scan_dir,
        ]

        stdout, stderr, rc = await _run_command(cmd, timeout=300)
        # TruffleHog exit 0 = no secrets, 183 = secrets found
        if rc not in (0, 183):
            if not stdout.strip():
                return ScannerResult(
                    scanner="trufflehog", format="trufflehog-json", report={},
                    error=f"TruffleHog failed (exit {rc}): {_sanitize_error(stderr)}",
                )

        # TruffleHog outputs JSON Lines (one JSON object per line), not a single JSON doc.
        # Collect all results into a list.
        results: list[dict[str, Any]] = []
        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                continue

        return ScannerResult(scanner="trufflehog", format="trufflehog-json", report={"results": results})
    except RuntimeError as exc:
        return ScannerResult(scanner="trufflehog", format="trufflehog-json", report={}, error=str(exc))
    finally:
        if clone_dir:
            shutil.rmtree(clone_dir, ignore_errors=True)
