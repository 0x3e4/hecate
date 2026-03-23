from __future__ import annotations

import asyncio
import base64
import binascii
import io
import json
import os
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import Any

from app.hecate_analyzer import run_analysis
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
    else:
        return ScannerResult(scanner=scanner_name, format="unknown", report={}, error=f"Unknown scanner: {scanner_name}")


async def _run_command(cmd: list[str], timeout: int = 600) -> tuple[str, str, int]:
    """Run a subprocess command and return stdout, stderr, returncode."""
    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
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
            return ScannerResult(scanner="trivy", format="trivy-json", report={}, error=f"Trivy failed (exit {rc}): {stderr}")
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
            return ScannerResult(scanner="grype", format="grype-json", report={}, error=f"Grype failed (exit {rc}): {stderr}")
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
            return ScannerResult(scanner="syft", format="cyclonedx-json", report={}, error=f"Syft failed (exit {rc}): {stderr}")
        return _parse_json_output(stdout, "syft", "cyclonedx-json")
    except RuntimeError as exc:
        return ScannerResult(scanner="syft", format="cyclonedx-json", report={}, error=str(exc))
    finally:
        if clone_dir:
            shutil.rmtree(clone_dir, ignore_errors=True)


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
        cmd = ["osv-scanner", "scan", "--format", "json", "-r", scan_dir]

        stdout, stderr, rc = await _run_command(cmd)
        # osv-scanner returns exit code 1 when vulnerabilities are found (expected)
        # exit 128 with "No package sources found" means the repo has no lockfiles/manifests — not an error
        if rc not in (0, 1):
            if "No package sources found" in stderr:
                return ScannerResult(scanner="osv-scanner", format="osv-json", report={})
            if not stdout.strip():
                return ScannerResult(scanner="osv-scanner", format="osv-json", report={}, error=f"OSV Scanner failed (exit {rc}): {stderr}")
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
    """Run Hecate's own infrastructure analyzer (Dockerfiles, docker-compose, package.json)."""
    if target_type == "container_image":
        return ScannerResult(
            scanner="hecate", format="cyclonedx-json", report={},
            error="Hecate Analyzer only supports source repository scanning",
        )

    clone_dir: str | None = None
    try:
        scan_dir = source_dir
        if not scan_dir:
            clone_dir = await _clone_repo(target)
            scan_dir = clone_dir

        report = run_analysis(scan_dir)
        return ScannerResult(scanner="hecate", format="cyclonedx-json", report=report)
    except Exception as exc:
        return ScannerResult(scanner="hecate", format="cyclonedx-json", report={}, error=str(exc))
    finally:
        if clone_dir:
            shutil.rmtree(clone_dir, ignore_errors=True)
