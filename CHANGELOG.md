# Changelog

All notable changes to Hecate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

### Changed

### Fixed

## [1.1.2] - 2026-05-21

### Added

### Changed
- Dependency bumps (backend / poetry): certifi 2026.4.22 → 2026.5.20, protobuf 7.34.1 → 7.35.0
- Dependency bumps (frontend / pnpm): react / react-dom 19.2.5 → 19.2.6, react-router-dom 7.14.2 → 7.15.0, vite 7.3.2 → 7.3.3

### Fixed

## [1.1.1] - 2026-05-18

### Added

### Changed
- Documentation sync with the 1.1.0 feature set: README CI/CD section rewritten to describe the actual GitHub Actions workflows (build-images, release) and GHCR registry; architecture.md CI/CD + container-registry section finalized; Support page added to every frontend route / view table (README, frontend/README, architecture.md); DevSkim now listed in every scanner enumeration, Mermaid diagram, and tech-stack row (architecture.md system context + deployment diagram, scanner/README integration diagram); router count bumped 19 → 20 (architecture.md, backend/README, README) with the new `malware` / `version` routers added to the API-layer listing; `sca_malware_alert` listed alongside the other notification rule types in the `notification_rules` collection description; `enrich-mal` / `purge-malware` added to the CLI block in architecture.md
- Dependency bumps (backend / poetry): click 8.3.3 → 8.4.0, coverage 7.13.5 → 7.14.0, google-auth 2.51.0 → 2.53.0, idna 3.13 → 3.15, markdown-it-py 4.1.0 → 4.2.0, mcp 1.27.0 → 1.27.1, pydantic-settings 2.14.0 → 2.14.1, python-multipart 0.0.27 → 0.0.29, requests 2.33.1 → 2.34.2, sse-starlette 3.4.2 → 3.4.4, urllib3 2.6.3 → 2.7.0
- Dependency bumps (scanner / poetry): click 8.3.3 → 8.4.0, idna 3.13 → 3.15, uvicorn 0.46.0 → 0.47.0
- Dependency bumps (frontend / pnpm): axios 1.15.2 → 1.16.0 (direct); transitive refreshes for `@babel/*`, `@iconify/utils`, and the `@rollup/rollup-*` platform binaries (4.60.2 → 4.60.3)
- Tooling pin: `packageManager` in `frontend/package.json` bumped from pnpm 10.33.0 → 10.33.4 (picked up automatically via Corepack in the frontend Dockerfile)

### Fixed

## [1.1.0] - 2026-05-17

### Added
- Continuous MAL-* watcher cross-checks new malware against existing SCA scans
- Regex search mode on the Vulnerabilities page and saved searches
- TruffleHog 3.95.3 (was 3.95.2)

### Changed
- `/check` probe now runs in parallel with scans (no more spurious skips under load)

### Fixed
- Surface real `/check` error (auth/DNS/TLS/timeout) on the target diagnostics row

## [1.0.2] - 2026-05-11

### Added

### Changed

### Fixed
- Running version on Support page now reflects pyproject.toml

## [1.0.1] - 2026-05-11

### Added
- GHCR package descriptions for backend / frontend / scanner

### Changed
- Support page: Version section moved to top, Support + Star side-by-side

### Fixed
- Support page badge shows "Up to date" when all components match latest

## [1.0.0] - 2026-05-11

Initial tagged release. Establishes the baseline for the semantic versioning timeline.
All prior development history is captured in the git log; future changes will be
tracked here.

### Added
- Scanner Breakdown tab on scan detail
- Per-component version check on the Support page
- Shields.io status badges for scans

### Changed
- Scanner subprocesses log via LOG_LEVEL

### Fixed
- DevSkim timeout handling