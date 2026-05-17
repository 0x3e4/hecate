# Changelog

All notable changes to Hecate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

### Changed
- Documentation refresh: README CI/CD section now describes the actual GitHub Actions workflows (build-images, release) and GHCR registry; deep docs (architecture.md, backend / frontend READMEs) brought in sync with the 1.1.0 feature set

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