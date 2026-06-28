# Changelog

## [2.0.0] - 2026-06-23

### Changed
- Complete rewrite from single-file to modular package
- Each OSINT technique is an independent module under spectre/modules/
- Network utilities extracted to spectre/utils/network.py

### Added
- 10 unit tests (models, network, CLI)
- pyproject.toml, Makefile, CI, Dockerfile
- docs/ARCHITECTURE.md
- LICENSE, CONTRIBUTING, SECURITY, CHANGELOG

## [1.0.0] - 2026-06-20

### Added
- Initial release: subdomain enum, email harvest, DNS intel,
  certificate transparency, infrastructure fingerprinting, org footprinting
