# Changelog

All notable changes to this project will be documented in this file.

## [1.1.0] - 2026-07-17
### Added
- Expanded architectural structure containing explicit modular separation (`src/`, `docs/`, `tests/`, `reports/`).
- Added specialized compliance testing checking specific domains (`ebs.py`, `root_user.py`, `password_policy.py`, `cloudtrail.py`, `cloudwatch.py`).
- Implemented clean centralized parameter configuration maps (`config.yaml`).
- Configured production-grade structured pipeline files for validation checks (`ci.yml`).