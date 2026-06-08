# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2026-06-08

### Added
- Added regression coverage for IDA 9 settings dialog state handling, generated YARA rule viewer tabs, `ida_domain` lifecycle cleanup, plugin reload cleanup, and 64-bit-safe YARA rule/string naming.

### Changed
- Made generated YARA rule viewer tabs transient and uniquely named so repeated generation from any action opens a new IDA tab instead of reusing a persistent `Created YARA rule` tab.
- Centralized YARA rule and string address formatting so selected instruction, selected range, selected basic block, and function outputs consistently use 16-digit addresses for 64-bit databases.
- Lazy-load `ida_domain` bindings in the bridge to keep command-line tests free of IDAPython SWIG import warnings until IDA database access is actually needed.
- Added a tag-driven GitHub Actions release workflow that builds and uploads an `hcli plugin install`-ready YarG ZIP asset.

### Fixed
- Fixed settings dialog state leakage where toggling GP or SP/BP master checkboxes could mutate saved settings even when the dialog was canceled.
- Fixed live IDA GUI cleanup to avoid calling `ida_domain.Database.close()`, preventing a `Close is available only when running as a library` console error after rule generation.
- Fixed plugin reload/unload cleanup so stale YarG UI hooks and registered actions are removed before local re-registration, preventing duplicate popup actions after iterative reloads.
- Fixed partial action-registration rollback so a failed registration does not leave already-registered YarG actions behind.
- Fixed `_is_ida_library_mode` environment check by calling `is_ida_library()` without arguments, preventing SWIG type mapping exceptions.
- Fixed function rule generation condition threshold to not exceed the total number of basic blocks for small functions.
- Added defensive fallback in rule formatting to output unformatted rules if `yara_x.Formatter` is missing or fails.

## [1.0.0] - 2026-06-07

### Added
- Integrated the new Hex-Rays `ida-plugin.json` metadata manifest for `ida-hcli` support.
- Added automatic validation and linting using `hcli plugin lint`.
- Migrated code querying layer to the modern `ida_domain` database API via a new bridge layer (`ida_domain_bridge.py`).
- Added compilation, validation, automated formatting, and post-format validation of generated YARA rules using `yara-x` (`yara_output.py`).
- Added a new PySide6 custom YARA rule visualization window (`rule_viewer.py`).
- Added complete YARA rule generation for selected instruction, selected range, selected basic block, and selected function actions.
- Added assembly comment blocks before generated strings with aligned raw-byte and disassembly columns.
- Configured automated GitHub Release note generation.

### Changed
- Major refactoring of action registration and lifecycle handling from global module imports to a structured `ActionsManager` and modern UI hooks.
- Upgraded the settings UI form and dialog layout from old custom forms to modern scrollable QT layouts in `forms/settings.py`.
- Modernized the code styling, linting rules, and imports using the `ruff` formatter.
- Refactored IDA lookups to avoid stale direct `idaapi`, `idautils`, and `idc` usage where modern APIs or `ida_domain` are available.
- Cleaned up documentation and configuration files to use generic system paths instead of hardcoded environment paths.
- Updated GitHub Actions to use Node 24 based `actions/checkout@v6` and `actions/setup-python@v6`.
- Pinned development tooling in `requirements-dev.txt` and made CI run Ruff, `compileall`, pytest, and HCLI plugin metadata linting.
- Removed stale `plyara` and `tabulate` dependencies in favor of internal rule rendering plus mandatory `yara-x` validation.

### Fixed
- Fixed Python `__ver_major__` and `__ver_minor__` re-export import definitions in `utils.py` to protect them from formatting optimizer deletion.
- Fixed selected range and selected basic block actions so they display complete YARA rules instead of standalone byte-string variables.
