# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.5] - 2026-06-10

### Changed
- Made ModR/M and SIB register parameterization folding lossless: alternatives are only collapsed to a nibble wildcard when they span the full nibble, so an enabled "fold same low/high 4 bits" option no longer silently widens a match into the adjacent, held register field.
- Aggregated the literal-fallback notice in pattern generation into a single per-rule message instead of printing once per affected instruction.

### Fixed
- Hardened the rule-generation actions to surface a warning instead of an unhandled traceback if the IDA database cannot be opened.
- Fixed the displacement parameterization fallback to use the clamped displacement bytes rather than the raw `instr.disp_size`, keeping it consistent with the size-clamping applied elsewhere.
- Fixed a potential stale viewer entry by registering a generated rule viewer only after it is shown successfully.

## [1.0.4] - 2026-06-10

### Added
- Added a per-instruction safety net so a generated template that does not match its own instruction bytes (degenerate/obfuscated sequences, or unmodelled encodings such as VEX/EVEX) falls back to the literal bytes, guaranteeing every generated pattern matches the code it was built from.
- Added regression tests covering zero-valued ModR/M, SIB, displacement, and opcode bytes, multi-byte opcode reconstruction, RIP-relative register-operand mapping, redundant prefixes, clamped immediate sizes, and the unmodelled-encoding fallback.
- Added a differential fuzz test (`tests/test_fuzz_patterns.py`) that disassembles random byte sequences across both bitnesses and many settings combinations and asserts every generated pattern matches its source bytes.

### Fixed
- Fixed ModR/M, SIB, and displacement bytes being dropped from generated patterns when their value was `0x00` (e.g. `[rax]`, `[rbp]`, `[rax+rax]`). Presence is now detected via instruction offsets (`modrm_offset`, `disp_offset`) and the decoded SIB object instead of a truthy check on the byte value, which had produced patterns shorter than the instruction that could not match.
- Fixed opcode bytes being dropped when an opcode byte was `0x00` (e.g. `ADD r/m8, r8`, the `0F 00 /r` group), and multi-byte opcodes being truncated (three-byte `0F 38`/`0F 3A` maps, mandatory `F3` prefixes for SSE). The opcode is now reconstructed from instruction offsets rather than filtering `instr.opcode` for truthy bytes.
- Fixed the operand locator swallowing the register operand of RIP-relative instructions: the `is_mem_rip_rel()` branch now only matches memory operands, so the ModR/M `reg` operand is mapped correctly and can be parameterized.
- Fixed redundant legacy prefixes being dropped (e.g. an `F3` on `xchg ebx, eax`): the prefix length is now decoded directly from the leading bytes rather than relying on `instr.prefix`, which capstone leaves empty for absorbed prefixes.
- Fixed runaway wildcard sequences from bogus disassembler sizes: immediate and displacement sizes are now clamped to the bytes actually present (e.g. far `ptr16:32` calls, for which capstone reports an oversized `imm_size`).

## [1.0.3] - 2026-06-09

### Added
- Added `ty` type checker (`ty==0.0.46`) to development dependencies and CI pipeline.

### Changed
- Added `PLUGIN_HIDE` flag to `YaraBuilder` so the plugin no longer appears as an inert entry in the Edit → Plugins menu; all user interaction goes through the right-click context menu.
- Replaced dynamic `setattr` loop in `SettingsDialog.__init__` with explicit per-attribute assignments so static type checkers can resolve all `_CheckControl` attributes.
- Replaced all flat PyQt5-style enum accesses with fully-qualified PySide6 equivalents: `QDialogButtonBox.StandardButton.Ok/Cancel`, `QDialog.DialogCode.Accepted`, `Qt.AlignmentFlag.AlignTop`, `QPlainTextEdit.LineWrapMode.NoWrap`, `QFontDatabase.SystemFont.FixedFont`.
- Unified duplicate `InstructionAnnotation` dataclass in `builder.py` with `YaraInstructionComment` from `yara_output.py`.

### Fixed
- Fixed `RuntimeWarning` about PyQt5 shim bitwise operation triggered in `SettingsDialog.Execute`.
- Fixed `invalid-method-override` in `Hooks.populating_widget_popup`: renamed `popup` parameter to `popup_handle` and added `ctx=None` default to match the `UI_Hooks` parent signature.
- Fixed `invalid-assignment` in `OperandParameterizer.__init__`, `Displacement` dataclass, and `OperandLocator.__init__` by annotating `modrm`, `sib`, and `disp` as `T | None`.
- Fixed `invalid-return-type` in `special_templates` by correcting its return annotation to `str | None`.

## [1.0.2] - 2026-06-08

### Added
- Added comprehensive unit tests for instruction encoding (ModR/M, SIB, Displacement) and operand locator logic.
- Added new test cases for `ida_domain_bridge` to verify function resolution and basic block iteration.

### Changed
- Refactored actions' `update` widget type checks to enable for both `BWN_DISASM` and `BWN_DISASM_ARROWS`.
- Modified action handlers' `activate` to return `1` on success instead of `0`.
- Broadened exception handling in `_is_ida_library_mode` to catch all `ImportError` subclasses.

### Fixed
- Fixed memory leakage in the settings dialog and rule viewer by clearing widget references on dialog rejection/acceptance and view close.
- Fixed SIB base R13 register decoding under REX.B prefix by checking base ID 13.
- Fixed locator register size matching by dynamically resolving base/index register sizes instead of using global bitness.
- Fixed crash risk (IndexError) in displacement and immediate parameterization when size is less than 2 under keep-last-2-bytes mode.
- Fixed fallthrough bug in displacement parameterization for SIB without base register by correctly mapping it as an absolute address.
- Fixed `is_gp_reg(0)` to correctly return `False` instead of `True` for invalid registers.
- Fixed format validation failures halting entire rule generation by falling back to verified unformatted YARA rules.

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
