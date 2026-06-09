# ruff: noqa: E402
"""Differential fuzz test for pattern generation.

Invariant: a pattern generated from a sequence of bytes must always *match* those exact
bytes. We verify this by translating the YARA hex pattern into a regular expression over
the instruction's hex dump (`?` -> one hex nibble, `(a|b|...)` -> alternation, literal hex
nibbles -> themselves) and requiring a full match. This catches both dropped/extra bytes
(length mismatch) and wrong concrete nibbles, regardless of how aggressively operands are
parameterized.
"""

import random
import re
import sys
import types
from unittest.mock import MagicMock

# Mock PySide6
for _m in ("PySide6", "PySide6.QtCore", "PySide6.QtGui", "PySide6.QtWidgets"):
    sys.modules[_m] = types.ModuleType(_m)

# Mock IDA modules. get_bitness() reads ida_ida at call time, so we reconfigure the mock
# per bitness inside the test.
_ida_ida = MagicMock()
sys.modules["ida_ida"] = _ida_ida
sys.modules["ida_kernwin"] = MagicMock()
sys.modules["ida_domain"] = MagicMock()

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

from yarg.builder import create_pattern_from_code
from yarg.utils import SettingsDialog

_HEX = set("0123456789ABCDEFabcdef")


def _set_bitness(bits):
    _ida_ida.inf_is_64bit.return_value = bits == 64
    _ida_ida.inf_is_32bit_exactly.return_value = bits == 32


def _pattern_to_regex(pattern: str) -> str:
    out = []
    for ch in pattern:
        if ch in _HEX:
            out.append(ch.upper())
        elif ch == "?":
            out.append("[0-9A-F]")
        elif ch in "(|)":
            out.append(ch)
        else:
            raise AssertionError(f"unexpected character {ch!r} in pattern {pattern!r}")
    return "".join(out)


def _settings_variants():
    """A spread of settings: defaults, everything parameterized, and each address/offset mode."""
    variants = []

    base = SettingsDialog()
    variants.append(base)

    full = SettingsDialog()
    full.set_default_check_box_values()
    full.cGpRegistersParam.checked = True
    full.cSRegistersParam.checked = True
    full.cImmediateParam.checked = True
    full.cGpImmParam.checked = True
    full.cSImmParam.checked = True
    full.cGpDisplacementParam.checked = True
    full.cSDisplacementParam.checked = True
    full.cFoldSameLow4bit.checked = True
    full.cFoldSameHigh4bit.checked = True
    full.check_all_gp(True)
    full.check_all_sp(True)
    variants.append(full)

    for addr_mode in (0, 1, 2):
        for off_mode in (0, 1, 2):
            s = SettingsDialog()
            s.set_default_check_box_values()
            s.check_all_gp(True)
            s.check_all_sp(True)
            s.cGpRegistersParam.checked = True
            s.cSRegistersParam.checked = True
            s.address_parameterization_mode = addr_mode
            s.offset_parameterization_mode = off_mode
            variants.append(s)

    return variants


def test_generated_pattern_always_matches_source_bytes():
    rng = random.Random(0xBADC0DE)
    modes = {32: Cs(CS_ARCH_X86, CS_MODE_32), 64: Cs(CS_ARCH_X86, CS_MODE_64)}
    for md in modes.values():
        md.detail = True

    variants = _settings_variants()
    checked = 0

    for _ in range(4000):
        length = rng.randint(1, 15)
        code = bytes(rng.randint(0, 255) for _ in range(length))
        bits = rng.choice((32, 64))
        _set_bitness(bits)
        md = modes[bits]

        instrs = list(md.disasm(code, 0x401000))
        if not instrs:
            continue
        consumed_hex = "".join(i.bytes.hex().upper() for i in instrs)

        for settings in variants:
            result = create_pattern_from_code(md, code, 0x401000, settings)
            regex = _pattern_to_regex(result.pattern)
            assert re.fullmatch(regex, consumed_hex), (
                f"pattern does not match source bytes\n"
                f"  bitness={bits}\n"
                f"  bytes={consumed_hex}\n"
                f"  pattern={result.pattern}\n"
                f"  disasm={[f'{i.mnemonic} {i.op_str}'.strip() for i in instrs]}"
            )
            checked += 1

    # Sanity: the fuzzer actually exercised a meaningful number of cases.
    assert checked > 1000
