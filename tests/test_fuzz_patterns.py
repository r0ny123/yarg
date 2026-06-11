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
from yarg.yara_output import pattern_atom_ok

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


# --- R1 (branch short/near encoding variants) and R6 (atom governor) ---------------------


def _patternize(code: bytes, settings: SettingsDialog, bits: int = 32) -> str:
    _set_bitness(bits)
    md = Cs(CS_ARCH_X86, CS_MODE_32 if bits == 32 else CS_MODE_64)
    md.detail = True
    return create_pattern_from_code(md, code, 0x401000, settings).pattern


def _branch_settings(branch: bool = True, governor: bool = False) -> SettingsDialog:
    s = SettingsDialog()
    s.cBranchEncodingVariants.checked = branch
    s.cAtomGovernor.checked = governor
    return s


def test_short_jcc_emits_short_and_near_alternation_when_enabled():
    # 74 05 = jz short (rel8) -> pair with the 0F 84 rel32 near form.
    assert _patternize(b"\x74\x05", _branch_settings(branch=True)) == "(74??|0F84????)"


def test_short_jcc_keeps_single_encoding_when_disabled():
    assert _patternize(b"\x74\x05", _branch_settings(branch=False)) == "74??"


def test_near_jcc_pairs_with_short_form():
    # 0F 84 05 00 00 00 = jz near (rel32) -> pair with the 74 rel8 short form.
    pat = _patternize(b"\x0f\x84\x05\x00\x00\x00", _branch_settings(branch=True))
    assert pat.startswith("(0F84")
    assert pat.endswith("|74??)")


def test_short_jmp_pairs_with_near_form():
    assert _patternize(b"\xeb\x05", _branch_settings(branch=True)) == "(EB??|E9????)"


def test_near_jmp_pairs_with_short_form():
    pat = _patternize(b"\xe9\x00\x00\x00\x00", _branch_settings(branch=True))
    assert pat.startswith("(E9")
    assert pat.endswith("|EB??)")


def test_branch_variant_suppressed_under_legacy_prefix():
    # 66 E9 05 00 = operand-size near jmp (rel16). The 0x66 prefix changes the counterpart's
    # length and is emitted outside the template, so no alternation may be grafted on.
    pat = _patternize(b"\x66\xe9\x05\x00", _branch_settings(branch=True))
    assert "(" not in pat
    assert pat.startswith("66E9")


def test_branch_variants_self_match_source_bytes():
    # The native branch must still match its own bytes even when an alternation is emitted.
    for code in (b"\x74\x05", b"\x0f\x84\x05\x00\x00\x00", b"\xeb\x05", b"\xe9\x00\x00\x00\x00"):
        pat = _patternize(code, _branch_settings(branch=True))
        consumed = code.hex().upper()
        assert re.fullmatch(_pattern_to_regex(pat), consumed), (code, pat)


def test_atom_governor_restores_anchor_for_otherwise_weak_block():
    # jmp short +2 ; mov ebx, eax  -> with branch + register parameterization the block has
    # no 2-byte fixed atom until the governor relocks one instruction to literal bytes.
    code = b"\xeb\x02\x89\xc3"

    off = SettingsDialog()
    off.set_default_check_box_values()
    off.cAtomGovernor.checked = False
    assert not pattern_atom_ok(_patternize(code, off))

    on = SettingsDialog()
    on.set_default_check_box_values()  # governor + branch variants enabled by default
    assert pattern_atom_ok(_patternize(code, on))


def test_atom_governor_leaves_single_instruction_untouched():
    # A lone short jump is a deliberate one-instruction selection; the governor must not
    # relock it just to manufacture an atom.
    on = SettingsDialog()
    on.set_default_check_box_values()
    pat = _patternize(b"\xeb\x05", on)
    assert pat == "(EB??|E9????)"
    assert not pattern_atom_ok(pat)


# --- Step 1: REX.W precision (cRexOperandSizeFixed) -------------------------------------


def _rex_settings(rex_fixed: bool) -> SettingsDialog:
    s = SettingsDialog()
    s.cRexOperandSizeFixed.checked = rex_fixed
    # Keep branch/disp variants off so the REX template is the only thing under test.
    s.cBranchEncodingVariants.checked = False
    s.cStackDispSizeVariants.checked = False
    return s


def test_rex_w1_fixed_emits_high_nibble_alternation():
    # 48 8B 45 FC = mov rax, qword ptr [rbp-4]; REX=0x48 (W=1). Holding W fixed keeps the
    # high half of the low nibble {8..F}, leaving R/X/B free.
    assert _patternize(b"\x48\x8b\x45\xfc", _rex_settings(True), bits=64) == "4(8|9|A|B|C|D|E|F)8B45FC"


def test_rex_w0_fixed_emits_low_nibble_alternation():
    # 44 8B 45 FC = mov r8d, dword ptr [rbp-4]; REX=0x44 (W=0). W fixed keeps {0..7}.
    assert _patternize(b"\x44\x8b\x45\xfc", _rex_settings(True), bits=64) == "4(0|1|2|3|4|5|6|7)8B45FC"


def test_rex_off_keeps_full_nibble_wildcard():
    # With the setting off, both W=1 and W=0 collapse to the original `4?` (conflating them).
    assert _patternize(b"\x48\x8b\x45\xfc", _rex_settings(False), bits=64) == "4?8B45FC"
    assert _patternize(b"\x44\x8b\x45\xfc", _rex_settings(False), bits=64) == "4?8B45FC"


def test_rex_template_self_matches_source_bytes():
    for code in (b"\x48\x8b\x45\xfc", b"\x44\x8b\x45\xfc"):
        pat = _patternize(code, _rex_settings(True), bits=64)
        assert re.fullmatch(_pattern_to_regex(pat), code.hex().upper()), (code, pat)


# --- Step 2: stack-frame disp8<->disp32 size variants (cStackDispSizeVariants) ----------


def _disp_settings(variants: bool = True, wildcard_disp: bool = True) -> SettingsDialog:
    s = SettingsDialog()
    s.cStackDispSizeVariants.checked = variants
    s.cBranchEncodingVariants.checked = False
    s.cRexOperandSizeFixed.checked = False
    # Stack-displacement wildcarding is gated by cSDisplacementParam.
    s.cSDisplacementParam.checked = wildcard_disp
    s.cGpDisplacementParam.checked = wildcard_disp
    return s


def test_rbp_disp8_emits_disp32_mod10_alternate():
    # mov dword ptr [ebp-4], eax = 89 45 FC (mod=01, disp8). Alternate flips to mod=10
    # (45 -> 85) and widens the displacement to four wildcard bytes.
    assert _patternize(b"\x89\x45\xfc", _disp_settings(), bits=32) == "89(45??|85????????)"


def test_rbp_disp8_literal_displacement_is_sign_extended():
    # With displacement wildcarding off, the disp8 0xFC (-4) sign-extends to FCFFFFFF.
    assert _patternize(b"\x89\x45\xfc", _disp_settings(wildcard_disp=False), bits=32) == "89(45FC|85FCFFFFFF)"


def test_rsp_sib_disp8_keeps_sib_byte_and_flips_mod():
    # mov eax, dword ptr [esp+8] = 8B 44 24 08 (SIB base=esp, mod=01). The SIB byte (24)
    # is unchanged; only the ModRM mod flips and the displacement widens.
    assert _patternize(b"\x8b\x44\x24\x08", _disp_settings(), bits=32) == "8B(4424??|8424????????)"


def test_rbp_disp32_emits_disp8_alternate_when_in_int8_range():
    # mov eax, dword ptr [ebp-4] = 8B 85 FC FF FF FF (mod=10, disp32 = -4, fits int8).
    assert _patternize(b"\x8b\x85\xfc\xff\xff\xff", _disp_settings(), bits=32) == "8B(85????????|45??)"


def test_rbp_disp32_out_of_int8_range_has_no_alternate():
    # [ebp+0x200] cannot be re-encoded as disp8, so the single native encoding stands.
    assert _patternize(b"\x8b\x85\x00\x02\x00\x00", _disp_settings(), bits=32) == "8B85????????"


def test_non_stack_base_gets_no_disp_variant():
    # [ecx+4] is a GP base, not a stack-frame access; no disp size variant is emitted.
    assert _patternize(b"\x8b\x41\x04", _disp_settings(), bits=32) == "8B41??"


def test_disp_variant_disabled_keeps_single_encoding():
    assert _patternize(b"\x89\x45\xfc", _disp_settings(variants=False), bits=32) == "8945??"


def test_rex_w_and_disp_variant_compose():
    # 48 89 45 FC = mov [rbp-4], rax. REX.W fixed wraps the REX byte; the disp variant wraps
    # the mem tail independently.
    s = _disp_settings()
    s.cRexOperandSizeFixed.checked = True
    assert _patternize(b"\x48\x89\x45\xfc", s, bits=64) == "4(8|9|A|B|C|D|E|F)89(45??|85????????)"


def test_disp_variants_self_match_source_bytes():
    cases = [
        (b"\x89\x45\xfc", 32),
        (b"\x8b\x44\x24\x08", 32),
        (b"\x8b\x85\xfc\xff\xff\xff", 32),
        (b"\x48\x89\x45\xfc", 64),
    ]
    for code, bits in cases:
        pat = _patternize(code, _disp_settings(), bits=bits)
        assert re.fullmatch(_pattern_to_regex(pat), code.hex().upper()), (code, pat)
