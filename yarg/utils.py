from typing import Optional, Tuple

import ida_ida
import ida_kernwin as kw

from capstone.x86_const import *

from .forms import SettingsDialog
from .version import __ver_major__ as __ver_major__, __ver_minor__ as __ver_minor__

__debugmode__ = False

VAR_NAME = "code_at_"

TEMPLATE_SYMBOL = "?"
REGISTER_LOOKUP_TABLE = {
    8: [
        X86_REG_AL,
        X86_REG_CL,
        X86_REG_DL,
        X86_REG_BL,
        X86_REG_AH,
        X86_REG_CH,
        X86_REG_DH,
        X86_REG_BH,
        X86_REG_R8B,
        X86_REG_R9B,
        X86_REG_R10B,
        X86_REG_R11B,
        X86_REG_R12B,
        X86_REG_R13B,
        X86_REG_R14B,
        X86_REG_R15B,
    ],
    16: [
        X86_REG_AX,
        X86_REG_CX,
        X86_REG_DX,
        X86_REG_BX,
        X86_REG_SP,
        X86_REG_BP,
        X86_REG_SI,
        X86_REG_DI,
        X86_REG_R8W,
        X86_REG_R9W,
        X86_REG_R10W,
        X86_REG_R11W,
        X86_REG_R12W,
        X86_REG_R13W,
        X86_REG_R14W,
        X86_REG_R15W,
    ],
    32: [
        X86_REG_EAX,
        X86_REG_ECX,
        X86_REG_EDX,
        X86_REG_EBX,
        X86_REG_ESP,
        X86_REG_EBP,
        X86_REG_ESI,
        X86_REG_EDI,
        X86_REG_R8D,
        X86_REG_R9D,
        X86_REG_R10D,
        X86_REG_R11D,
        X86_REG_R12D,
        X86_REG_R13D,
        X86_REG_R14D,
        X86_REG_R15D,
    ],
    64: [
        X86_REG_RAX,
        X86_REG_RCX,
        X86_REG_RDX,
        X86_REG_RBX,
        X86_REG_RSP,
        X86_REG_RBP,
        X86_REG_RSI,
        X86_REG_RDI,
        X86_REG_R8,
        X86_REG_R9,
        X86_REG_R10,
        X86_REG_R11,
        X86_REG_R12,
        X86_REG_R13,
        X86_REG_R14,
        X86_REG_R15,
    ],
}


def _compact_byte_alternatives(values, settings: SettingsDialog) -> str:
    """Render a set of byte alternatives as the most compact *lossless* hex pattern.

    A nibble may be wildcarded only when the alternatives actually span all 16 of its
    values; otherwise the faithful alternation ``(AA|BB|...)`` is emitted. Folding to a
    nibble wildcard when the set does not cover the full nibble (the previous behaviour)
    silently widened the match into the neighbouring, held register field.
    """
    byte_values = sorted(dict.fromkeys(values))
    high_nibbles = {value >> 4 for value in byte_values}
    low_nibbles = {value & 0xF for value in byte_values}
    full_nibble = set(range(16))

    if settings.cFoldSameLow4bit.checked and len(high_nibbles) == 1 and low_nibbles == full_nibble:
        return f"{next(iter(high_nibbles)):X}{TEMPLATE_SYMBOL}"

    if settings.cFoldSameHigh4bit.checked and len(low_nibbles) == 1 and high_nibbles == full_nibble:
        return f"{TEMPLATE_SYMBOL}{next(iter(low_nibbles)):X}"

    return "(" + "|".join(f"{value:02X}" for value in byte_values) + ")"


def generate_8bit_pattern_2_0_any(v_7_6, v_5_3, settings: SettingsDialog) -> str:
    cst_part = (v_7_6 << 6) | (v_5_3 << 3)
    return _compact_byte_alternatives([cst_part | i for i in range(8)], settings)


def generate_8bit_pattern_5_0_any(v_7_6, settings: SettingsDialog) -> str:
    cst_part = v_7_6 << 2
    v = []
    for i in range(0, 4):
        v.append(f"{(cst_part | i):1X}?")

    return f"({'|'.join(v)})"


def generate_8bit_pattern_5_3_any(v_7_6, v_2_0, settings: SettingsDialog) -> str:
    cst_part = (v_7_6 << 6) | v_2_0
    return _compact_byte_alternatives([cst_part | (i << 3) for i in range(8)], settings)


def get_reg(reg_id, size, instr) -> Optional[int]:
    regs_list = REGISTER_LOOKUP_TABLE.get(size, [])
    if not regs_list:
        return None

    try:
        reg = regs_list[reg_id]
    except IndexError:
        return None

    rex_fixup = {X86_REG_AH: X86_REG_SPL, X86_REG_CH: X86_REG_BPL, X86_REG_DH: X86_REG_SIL, X86_REG_BH: X86_REG_DIL}

    if instr.rex and reg in (X86_REG_AH, X86_REG_CH, X86_REG_DH, X86_REG_BH):
        reg = rex_fixup[reg]

    return reg


def is_stack_reg(r) -> bool:
    return r in (X86_REG_BP, X86_REG_BPL, X86_REG_SP, X86_REG_SPL, X86_REG_ESP, X86_REG_EBP, X86_REG_RSP, X86_REG_RBP)


def is_gp_reg(r) -> bool:
    return r != 0 and not is_stack_reg(r)


def get_bitness() -> int:
    if ida_ida.inf_is_64bit():
        size = 64
    elif ida_ida.inf_is_32bit_exactly():
        size = 32
    else:
        size = 16
    return size


def get_selected_range() -> Tuple[Optional[int], Optional[int]]:

    view = kw.get_current_viewer()
    selected = kw.read_range_selection(view)

    if not selected or not selected[1]:
        return None, None

    return selected[1], selected[2]


def dbg_print(msg) -> None:
    if not __debugmode__:
        return

    print(msg)


def get_reg_size(reg) -> Optional[int]:
    for k, v in REGISTER_LOOKUP_TABLE.items():
        if reg in v:
            return k

    return None
