import re
from struct import unpack
from binascii import hexlify
from dataclasses import dataclass

from capstone import *


from .operand import OperandParameterizer
from .utils import SettingsDialog, get_bitness, dbg_print, TEMPLATE_SYMBOL
from .yara_output import YaraInstructionComment


# x86 legacy prefix bytes: lock/repeat (F0, F2, F3), segment overrides
# (2E, 36, 3E, 26, 64, 65), and operand/address-size overrides (66, 67).
LEGACY_PREFIX_BYTES = frozenset({0xF0, 0xF2, 0xF3, 0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65, 0x66, 0x67})


@dataclass(frozen=True)
class PatternResult:
    pattern: str
    annotations: list[YaraInstructionComment]


def pattern_to_regex(pattern: str) -> str | None:
    """Translate a generated YARA hex pattern into a regex over an uppercase hex dump.

    Hex nibbles map to themselves, ``?`` to a single hex-nibble class, and ``(a|b|...)``
    alternation groups pass through unchanged. Returns ``None`` if the pattern contains an
    unexpected character, which the caller treats as a non-match.
    """
    out = []
    for char in pattern:
        if char in "0123456789abcdefABCDEF":
            out.append(char.upper())
        elif char == "?":
            out.append("[0-9A-F]")
        elif char in "(|)":
            out.append(char)
        else:
            return None
    return "".join(out)


def _finalize_instr_template(instr_template: str, instr_data: bytes) -> str:
    """Guarantee a per-instruction template matches the instruction it was built from.

    A generated pattern must always match the bytes it describes. Disassembler metadata can
    be internally inconsistent on degenerate/obfuscated byte sequences, and encodings outside
    the supported legacy ModR/M scheme (e.g. VEX/EVEX) are not modelled here; either can yield
    a template that does not match the instruction. When that happens, fall back to the literal
    instruction bytes, which match by definition.
    """
    target = instr_data.hex().upper()
    regex = pattern_to_regex(instr_template)
    if regex is not None and re.fullmatch(regex, target):
        return instr_template

    print("[!] Generated pattern does not match its instruction bytes; falling back to literal bytes")
    return target


def format_debug_table(headers, row) -> str:
    widths = [max(len(str(header)), len(str(value))) for header, value in zip(headers, row)]
    header_line = " | ".join(str(header).ljust(width) for header, width in zip(headers, widths))
    separator = "-+-".join("-" * width for width in widths)
    row_line = " | ".join(str(value).ljust(width) for value, width in zip(row, widths))
    return f"{header_line}\n{separator}\n{row_line}"


def special_templates(instr, dw_opcode, settings: SettingsDialog, db=None) -> str | None:
    """
    Processing special opcodes
    :param instr:  Capstone instruction CsInsn
    :param dw_opcode: Opcode (dword)
    :param settings: Settings instance
    :return: (str) Parameterized pattern of the code
    """
    # PUSH +r (b/w/d)
    # POP  +r (b/w/d)
    if 0x50 <= dw_opcode < 0x60:
        return f"5{TEMPLATE_SYMBOL}"

    # INC +r (b/w/d)
    # DEC  +r (b/w/d)
    if 0x40 <= dw_opcode < 0x50:
        return f"4{TEMPLATE_SYMBOL}"

    # XCHG +r (b/w/d)
    if 0x91 <= dw_opcode < 0x98:
        return f"9{TEMPLATE_SYMBOL}"

    # MOV +r, imm
    if 0xB0 <= dw_opcode < 0xC0:
        return f"B{TEMPLATE_SYMBOL}" + OperandParameterizer(instr, db=db).parameterize_imm(settings)

    # CALL {XX XX XX XX}
    if dw_opcode == 0xE8:
        if settings.offset_parameterization_mode == 0:
            return "E8" + f"{TEMPLATE_SYMBOL}{TEMPLATE_SYMBOL}" * instr.imm_size

        if settings.offset_parameterization_mode == 1:
            return "E8" + f"{TEMPLATE_SYMBOL}{TEMPLATE_SYMBOL}" * (instr.imm_size - 1) + f"{instr.bytes[-1]:02X}"

        if settings.offset_parameterization_mode == 2:
            return (
                "E8"
                + f"{TEMPLATE_SYMBOL}{TEMPLATE_SYMBOL}" * (instr.imm_size - 2)
                + f"{instr.bytes[-2]:02X}"
                + f"{instr.bytes[-1]:02X}"
            )

    # JCC second table
    if 0x800F <= dw_opcode <= 0x8F0F:
        opcode = "".join([f"{opcode_byte:02X}" for opcode_byte in instr.opcode if opcode_byte])

        if settings.offset_parameterization_mode == 0:
            return f"{opcode}" + f"{TEMPLATE_SYMBOL}{TEMPLATE_SYMBOL}" * instr.imm_size

        if settings.offset_parameterization_mode == 1:
            return f"{opcode}" + f"{TEMPLATE_SYMBOL}{TEMPLATE_SYMBOL}" * (instr.imm_size - 1) + f"{instr.bytes[-1]:02X}"

        if settings.offset_parameterization_mode == 2:
            return (
                f"{opcode}"
                + f"{TEMPLATE_SYMBOL}{TEMPLATE_SYMBOL}" * (instr.imm_size - 2)
                + f"{instr.bytes[-2]:02X}"
                + f"{instr.bytes[-1]:02X}"
            )

    # JCC first table
    if 0x70 <= dw_opcode <= 0x7F:
        return f"{instr.opcode[0]:02X}??"

    # JMP near imm8
    if dw_opcode == 0xEB:
        return "EB??"

    # JMP near imm16/im32
    if dw_opcode == 0xE9:
        opcode = "E9"

        if settings.offset_parameterization_mode == 0:
            return f"{opcode}" + f"{TEMPLATE_SYMBOL}{TEMPLATE_SYMBOL}" * instr.imm_size

        if settings.offset_parameterization_mode == 1:
            return f"{opcode}" + f"{TEMPLATE_SYMBOL}{TEMPLATE_SYMBOL}" * (instr.imm_size - 1) + f"{instr.bytes[-1]:02X}"

        if settings.offset_parameterization_mode == 2:
            return (
                f"{opcode}"
                + f"{TEMPLATE_SYMBOL}{TEMPLATE_SYMBOL}" * (instr.imm_size - 2)
                + f"{instr.bytes[-2]:02X}"
                + f"{instr.bytes[-1]:02X}"
            )


def create_pattern_from_code(md: Cs, code: bytes, addr: int, settings: SettingsDialog, db=None) -> PatternResult:
    """
    Builds pattern from byte sequence
    :param md: Capstone disassembler instance
    :param code: Byte sequence
    :param addr: Start address
    :param settings: Settings instance
    :return: Parameterized pattern and per-instruction comments
    """
    code_pattern = ""
    annotations = []
    for instr in md.disasm(code, addr):
        instr_template = ""
        instr_data = instr.bytes
        disassembly = f"{instr.mnemonic} {instr.op_str}".strip()
        annotations.append(YaraInstructionComment(instr.address, instr_data.hex(), disassembly))

        instr_template_verb_hdr = ["legacy prefix", "rex", "opcode", "modrm", "sib", "disp", "imm"]
        instr_template_verb = [[]]

        # template legacy prefix.
        # Count the leading legacy-prefix bytes by decoding them directly rather than
        # trusting instr.prefix: capstone silently absorbs redundant/ignored prefixes
        # (e.g. an F3 on `xchg ebx, eax`) into neither instr.prefix nor instr.opcode, so
        # counting instr.prefix would undercount and drop those bytes from the pattern.
        number_of_prefixes = 0
        while number_of_prefixes < len(instr_data) and instr_data[number_of_prefixes] in LEGACY_PREFIX_BYTES:
            number_of_prefixes += 1

        legacy_prefix = "".join([f"{instr_data[x]:02X}" for x in range(number_of_prefixes)])

        instr_template += legacy_prefix
        instr_template_verb[0].append(legacy_prefix)

        # Bits [7;4] are invariant for any instructions
        # Bits [3;0] can change in similar instructions
        rex_template = ""

        if get_bitness() == 64 and instr.rex:
            rex_template += f"{instr.rex >> 4:1X}{TEMPLATE_SYMBOL}"

        instr_template += rex_template
        instr_template_verb[0].append(rex_template)

        dw_opcode = unpack("<I", bytes(instr.opcode))[0]

        opcode_tempalte = special_templates(instr, dw_opcode, settings, db=db)
        if opcode_tempalte:
            instr_template += opcode_tempalte
            code_pattern += _finalize_instr_template(instr_template, instr_data)
            continue

        # No special actions need. Just copy opcodes.
        # Reconstruct the opcode bytes from instruction offsets rather than filtering
        # instr.opcode for truthy bytes: a legitimate opcode byte can be 0x00 (e.g. ADD
        # r/m8, r8 = 0x00, the 0F 00 /r group, three-byte 0F 38/0F 3A maps) and a truthy
        # filter would silently drop it. The opcode spans from just after the legacy
        # prefixes and REX byte up to the first encoded field that follows it.
        opcode_start = number_of_prefixes + (1 if instr.rex else 0)
        opcode_end_candidates = [off for off in (instr.modrm_offset, instr.disp_offset, instr.imm_offset) if off]
        opcode_end = min(opcode_end_candidates) if opcode_end_candidates else len(instr_data)
        opcode_tempalte = instr_data[opcode_start:opcode_end].hex().upper()

        instr_template += opcode_tempalte
        instr_template_verb[0].append(opcode_tempalte)

        op_param = OperandParameterizer(instr, db=db)

        modrm_template = ""
        if instr.modrm_offset:
            modrm_template = op_param.parameterize_modrm_byte(settings)

        instr_template += modrm_template
        instr_template_verb[0].append(modrm_template)

        sib_template = ""
        if op_param.sib is not None:
            sib_template = op_param.parameterize_sib_byte(settings)

        instr_template += sib_template
        instr_template_verb[0].append(sib_template)

        disp_template = ""
        if instr.disp_offset:
            disp_template = op_param.parameterize_disp(settings)

        instr_template += disp_template
        instr_template_verb[0].append(disp_template)

        imm_template = ""
        if instr.imm_offset:
            dbg_print(
                f"imm: {hexlify(instr_data[instr.imm_offset : instr.imm_offset + instr.imm_size]).decode('utf-8')}"
            )

            imm_template += op_param.parameterize_imm(settings)

        instr_template += imm_template
        instr_template_verb[0].append(imm_template)

        dbg_print(f"{instr.address:08X}: {instr_template}")
        dbg_print(format_debug_table(instr_template_verb_hdr, instr_template_verb[0]))
        dbg_print("--------------------------------------------------------------")

        code_pattern += _finalize_instr_template(instr_template, instr_data)

    return PatternResult(pattern=code_pattern, annotations=annotations)
