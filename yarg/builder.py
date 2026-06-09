from struct import unpack
from binascii import hexlify
from dataclasses import dataclass

from capstone import *


from .operand import OperandParameterizer
from .utils import SettingsDialog, get_bitness, dbg_print, TEMPLATE_SYMBOL
from .yara_output import YaraInstructionComment


@dataclass(frozen=True)
class PatternResult:
    pattern: str
    annotations: list[YaraInstructionComment]


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
        # Extract number of prefix groups used in instruction
        number_of_prefixes = 0
        for prefix_byte in instr.prefix:
            if prefix_byte:
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
            code_pattern += instr_template
            continue

        # No special actions need. Just copy opcodes
        opcode_tempalte = "".join([f"{opcode_byte:02X}" for opcode_byte in instr.opcode if opcode_byte])

        instr_template += opcode_tempalte
        instr_template_verb[0].append(opcode_tempalte)

        op_param = OperandParameterizer(instr, db=db)

        modrm_template = ""
        if instr.modrm:
            modrm_template = op_param.parameterize_modrm_byte(settings)

        instr_template += modrm_template
        instr_template_verb[0].append(modrm_template)

        sib_template = ""
        if instr.sib:
            sib_template = op_param.parameterize_sib_byte(settings)

        instr_template += sib_template
        instr_template_verb[0].append(sib_template)

        disp_template = ""
        if instr.disp:
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

        code_pattern += instr_template

    return PatternResult(pattern=code_pattern, annotations=annotations)
