import re
from struct import unpack
from binascii import hexlify
from dataclasses import dataclass

from capstone import *


from .operand import OperandParameterizer
from .utils import SettingsDialog, get_bitness, dbg_print, TEMPLATE_SYMBOL
from .yara_output import YaraInstructionComment, pattern_atom_ok


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


def _finalize_instr_template(instr_template: str, instr_data: bytes) -> tuple[str, bool]:
    """Guarantee a per-instruction template matches the instruction it was built from.

    A generated pattern must always match the bytes it describes. Disassembler metadata can
    be internally inconsistent on degenerate/obfuscated byte sequences, and encodings outside
    the supported legacy ModR/M scheme (e.g. VEX/EVEX) are not modelled here; either can yield
    a template that does not match the instruction. When that happens, fall back to the literal
    instruction bytes, which match by definition.

    Returns the finalized template and whether the literal fallback was used (the caller
    aggregates fallbacks into a single message instead of printing once per instruction).
    """
    target = instr_data.hex().upper()
    regex = pattern_to_regex(instr_template)
    if regex is not None and re.fullmatch(regex, target):
        return instr_template, False

    return target, True


def _enforce_block_atom(parts: list[tuple[str, bytes]], min_atom: int = 2) -> list[tuple[str, bytes]]:
    """Ensure a multi-instruction block keeps a fixed-byte run YARA can use as an atom.

    Heavy operand/branch parameterization can leave a block with no run of >=``min_atom``
    fixed bytes, which YARA cannot prefilter on (slow full scan, or rejected as too generic).
    When that happens, relock the single longest instruction to its literal bytes — the
    strongest, most discriminating anchor to make concrete — and stop once an atom exists.
    Relocking to literal is lossless against the *source* bytes (a literal always matches),
    trading that one instruction's generality for a viable atom.

    Single-instruction patterns are left untouched: the user selected exactly that
    instruction, so its atom weakness is deliberate, not a side effect of block assembly.
    """
    if len(parts) <= 1 or pattern_atom_ok("".join(template for template, _ in parts), min_atom):
        return parts

    # Prefer relocking a plain (non-alternation) instruction over one carrying a deliberate
    # short/near or register alternation, then the longest — sacrifice the least generality.
    for index in sorted(range(len(parts)), key=lambda i: ("(" not in parts[i][0], len(parts[i][1])), reverse=True):
        template, data = parts[index]
        if len(data) < min_atom or ("?" not in template and "(" not in template):
            continue
        parts[index] = (data.hex().upper(), data)
        if pattern_atom_ok("".join(template for template, _ in parts), min_atom):
            break
    return parts


def _offset_body(instr, mode: int) -> str:
    """Wildcard a relative-offset immediate, optionally locking its low byte(s).

    mode 0 wildcards every immediate byte; mode 1 locks the last byte; mode 2 locks the last
    two (the low bytes move least when a nearby target shifts).
    """
    pair = f"{TEMPLATE_SYMBOL}{TEMPLATE_SYMBOL}"
    n = instr.imm_size
    if mode == 1 and n >= 1:
        return pair * (n - 1) + f"{instr.bytes[-1]:02X}"
    if mode == 2 and n >= 2:
        return pair * (n - 2) + f"{instr.bytes[-2]:02X}{instr.bytes[-1]:02X}"
    return pair * n


def _near_jcc_from_short(short_opcode: int) -> str:
    """Map a one-byte ``Jcc rel8`` opcode (70+cc) to its two-byte ``Jcc rel32`` form (0F 80+cc)."""
    return f"0F{0x80 + (short_opcode - 0x70):02X}"


def _short_jcc_from_near(near_second_opcode: int) -> str:
    """Map the second byte of ``Jcc rel32`` (0F 80+cc) back to the ``Jcc rel8`` opcode (70+cc)."""
    return f"{0x70 + (near_second_opcode - 0x80):02X}"


def _with_branch_variant(native: str, alternate: str, settings: SettingsDialog, has_legacy_prefix: bool) -> str:
    """Pair an encoding with its short<->near counterpart as a lossless YARA alternation.

    Compilers pick the short (rel8) or near (rel16/32) form of a branch purely by target
    distance, so the same source can appear in either form across builds. Emitting both as
    ``(native|alternate)`` tolerates that without changing what the *original* bytes match
    (the native branch matches them; the counterpart is an additional generalization).

    Only applied when the instruction carries no legacy prefix: the prefix is emitted by the
    caller outside this template, and an operand-size (0x66) prefix changes the counterpart's
    length, so grafting the prefix onto the counterpart would describe a malformed encoding.
    The counterpart's displacement is fully wildcarded (rel32/rel8) with no low-byte locking —
    its real displacement is unknown for this instance.
    """
    if not settings.cBranchEncodingVariants.checked or has_legacy_prefix:
        return native
    return f"({native}|{alternate})"


def _rex_template(rex: int, settings: SettingsDialog) -> str:
    """Build the REX-byte template, optionally pinning REX.W to its observed value.

    The REX high nibble is always 4 (the fixed REX signature). The low nibble is ``W R X B``.
    By default we wildcard the whole low nibble (``4?``), which generalizes across the
    register-extension bits R/X/B *and* the operand-size bit W -- so ``4?`` conflates a
    64-bit-operand (W=1) instruction with its 32-bit-operand (W=0) cousin.

    When ``cRexOperandSizeFixed`` is on we keep R/X/B free (8 combinations) but hold W fixed
    to its observed value. There is no single hex wildcard for "top bit of a nibble fixed",
    so we emit an 8-way alternation of the concrete low-nibble hex digits whose bit3 equals
    observed W: W=1 -> ``4(8|9|A|B|C|D|E|F)``, W=0 -> ``4(0|1|2|3|4|5|6|7)``. This never
    reduces recall across compiler/optimization variation (W tracks source operand size, not
    codegen choice); it only stops matching the operand-size cousin.
    """
    high = rex >> 4
    if not settings.cRexOperandSizeFixed.checked:
        return f"{high:1X}{TEMPLATE_SYMBOL}"
    w = (rex >> 3) & 1
    low_values = range(8, 16) if w else range(0, 8)
    return f"{high:1X}(" + "|".join(f"{value:X}" for value in low_values) + ")"


def format_debug_table(headers, row) -> str:
    widths = [max(len(str(header)), len(str(value))) for header, value in zip(headers, row)]
    header_line = " | ".join(str(header).ljust(width) for header, width in zip(headers, widths))
    separator = "-+-".join("-" * width for width in widths)
    row_line = " | ".join(str(value).ljust(width) for value, width in zip(row, widths))
    return f"{header_line}\n{separator}\n{row_line}"


def special_templates(instr, dw_opcode, settings: SettingsDialog, db=None, has_legacy_prefix: bool = False) -> str | None:
    """
    Processing special opcodes
    :param instr:  Capstone instruction CsInsn
    :param dw_opcode: Opcode (dword)
    :param settings: Settings instance
    :param has_legacy_prefix: whether a legacy prefix precedes the opcode (gates branch variants)
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

    # CALL rel16/32 (no short relative form exists, so no branch variant)
    if dw_opcode == 0xE8:
        return "E8" + _offset_body(instr, settings.offset_parameterization_mode)

    # Jcc rel16/32 (0F 8x); pair with the rel8 (7x) short form
    if 0x800F <= dw_opcode <= 0x8F0F:
        opcode = "".join([f"{opcode_byte:02X}" for opcode_byte in instr.opcode if opcode_byte])
        native = opcode + _offset_body(instr, settings.offset_parameterization_mode)
        short = f"{_short_jcc_from_near(instr.opcode[1])}??"
        return _with_branch_variant(native, short, settings, has_legacy_prefix)

    # Jcc rel8 (7x); pair with the rel32 (0F 8x) near form
    if 0x70 <= dw_opcode <= 0x7F:
        native = f"{instr.opcode[0]:02X}??"
        near = f"{_near_jcc_from_short(instr.opcode[0])}????"
        return _with_branch_variant(native, near, settings, has_legacy_prefix)

    # JMP rel8 (EB); pair with the rel32 (E9) near form
    if dw_opcode == 0xEB:
        return _with_branch_variant("EB??", "E9????", settings, has_legacy_prefix)

    # JMP rel16/32 (E9); pair with the rel8 (EB) short form
    if dw_opcode == 0xE9:
        native = "E9" + _offset_body(instr, settings.offset_parameterization_mode)
        return _with_branch_variant(native, "EB??", settings, has_legacy_prefix)


def create_pattern_from_code(md: Cs, code: bytes, addr: int, settings: SettingsDialog, db=None) -> PatternResult:
    """
    Builds pattern from byte sequence
    :param md: Capstone disassembler instance
    :param code: Byte sequence
    :param addr: Start address
    :param settings: Settings instance
    :return: Parameterized pattern and per-instruction comments
    """
    parts: list[tuple[str, bytes]] = []
    annotations = []
    fallback_count = 0
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
            rex_template += _rex_template(instr.rex, settings)

        instr_template += rex_template
        instr_template_verb[0].append(rex_template)

        dw_opcode = unpack("<I", bytes(instr.opcode))[0]

        opcode_tempalte = special_templates(instr, dw_opcode, settings, db=db, has_legacy_prefix=number_of_prefixes > 0)
        if opcode_tempalte:
            instr_template += opcode_tempalte
            finalized, fell_back = _finalize_instr_template(instr_template, instr_data)
            parts.append((finalized, instr_data))
            fallback_count += fell_back
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

        instr_template_verb[0].append(modrm_template)

        sib_template = ""
        if op_param.sib is not None:
            sib_template = op_param.parameterize_sib_byte(settings)

        instr_template_verb[0].append(sib_template)

        disp_template = ""
        if instr.disp_offset:
            disp_template = op_param.parameterize_disp(settings)

        instr_template_verb[0].append(disp_template)

        # The native modrm/sib/disp tail always matches the source bytes. For a stack-frame
        # memory access a compiler may pick disp8 (mod=01) or disp32 (mod=10) for the same
        # source; emit both as a whole-tail alternation when enabled. The flip changes length
        # and the ModRM mod bits, so it cannot be a field wildcard. If the alternate cannot be
        # built safely the native single encoding is kept (invariant preserved).
        mem_tail = modrm_template + sib_template + disp_template
        if settings.cStackDispSizeVariants.checked:
            alternate_tail = op_param.stack_disp_size_variant(modrm_template, sib_template, disp_template, settings)
            if alternate_tail is not None and alternate_tail != mem_tail:
                mem_tail = f"({mem_tail}|{alternate_tail})"

        instr_template += mem_tail

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

        finalized, fell_back = _finalize_instr_template(instr_template, instr_data)
        parts.append((finalized, instr_data))
        fallback_count += fell_back

    if fallback_count:
        print(
            f"[!] {fallback_count} instruction(s) could not be parameterized "
            "(degenerate or unsupported encoding); emitted their literal bytes"
        )

    if settings.cAtomGovernor.checked:
        parts = _enforce_block_atom(parts)

    code_pattern = "".join(template for template, _ in parts)
    return PatternResult(pattern=code_pattern, annotations=annotations)
