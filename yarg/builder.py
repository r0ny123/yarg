import re
from struct import unpack
from binascii import hexlify
from dataclasses import dataclass

from capstone import *


from capstone.x86_const import X86_OP_REG

from .operand import OperandParameterizer
from .utils import SettingsDialog, get_bitness, dbg_print, TEMPLATE_SYMBOL, is_gp_reg, is_stack_reg
from .yara_output import YaraInstructionComment, pattern_atom_ok


# x86 legacy prefix bytes: lock/repeat (F0, F2, F3), segment overrides
# (2E, 36, 3E, 26, 64, 65), and operand/address-size overrides (66, 67).
LEGACY_PREFIX_BYTES = frozenset({0xF0, 0xF2, 0xF3, 0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65, 0x66, 0x67})

# Maximum bytes for the inter-instruction gap wildcard token ``[0-K]``.
INTER_INSTRUCTION_GAP = 4


@dataclass(frozen=True)
class PatternResult:
    pattern: str
    annotations: list[YaraInstructionComment]


def pattern_to_regex(pattern: str) -> str | None:
    """Translate a generated YARA hex pattern into a regex over an uppercase hex dump.

    Hex nibbles map to themselves, ``?`` to a single hex-nibble class, ``(a|b|...)``
    alternation groups pass through unchanged, and ``[m-n]`` bounded jump tokens map to
    ``[0-9A-F]{2m,2n}`` (each skipped byte is two hex digits). Returns ``None`` if the
    pattern contains an unexpected character, which the caller treats as a non-match.
    """
    out = []
    i = 0
    n = len(pattern)
    while i < n:
        char = pattern[i]
        if char in "0123456789abcdefABCDEF":
            out.append(char.upper())
            i += 1
        elif char == "?":
            out.append("[0-9A-F]")
            i += 1
        elif char in "(|)":
            out.append(char)
            i += 1
        elif char == "[":
            # Parse a bounded jump token [m-n].
            close = pattern.find("]", i)
            if close == -1:
                return None
            token = pattern[i + 1 : close]
            if "-" not in token:
                return None
            parts = token.split("-", 1)
            try:
                lo = int(parts[0])
                hi = int(parts[1])
            except ValueError:
                return None
            out.append(f"[0-9A-F]{{{2 * lo},{2 * hi}}}")
            i = close + 1
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


# Opcode-to-ModRM-reg-digit mapping for the ALU accumulator short forms.
# The digit encodes the operation in the ModRM reg field: ADD=0 OR=1 ADC=2 SBB=3 AND=4 SUB=5 XOR=6 CMP=7.
_ACCUM_8BIT_OPCODE_DIGIT: dict[int, int] = {
    0x04: 0,  # ADD AL, imm8
    0x0C: 1,  # OR  AL, imm8
    0x14: 2,  # ADC AL, imm8
    0x1C: 3,  # SBB AL, imm8
    0x24: 4,  # AND AL, imm8
    0x2C: 5,  # SUB AL, imm8
    0x34: 6,  # XOR AL, imm8
    0x3C: 7,  # CMP AL, imm8
}
_ACCUM_ZBIT_OPCODE_DIGIT: dict[int, int] = {
    0x05: 0,  # ADD eAX/rAX, imm(z)
    0x0D: 1,  # OR  eAX/rAX, imm(z)
    0x15: 2,  # ADC eAX/rAX, imm(z)
    0x1D: 3,  # SBB eAX/rAX, imm(z)
    0x25: 4,  # AND eAX/rAX, imm(z)
    0x2D: 5,  # SUB eAX/rAX, imm(z)
    0x35: 6,  # XOR eAX/rAX, imm(z)
    0x3D: 7,  # CMP eAX/rAX, imm(z)
}


def _accum_imm_template(instr, settings: SettingsDialog, width: int) -> str:
    """Build the immediate template for an accumulator short-form instruction.

    When ``width`` equals ``instr.imm_size`` this simply delegates to
    ``OperandParameterizer.parameterize_imm``. When ``width`` is 1 (the sign-extended
    imm8 form inside the 83-group) and parameterization is active, a single ``??`` is
    returned; otherwise the low byte of the immediate is emitted as a literal hex pair.
    """
    if width == instr.imm_size:
        return OperandParameterizer(instr).parameterize_imm(settings)

    # width == 1, alternate (83) sign-extended form: use the low byte of the immediate.
    imm_offset = instr.imm_offset
    imm_data = instr.bytes[imm_offset : imm_offset + instr.imm_size]
    # Check whether imm is wildcarded by the caller's settings.
    if settings.cImmediateParam.checked:
        return f"{TEMPLATE_SYMBOL}{TEMPLATE_SYMBOL}"
    # Check GP or SP parameterization: for the accumulator short form there is no ModRM
    # reg/rm field, so we check the actual register operand from capstone's operand list.
    for op in instr.operands:
        if op.type == X86_OP_REG:
            if is_stack_reg(op.reg) and settings.cSImmParam.checked:
                return f"{TEMPLATE_SYMBOL}{TEMPLATE_SYMBOL}"
            if is_gp_reg(op.reg) and settings.cGpImmParam.checked:
                return f"{TEMPLATE_SYMBOL}{TEMPLATE_SYMBOL}"
    # Literal: the low byte of the full immediate.
    return f"{imm_data[0]:02X}"


def _with_accum_variant(instr, native_opcode: str, settings: SettingsDialog, db=None) -> str:
    """Emit an accumulator short-form encoding paired with its generic ModRM alternate(s).

    For 8-bit forms (AL, imm8) the single alternate is ``80 /digit imm8``.
    For z-bit forms (eAX/rAX, imm(z)) two alternates are emitted:
      - ``81 /digit imm(z)``  (always)
      - ``83 /digit imm8``    (only when the immediate fits in a signed int8)
    TEST (A8/A9) maps to F6/F7 /0 instead of 80/81 and has no 83 form.

    If any alternate cannot be constructed safely, the native single encoding is returned
    (invariant preserved). If the setting is off, the native single encoding with the
    immediate appended is returned.
    """
    # Build the immediate template first — needed both for the native-only and alternation paths.
    try:
        op_param = OperandParameterizer(instr, db=db)
        imm_t = op_param.parameterize_imm(settings)
    except Exception:
        # Fall back to the literal bytes; the caller's _finalize_instr_template will validate.
        imm_offset = instr.imm_offset
        imm_data = instr.bytes[imm_offset : imm_offset + instr.imm_size]
        imm_t = imm_data.hex().upper()

    dw_opcode = unpack("<I", bytes(instr.opcode))[0]
    native = native_opcode + imm_t

    if not settings.cAccumulatorEncodingVariants.checked:
        return native

    # --- 8-bit forms (AL, imm8) ---
    if dw_opcode in _ACCUM_8BIT_OPCODE_DIGIT:
        digit = _ACCUM_8BIT_OPCODE_DIGIT[dw_opcode]
        modrm = 0xC0 | (digit << 3)
        alt = f"80{modrm:02X}{imm_t}"
        return f"({native}|{alt})"

    # TEST AL, imm8 (A8) -> generic F6 /0 (ModRM C0)
    if dw_opcode == 0xA8:
        alt = f"F6C0{imm_t}"
        return f"({native}|{alt})"

    # --- z-bit forms (eAX/rAX, imm(z)) ---
    if dw_opcode in _ACCUM_ZBIT_OPCODE_DIGIT:
        digit = _ACCUM_ZBIT_OPCODE_DIGIT[dw_opcode]
        modrm = 0xC0 | (digit << 3)
        alt81 = f"81{modrm:02X}{imm_t}"
        alts = [native, alt81]

        # Sign-extended imm8 form (83-group): only when value fits in signed int8.
        # Use the raw immediate value; capstone sign-extends to int64 for signed imms.
        imm_offset = instr.imm_offset
        imm_data = instr.bytes[imm_offset : imm_offset + instr.imm_size]
        if imm_data:
            raw_val = int.from_bytes(imm_data, "little")
            # Treat as signed (two's complement for the native width).
            signed_val = raw_val if raw_val < (1 << (instr.imm_size * 8 - 1)) else raw_val - (1 << (instr.imm_size * 8))
            include_83 = -128 <= signed_val <= 127
            if not include_83 and settings.cImmediateParam.checked:
                # Immediate is wildcarded: we can't rule out a value that fits int8 at
                # runtime, so always include the 83 form for correctness.
                include_83 = True
            if include_83:
                imm8_t = _accum_imm_template(instr, settings, 1)
                alt83 = f"83{modrm:02X}{imm8_t}"
                alts.append(alt83)

        return "(" + "|".join(alts) + ")"

    # TEST eAX/rAX, imm(z) (A9) -> generic F7 /0 (ModRM C0); no 83 form.
    if dw_opcode == 0xA9:
        alt = f"F7C0{imm_t}"
        return f"({native}|{alt})"

    # Unrecognised opcode in this path: return the native (opcode + imm) string.
    return native


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
    to its observed value. YARA hex alternatives are whole bytes (a bare nibble is not a valid
    token), so we enumerate the eight concrete REX bytes whose W bit matches the observed one:
    W=1 -> ``(48|49|4A|4B|4C|4D|4E|4F)``, W=0 -> ``(40|41|42|43|44|45|46|47)``. This never
    reduces recall across compiler/optimization variation (W tracks source operand size, not
    codegen choice); it only stops matching the operand-size cousin.
    """
    high = rex >> 4
    if not settings.cRexOperandSizeFixed.checked:
        return f"{high:1X}{TEMPLATE_SYMBOL}"
    w = (rex >> 3) & 1
    low_values = range(8, 16) if w else range(0, 8)
    base = high << 4
    return "(" + "|".join(f"{base | low:02X}" for low in low_values) + ")"


def format_debug_table(headers, row) -> str:
    widths = [max(len(str(header)), len(str(value))) for header, value in zip(headers, row)]
    header_line = " | ".join(str(header).ljust(width) for header, width in zip(headers, widths))
    separator = "-+-".join("-" * width for width in widths)
    row_line = " | ".join(str(value).ljust(width) for value, width in zip(row, widths))
    return f"{header_line}\n{separator}\n{row_line}"


def special_templates(
    instr, dw_opcode, settings: SettingsDialog, db=None, has_legacy_prefix: bool = False
) -> str | None:
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
        near = f"{_near_jcc_from_short(instr.opcode[0])}????????"
        return _with_branch_variant(native, near, settings, has_legacy_prefix)

    # JMP rel8 (EB); pair with the rel32 (E9) near form
    if dw_opcode == 0xEB:
        return _with_branch_variant("EB??", "E9????????", settings, has_legacy_prefix)

    # JMP rel16/32 (E9); pair with the rel8 (EB) short form
    if dw_opcode == 0xE9:
        native = "E9" + _offset_body(instr, settings.offset_parameterization_mode)
        return _with_branch_variant(native, "EB??", settings, has_legacy_prefix)

    # Accumulator short-form ALU/TEST instructions (04..3D, A8/A9):
    # emit the native opcode string and let _with_accum_variant append the immediate and
    # any alternate(s). The opcode is a single literal byte here.
    if dw_opcode in _ACCUM_8BIT_OPCODE_DIGIT or dw_opcode == 0xA8:
        native_opcode = f"{dw_opcode:02X}"
        return _with_accum_variant(instr, native_opcode, settings, db=db)

    if dw_opcode in _ACCUM_ZBIT_OPCODE_DIGIT or dw_opcode == 0xA9:
        native_opcode = f"{dw_opcode:02X}"
        return _with_accum_variant(instr, native_opcode, settings, db=db)


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

    gap_token = f"[0-{INTER_INSTRUCTION_GAP}]"
    if settings.cInterInstructionGaps.checked and len(parts) >= 2:
        # Insert a bounded gap token BETWEEN consecutive instructions only.
        # Never at the start or the end — yara_x forbids leading/trailing jumps.
        templates = [template for template, _ in parts]
        code_pattern = gap_token.join(templates)
        # Sanity: no jump at start or end, no two adjacent jumps.
        assert not code_pattern.startswith("["), "gap token must not be at the start"
        assert not code_pattern.endswith("]"), "gap token must not be at the end"
        assert "]]" not in code_pattern, "adjacent gap tokens are not allowed"
    else:
        code_pattern = "".join(template for template, _ in parts)
    return PatternResult(pattern=code_pattern, annotations=annotations)
