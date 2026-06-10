# ruff: noqa: E402
import sys
import types
from unittest.mock import MagicMock

# Mock PySide6
pyside6 = types.ModuleType("PySide6")
sys.modules["PySide6"] = pyside6
sys.modules["PySide6.QtCore"] = types.ModuleType("PySide6.QtCore")
sys.modules["PySide6.QtGui"] = types.ModuleType("PySide6.QtGui")
sys.modules["PySide6.QtWidgets"] = types.ModuleType("PySide6.QtWidgets")

# Mock IDA modules
sys.modules["ida_ida"] = MagicMock()
sys.modules["ida_kernwin"] = MagicMock()

# Now import the target modules and capstone constants
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
from capstone.x86_const import X86_REG_RSP, X86_REG_RAX, X86_OP_MEM, X86_REG_EAX, X86_REG_ECX, X86_OP_REG, X86_OP_IMM
from yarg.builder import create_pattern_from_code
from yarg.encoding import Sib, Displacement
from yarg.locator import OperandLocator, OPERAND_SIB
from yarg.utils import is_gp_reg, SettingsDialog


def _pattern(code, mode=CS_MODE_64):
    md = Cs(CS_ARCH_X86, mode)
    md.detail = True
    return create_pattern_from_code(md, code, 0x1000, SettingsDialog()).pattern


def _matches(pattern, code):
    import re

    regex = "".join("[0-9A-F]" if ch == "?" else ch for ch in pattern.upper())
    return re.fullmatch(regex, code.hex().upper()) is not None


def test_zero_modrm_sib_disp_bytes_are_not_dropped():
    # Each of these instructions encodes a 0x00 ModR/M, SIB or displacement byte that
    # must still appear in the generated pattern (a truthy guard used to drop them,
    # producing a pattern shorter than the instruction that could never match).
    assert _pattern(b"\x8b\x00") == "8B00"  # mov eax, [rax]      -> modrm == 0x00
    assert _pattern(b"\x8b\x45\x00") == "8B4500"  # mov eax, [rbp]      -> disp8 == 0x00
    assert _pattern(b"\x8b\x04\x00") == "8B0400"  # mov eax, [rax+rax]  -> sib == 0x00


def test_zero_and_multibyte_opcodes_are_preserved():
    # Opcode bytes can legitimately be 0x00 and opcodes can be multi-byte; the opcode
    # must be reconstructed from offsets rather than filtered for truthy bytes.
    assert _pattern(b"\x00\x00") == "0000"  # add [rax], al      -> opcode 0x00
    assert _pattern(b"\x0f\x00\x00") == "0F0000"  # sldt [rax]         -> 0F 00 /r
    assert _pattern(b"\x0f\x38\x00\xc0") == "0F3800C0"  # pshufb mm0, mm0    -> three-byte 0F 38
    assert _pattern(b"\xf3\x0f\x10\x00") == "F30F1000"  # movss             -> mandatory F3 prefix


def test_is_gp_reg():
    # 0 is X86_REG_INVALID (which is 0), should be False
    assert is_gp_reg(0) is False
    # stack regs should be False
    assert is_gp_reg(X86_REG_RSP) is False
    # other regs should be True
    assert is_gp_reg(X86_REG_RAX) is True


def test_sib_decoding_base_13_rex_b():
    # SIB base R13 / REX.B decoding logic: base_id in (5, 13)
    sib = Sib(mod=0, scale=0, index=1, base=5, index_ext=0, base_ext=1)  # base_id = 13
    assert sib.base_id == 13
    assert sib.is_mem_without_base_reg() is True
    assert sib.is_mem_with_only_index_disp_32() is True


def test_locator_resolves_sib_register_size():
    class FakeMem:
        def __init__(self, base, index):
            self.base = base
            self.index = index

    class FakeOperand:
        def __init__(self, type_, base, index):
            self.type = type_
            self.mem = FakeMem(base, index)

    class FakeInstr:
        def __init__(self, operands):
            self.operands = operands
            self.address = 0x401000
            self.rex = 0

        def reg_name(self, r):
            return f"reg_{r}"

    modrm = MagicMock()
    modrm.is_mem_with_sib.return_value = True
    # base=5, base_ext=0 -> base_id=5 (EBP/EBP/R13)
    # index=1, index_ext=0 -> index_id=1 (ECX/RCX)
    sib = Sib(mod=0, scale=0, index=1, base=5, index_ext=0, base_ext=0)
    disp = MagicMock()

    # operand uses 32-bit base EAX
    op = FakeOperand(X86_OP_MEM, X86_REG_EAX, X86_REG_ECX)
    instr = FakeInstr([op])

    locator = OperandLocator(instr, modrm, sib, disp)
    assert locator.locate(OPERAND_SIB) is op


def test_defensive_imm_and_disp_parameterization():
    settings = SettingsDialog()
    settings.address_parameterization_mode = 2
    settings.offset_parameterization_mode = 2

    # Displacement with size 1
    disp = Displacement(disp=5, offset=0, size=1, data=b"\x05", modrm=None, sib=None)
    assert disp.parameterize_address(settings) == "05"
    assert disp.parameterize_offset(settings) == "05"

    # Displacement with size 4
    disp4 = Displacement(disp=5, offset=0, size=4, data=b"\x01\x02\x03\x04", modrm=None, sib=None)
    assert disp4.parameterize_address(settings) == "????0304"


def test_fold_does_not_overmatch_held_register_field():
    # With folding enabled, a half-nibble set must stay a faithful alternation rather than
    # collapsing to a nibble wildcard that would also match the neighbouring held field.
    from yarg.utils import generate_8bit_pattern_2_0_any, generate_8bit_pattern_5_3_any

    settings = SettingsDialog()
    settings.cFoldSameLow4bit.checked = True
    settings.cFoldSameHigh4bit.checked = True

    # hold mod=3, reg=1 -> bytes C8..CF; "C?" would wrongly also match C0..C7 (reg=0).
    assert generate_8bit_pattern_2_0_any(3, 1, settings) == "(C8|C9|CA|CB|CC|CD|CE|CF)"
    # hold mod=3, rm=0 -> C0,C8,..,F8; "(?0|?8)" would wrongly also match mod != 3.
    assert generate_8bit_pattern_5_3_any(3, 0, settings) == "(C0|C8|D0|D8|E0|E8|F0|F8)"


def test_redundant_prefix_is_not_dropped():
    # capstone absorbs a redundant F3 prefix on `xchg ebx, eax` into neither prefix nor
    # opcode; the prefix length is decoded directly so the byte is still emitted.
    pattern = _pattern(b"\xf3\x93", CS_MODE_32)
    assert pattern.startswith("F3")
    assert _matches(pattern, b"\xf3\x93")


def test_bogus_immediate_size_is_clamped():
    # A far ptr16:32 call makes capstone report a huge bogus imm_size; the pattern must stay
    # the length of the instruction (7 bytes -> 14 hex chars) and still match its bytes.
    code = b"\x9a\xc1\x43\xf2\x97\x49\xb9"
    pattern = _pattern(code, CS_MODE_32)
    assert len(pattern) == 2 * len(code)
    assert _matches(pattern, code)


def test_unmodelled_encoding_falls_back_to_literal_bytes():
    # VEX-encoded AVX is outside the supported legacy ModR/M scheme; the match-based safety
    # net must fall back to literal bytes so the pattern still matches the instruction.
    code = b"\xc5\xfd\x7f\x00"  # vmovdqa [rax], ymm0
    pattern = _pattern(code)
    assert _matches(pattern, code)


def test_riprel_does_not_swallow_register_operand():
    # For a RIP-relative instruction (mov rax, [rip+0x10]) the memory operand must map to
    # OPERAND_DISP while the register operand still reaches OPERAND_MODRM_REG. A previously
    # unguarded is_mem_rip_rel() branch consumed the register operand, leaving its reg field
    # un-parameterizable.
    from yarg.operand import OperandParameterizer
    from yarg.locator import OPERAND_MODRM_REG, OPERAND_DISP

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    for instr in md.disasm(b"\x48\x8b\x05\x10\x00\x00\x00", 0x1000):
        op = OperandParameterizer(instr)
        reg_op = op.locator.locate(OPERAND_MODRM_REG)
        disp_op = op.locator.locate(OPERAND_DISP)
        assert reg_op is not None and reg_op.type == X86_OP_REG
        assert disp_op is not None and disp_op.type == X86_OP_MEM


def test_locator_does_not_crash_on_non_mem_operands():
    class FakeOperand:
        def __init__(self, type_, reg=0, imm=0):
            self.type = type_
            self.reg = reg
            self.imm = imm

    class FakeInstr:
        def __init__(self, operands):
            self.operands = operands
            self.address = 0x401000
            self.rex = 0

        def reg_name(self, r):
            return f"reg_{r}"

    modrm = MagicMock()
    modrm.is_mem_with_sib.return_value = True
    sib = Sib(mod=0, scale=0, index=1, base=5, index_ext=0, base_ext=0)
    disp = MagicMock()

    # Non-memory operands (Register and Immediate)
    op1 = FakeOperand(X86_OP_REG, reg=X86_REG_RAX)
    op2 = FakeOperand(X86_OP_IMM, imm=0x1234)
    instr = FakeInstr([op1, op2])

    # This should run without AttributeError or ctypes reinterpretation crash
    locator = OperandLocator(instr, modrm, sib, disp)
    assert locator.locate(OPERAND_SIB) is None
